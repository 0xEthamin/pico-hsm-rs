//! Async tasks running on the firmware.
//!
//! The current design uses two tasks:
//!
//! 1. [`usb_run_task`] : keeps the embassy-usb device stack alive by
//!    polling its `run` future forever.
//! 2. [`dispatch_task`] : reads incoming HID reports, dispatches the
//!    request to the [`CryptoService`], and writes the response back.
//!
//! Splitting the device run loop from the dispatch loop is the canonical
//! embassy-usb pattern: the stack handles control transfers and resets
//! transparently while the application owns its own request/response
//! cadence.

use defmt::{info, warn};

use atecc608b::AteccHal;
use hsm_crypto_service::{Clock, CryptoService, CryptoServiceError};
use hsm_usb_protocol::commands::{
    parse_set_pin, parse_sign, parse_slot_only, parse_unblock_pin, parse_verify_pin,
    CommandOpcode,
};
use hsm_usb_protocol::responses::ResponseStatus;
use hsm_usb_protocol::Frame;

use atecc608b::Slot;

use crate::usb::{HidRx, HidTx, REPORT_SIZE, UsbStack};

/// Drive the embassy-usb device stack. Spawn this once at boot.
#[embassy_executor::task]
pub async fn usb_run_task(mut usb: UsbStack<'static>) -> !
{
    usb.run().await
}

/// Main request/response loop: read a HID report, dispatch on the opcode,
/// write the response.
///
/// This task owns the [`CryptoService`] and therefore runs **sequentially**.
/// Concurrent requests are not supported; the protocol does not need them.
pub async fn dispatch_loop<H, C>(
    mut rx: HidRx<'static>,
    mut tx: HidTx<'static>,
    mut service: CryptoService<H, C>,
) -> !
where
    H: AteccHal,
    C: Clock,
    H::Error: core::fmt::Debug,
{
    let mut rx_buf = [0u8; REPORT_SIZE];
    let mut tx_buf = [0u8; REPORT_SIZE];

    loop
    {
        let n = match rx.read(&mut rx_buf).await
        {
            Ok(n) => n,
            Err(_) =>
            {
                warn!("usb hid read error, restarting loop");
                continue;
            }
        };

        if n != REPORT_SIZE
        {
            warn!("unexpected short hid report ({} bytes), discarding", n);
            continue;
        }

        let response_len = handle_one_request(&mut service, &rx_buf, &mut tx_buf).await;

        if let Err(_) = tx.write(&tx_buf[..response_len]).await
        {
            warn!("usb hid write error");
        }
    }
}

/// Process one incoming report, write the response into `tx_buf`, return
/// the number of bytes used.
///
/// Always writes exactly [`REPORT_SIZE`] bytes (a HID report is fixed-size)
/// so the return value is currently always [`REPORT_SIZE`]. The signature
/// keeps it explicit in case a future variant needs to send less.
async fn handle_one_request<H, C>(
    service: &mut CryptoService<H, C>,
    rx_buf: &[u8],
    tx_buf: &mut [u8],
) -> usize
where
    H: AteccHal,
    C: Clock,
    H::Error: core::fmt::Debug,
{
    let frame = match Frame::parse(rx_buf)
    {
        Ok(f) => f,
        Err(_) => return write_status(tx_buf, ResponseStatus::InvalidPayload, &[]),
    };

    let opcode = match CommandOpcode::try_from(frame.opcode)
    {
        Ok(op) => op,
        Err(_) => return write_status(tx_buf, ResponseStatus::InvalidCommand, &[]),
    };

    info!("dispatching opcode {:#x}", opcode as u8);

    match opcode
    {
        CommandOpcode::Info => handle_info(service, tx_buf).await,
        CommandOpcode::GetPubkey => handle_get_pubkey(service, frame.payload, tx_buf).await,
        CommandOpcode::Sign => handle_sign(service, frame.payload, tx_buf).await,
        CommandOpcode::GenKey => handle_genkey(service, frame.payload, tx_buf).await,
        CommandOpcode::ReadConfigZone =>
        {
            handle_read_config_zone(service, frame.payload, tx_buf).await
        }
        CommandOpcode::VerifyPin => handle_verify_pin(service, frame.payload, tx_buf).await,
        CommandOpcode::SetPin => handle_set_pin(service, frame.payload, tx_buf).await,
        CommandOpcode::UnblockPin => handle_unblock_pin(service, frame.payload, tx_buf).await,
        CommandOpcode::GetPinStatus => handle_get_pin_status(service, tx_buf).await,
        // Provisioning and lock paths are not handled here: they are
        // dangerous and must be implemented behind dedicated double-confirm
        // logic. For now, surface them as "not yet implemented".
        CommandOpcode::ReadConfigSlot
        | CommandOpcode::WriteConfigZone
        | CommandOpcode::LockConfigZone
        | CommandOpcode::LockDataZone
        | CommandOpcode::LockSlot => write_status(tx_buf, ResponseStatus::InvalidCommand, &[]),
    }
}

// ---------------------------------------------------------------------------
// Per-opcode handlers
// ---------------------------------------------------------------------------

async fn handle_info<H, C>(
    service: &mut CryptoService<H, C>,
    tx_buf: &mut [u8],
) -> usize
where
    H: AteccHal,
    C: Clock,
    H::Error: core::fmt::Debug,
{
    match service.info().await
    {
        Ok(info) =>
        {
            // Payload layout: revision(4) || serial(9) || provisioned_flag(1) = 14 bytes.
            let mut payload = [0u8; 14];
            payload[0..4].copy_from_slice(&info.revision);
            payload[4..13].copy_from_slice(&info.serial);
            payload[13] = u8::from(info.is_provisioned);
            write_status(tx_buf, ResponseStatus::Ok, &payload)
        }
        Err(err) => write_error(tx_buf, &err),
    }
}

async fn handle_get_pubkey<H, C>(
    service: &mut CryptoService<H, C>,
    payload: &[u8],
    tx_buf: &mut [u8],
) -> usize
where
    H: AteccHal,
    C: Clock,
    H::Error: core::fmt::Debug,
{
    let slot = match parse_slot_only(payload)
    {
        Ok(s) => s,
        Err(_) => return write_status(tx_buf, ResponseStatus::InvalidPayload, &[]),
    };
    let slot = match Slot::new(slot)
    {
        Some(s) => s,
        None => return write_status(tx_buf, ResponseStatus::InvalidSlot, &[]),
    };
    match service.get_pubkey(slot).await
    {
        Ok(pk) => write_status(tx_buf, ResponseStatus::Ok, &pk),
        Err(err) => write_error(tx_buf, &err),
    }
}

async fn handle_sign<H, C>(
    service: &mut CryptoService<H, C>,
    payload: &[u8],
    tx_buf: &mut [u8],
) -> usize
where
    H: AteccHal,
    C: Clock,
    H::Error: core::fmt::Debug,
{
    let (slot_idx, digest) = match parse_sign(payload)
    {
        Ok(v) => v,
        Err(_) => return write_status(tx_buf, ResponseStatus::InvalidPayload, &[]),
    };
    let slot = match Slot::new(slot_idx)
    {
        Some(s) => s,
        None => return write_status(tx_buf, ResponseStatus::InvalidSlot, &[]),
    };
    match service.sign(slot, &digest).await
    {
        Ok(sig) => write_status(tx_buf, ResponseStatus::Ok, &sig),
        Err(err) => write_error(tx_buf, &err),
    }
}

async fn handle_genkey<H, C>(
    _service: &mut CryptoService<H, C>,
    _payload: &[u8],
    tx_buf: &mut [u8],
) -> usize
where
    H: AteccHal,
    C: Clock,
    H::Error: core::fmt::Debug,
{
    // GenKey create regenerates the identity key entirely on chip. It is
    // gated behind a PIN session at the service level and is only useful
    // post-provisioning. Not exposed yet.
    write_status(tx_buf, ResponseStatus::InvalidCommand, &[])
}

async fn handle_read_config_zone<H, C>(
    _service: &mut CryptoService<H, C>,
    payload: &[u8],
    tx_buf: &mut [u8],
) -> usize
where
    H: AteccHal,
    C: Clock,
    H::Error: core::fmt::Debug,
{
    // Payload: [block: u8]. Returns 32 bytes of the requested block.
    let _block = match parse_slot_only(payload)
    {
        Ok(b) => b,
        Err(_) => return write_status(tx_buf, ResponseStatus::InvalidPayload, &[]),
    };
    // Implementation deferred: needs a per-block read helper on
    // CryptoService. The crypto-service currently exposes the full-zone
    // read but not a single-block accessor. Surface as not-implemented for
    // the moment.
    write_status(tx_buf, ResponseStatus::InvalidCommand, &[])
}

async fn handle_verify_pin<H, C>(
    service: &mut CryptoService<H, C>,
    payload: &[u8],
    tx_buf: &mut [u8],
) -> usize
where
    H: AteccHal,
    C: Clock,
    H::Error: core::fmt::Debug,
{
    let pin = match parse_verify_pin(payload)
    {
        Ok(p) => p,
        Err(_) => return write_status(tx_buf, ResponseStatus::InvalidPayload, &[]),
    };
    match service.verify_pin(&pin).await
    {
        Ok(()) => write_status(tx_buf, ResponseStatus::Ok, &[]),
        Err(err) => write_error(tx_buf, &err),
    }
}

async fn handle_set_pin<H, C>(
    _service: &mut CryptoService<H, C>,
    payload: &[u8],
    tx_buf: &mut [u8],
) -> usize
where
    H: AteccHal,
    C: Clock,
    H::Error: core::fmt::Debug,
{
    let (_old, _new) = match parse_set_pin(payload)
    {
        Ok(v) => v,
        Err(_) => return write_status(tx_buf, ResponseStatus::InvalidPayload, &[]),
    };
    // SetPin requires the encrypted-write-to-slot-5 dance. Same status as
    // the rewrite path inside unblock_pin: not yet wired up.
    write_status(tx_buf, ResponseStatus::InvalidCommand, &[])
}

async fn handle_unblock_pin<H, C>(
    service: &mut CryptoService<H, C>,
    payload: &[u8],
    tx_buf: &mut [u8],
) -> usize
where
    H: AteccHal,
    C: Clock,
    H::Error: core::fmt::Debug,
{
    let (puk, new_pin) = match parse_unblock_pin(payload)
    {
        Ok(v) => v,
        Err(_) => return write_status(tx_buf, ResponseStatus::InvalidPayload, &[]),
    };
    match service.unblock_pin(&puk, &new_pin).await
    {
        Ok(()) => write_status(tx_buf, ResponseStatus::Ok, &[]),
        Err(err) => write_error(tx_buf, &err),
    }
}

async fn handle_get_pin_status<H, C>(
    service: &mut CryptoService<H, C>,
    tx_buf: &mut [u8],
) -> usize
where
    H: AteccHal,
    C: Clock,
    H::Error: core::fmt::Debug,
{
    match service.get_pin_status().await
    {
        Ok(status) =>
        {
            let payload = [
                status.pin_tries_remaining,
                status.puk_tries_remaining,
                u8::from(status.session_active),
            ];
            write_status(tx_buf, ResponseStatus::Ok, &payload)
        }
        Err(err) => write_error(tx_buf, &err),
    }
}

// ---------------------------------------------------------------------------
// Response helpers
// ---------------------------------------------------------------------------

/// Map a [`CryptoServiceError`] into a status + payload and write it.
fn write_error<HalError>(
    tx_buf: &mut [u8],
    err: &CryptoServiceError<HalError>,
) -> usize
where
    HalError: core::fmt::Debug,
{
    use CryptoServiceError as E;
    match err
    {
        E::Atecc(_) => write_status(tx_buf, ResponseStatus::AteccCommunicationError, &[]),
        E::InvalidFormat(_) => write_status(tx_buf, ResponseStatus::InvalidPayload, &[]),
        E::PinIncorrect { tries_remaining } =>
        {
            write_status(tx_buf, ResponseStatus::WrongPin, &[*tries_remaining])
        }
        E::PinBlocked => write_status(tx_buf, ResponseStatus::PinBlocked, &[]),
        E::PukIncorrect { tries_remaining } =>
        {
            write_status(tx_buf, ResponseStatus::WrongPuk, &[*tries_remaining])
        }
        E::Bricked => write_status(tx_buf, ResponseStatus::Bricked, &[]),
        E::PinRequired => write_status(tx_buf, ResponseStatus::PinRequired, &[]),
        E::NotProvisioned => write_status(tx_buf, ResponseStatus::NotProvisioned, &[]),
    }
}

/// Build a response frame in `tx_buf` and return its length.
fn write_status(tx_buf: &mut [u8], status: ResponseStatus, payload: &[u8]) -> usize
{
    // If the payload is too large for one report, truncate. This should
    // not happen in practice because all our responses fit. Defensive
    // programming.
    if Frame::write(status.as_u8(), payload, tx_buf).is_err()
    {
        // Degrade gracefully: write a short InvalidPayload status.
        let _ = Frame::write(ResponseStatus::InvalidPayload.as_u8(), &[], tx_buf);
    }
    REPORT_SIZE
}