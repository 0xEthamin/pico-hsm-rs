// Copyright (c) 2026 Tuloup Simon
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

//! Async tasks running on the firmware.
//!
//! Two tasks live in this module:
//!
//! 1. [`usb_run_task`] : keeps the embassy-usb device stack alive by
//!    polling its `run` future forever. Spawned at boot.
//! 2. [`dispatch_loop`] : reads incoming HID reports, dispatches the
//!    request to the [`CryptoService`], and writes the response back.
//!    Runs in the main task because it owns the `CryptoService`.
//!
//! The dispatch loop also drives the [`crate::state`] state machine by
//! posting events on [`crate::channels::EVENT_CHANNEL`]:
//!
//! - `Event::PinVerified` after a successful `verify_pin`.
//! - `Event::SignRequested` at the start of a `sign` operation, then
//!   blocks on [`crate::channels::TOUCH_CONFIRMED`] until the touch task
//!   has confirmed the user pressed the button.
//! - `Event::TouchTimeout` if the wait runs out.
//! - `Event::SignComplete` once the signing call returned.
//! - `Event::ErrorRaised` on any service error during signing.
//!
//! Splitting the device run loop from the dispatch loop is the canonical
//! embassy-usb pattern: the stack handles control transfers and resets
//! transparently while the application owns its own request/response
//! cadence.

use defmt::{info, warn};
use embassy_futures::select::{select, Either};
use embassy_time::{Duration, Timer};

use atecc608b::AteccErrorKind;
use atecc608b::AteccHal;
use atecc608b::Slot;
use hsm_crypto_service::{Clock, CryptoService, CryptoServiceError};
use hsm_firmware_logic::{Event, TOUCH_TIMEOUT_MS};
use hsm_usb_protocol::commands::
{
    parse_emergency_reset, parse_lock_config_zone, parse_lock_data_zone, parse_lock_slot,
    parse_provision_slot, parse_read_slot_block, parse_read_slot_word, parse_set_pin,
    parse_set_puk, parse_sign, parse_slot_only, parse_unblock_pin, parse_verify_pin,
    parse_write_config_zone, CommandOpcode,
};
use hsm_usb_protocol::responses::ResponseStatus;
use hsm_usb_protocol::Frame;

use crate::channels::{post_event, TOUCH_CONFIRMED};
use crate::usb::{HidRx, HidTx, REPORT_SIZE, UsbStack};

/// Drive the embassy-usb device stack. Spawn this once at boot.
#[embassy_executor::task]
pub(crate) async fn usb_run_task(mut usb: UsbStack<'static>) -> !
{
    usb.run().await
}

/// Main request/response loop: read a HID report, dispatch on the opcode,
/// write the response.
///
/// This task owns the [`CryptoService`] and therefore runs **sequentially**.
/// Concurrent requests are not supported; the protocol does not need them.
pub(crate) async fn dispatch_loop<H, C>
(
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

        if tx.write(&tx_buf[..response_len]).await.is_err()
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
async fn handle_one_request<H, C>
(
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
        CommandOpcode::SetPuk => handle_set_puk(service, frame.payload, tx_buf).await,
        CommandOpcode::CloseSession => handle_close_session(service, tx_buf),
        CommandOpcode::EmergencyReset =>
        {
            handle_emergency_reset(service, frame.payload, tx_buf).await
        }
        CommandOpcode::ReadSlotBlock =>
        {
            handle_read_slot_block(service, frame.payload, tx_buf).await
        }
        CommandOpcode::ReadSlotWord =>
        {
            handle_read_slot_word(service, frame.payload, tx_buf).await
        }
        CommandOpcode::ReadConfigSlot =>
        {
            handle_read_config_slot(service, frame.payload, tx_buf).await
        }
        CommandOpcode::WriteConfigZone =>
        {
            handle_write_config_zone(service, frame.payload, tx_buf).await
        }
        CommandOpcode::ProvisionSlot =>
        {
            handle_provision_slot(service, frame.payload, tx_buf).await
        }
        CommandOpcode::ProvisionInitialPin =>
        {
            handle_provision_initial_pin(service, tx_buf).await
        }
        CommandOpcode::ProvisionInitialPuk =>
        {
            handle_provision_initial_puk(service, tx_buf).await
        }
        CommandOpcode::ProvisionIoKey =>
        {
            handle_provision_io_key(service, tx_buf).await
        }
        CommandOpcode::ReadCounter =>
        {
            handle_read_counter(service, frame.payload, tx_buf).await
        }
        CommandOpcode::LockConfigZone =>
        {
            handle_lock_config_zone(service, frame.payload, tx_buf).await
        }
        CommandOpcode::LockDataZone =>
        {
            handle_lock_data_zone(service, frame.payload, tx_buf).await
        }
        CommandOpcode::LockSlot =>
        {
            handle_lock_slot(service, frame.payload, tx_buf).await
        }
    }
}

async fn handle_info<H, C>
(
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

async fn handle_get_pubkey<H, C>
(
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

async fn handle_sign<H, C>
(
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

    // Fail fast if there's no active PIN session, before arming the
    // touch wait.
    if !service.is_session_active()
    {
        return write_status(tx_buf, ResponseStatus::PinRequired, &[]);
    }

    // Drain any stale TOUCH_CONFIRMED pulse from a previous run before
    // arming the wait.
    TOUCH_CONFIRMED.reset();

    // Drain any stale TOUCH_CONFIRMED pulse from a previous run before
    // arming the wait.
    TOUCH_CONFIRMED.reset();

    // Notify the state machine that a sign request needs a touch.
    post_event(Event::SignRequested);

    // Wait for the user to physically touch the button. 
    // Bail out after TOUCH_TIMEOUT_MS.
    let timeout = Timer::after(Duration::from_millis(TOUCH_TIMEOUT_MS));
    let confirmation = TOUCH_CONFIRMED.wait();
    match select(timeout, confirmation).await
    {
        Either::First(()) =>
        {
            info!("touch timeout, cancelling sign");
            post_event(Event::TouchTimeout);
            return write_status(tx_buf, ResponseStatus::TouchTimeout, &[]);
        }
        Either::Second(()) =>
        {
            // Touch confirmed, proceed.
        }
    }

    // Perform the actual signing. On error, also fire SignComplete so
    // the SM does not stay stuck in Signing.
    let result = service.sign(slot, &digest).await;
    post_event(Event::SignComplete);

    match result
    {
        Ok(sig) => write_status(tx_buf, ResponseStatus::Ok, &sig),
        Err(err) =>
        {
            post_event(Event::ErrorRaised);
            write_error(tx_buf, &err)
        }
    }
}

async fn handle_genkey<H, C>
(
    service: &mut CryptoService<H, C>,
    payload: &[u8],
    tx_buf: &mut [u8],
) -> usize
where
    H: AteccHal,
    C: Clock,
    H::Error: core::fmt::Debug,
{
    // Payload: [slot: u8]. Returns the new public key (64 bytes).
    let slot_idx = match parse_slot_only(payload)
    {
        Ok(s) => s,
        Err(_) => return write_status(tx_buf, ResponseStatus::InvalidPayload, &[]),
    };
    let slot = match Slot::new(slot_idx)
    {
        Some(s) => s,
        None => return write_status(tx_buf, ResponseStatus::InvalidSlot, &[]),
    };
    match service.genkey_create(slot).await
    {
        Ok(pubkey) => write_status(tx_buf, ResponseStatus::Ok, &pubkey),
        Err(err) => write_error(tx_buf, &err),
    }
}

async fn handle_read_config_zone<H, C>
(
    service: &mut CryptoService<H, C>,
    payload: &[u8],
    tx_buf: &mut [u8],
) -> usize
where
    H: AteccHal,
    C: Clock,
    H::Error: core::fmt::Debug,
{
    // Payload: [block: u8]. Returns 32 bytes of the requested block.
    let block = match parse_slot_only(payload)
    {
        Ok(b) => b,
        Err(_) => return write_status(tx_buf, ResponseStatus::InvalidPayload, &[]),
    };
    match service.read_config_block(block).await
    {
        Ok(data) => write_status(tx_buf, ResponseStatus::Ok, &data),
        Err(err) => write_error(tx_buf, &err),
    }
}

async fn handle_read_config_slot<H, C>
(
    service: &mut CryptoService<H, C>,
    payload: &[u8],
    tx_buf: &mut [u8],
) -> usize
where
    H: AteccHal,
    C: Clock,
    H::Error: core::fmt::Debug,
{
    // Payload: [slot: u8]. Returns 4 bytes: [SlotConfig lo/hi, KeyConfig lo/hi].
    let slot_idx = match parse_slot_only(payload)
    {
        Ok(s) => s,
        Err(_) => return write_status(tx_buf, ResponseStatus::InvalidPayload, &[]),
    };
    let slot = match Slot::new(slot_idx)
    {
        Some(s) => s,
        None => return write_status(tx_buf, ResponseStatus::InvalidSlot, &[]),
    };
    match service.read_config_slot(slot).await
    {
        Ok(data) => write_status(tx_buf, ResponseStatus::Ok, &data),
        Err(err) => write_error(tx_buf, &err),
    }
}

async fn handle_write_config_zone<H, C>
(
    service: &mut CryptoService<H, C>,
    payload: &[u8],
    tx_buf: &mut [u8],
) -> usize
where
    H: AteccHal,
    C: Clock,
    H::Error: core::fmt::Debug,
{
    // Payload: [block: u8, data: [u8; 32]]. Writes one block of the
    // config zone.
    let (block, data) = match parse_write_config_zone(payload)
    {
        Ok(v) => v,
        Err(_) => return write_status(tx_buf, ResponseStatus::InvalidPayload, &[]),
    };
    match service.write_config_block(block, &data).await
    {
        Ok(()) => write_status(tx_buf, ResponseStatus::Ok, &[]),
        Err(err) => write_error(tx_buf, &err),
    }
}

async fn handle_provision_slot<H, C>
(
    service: &mut CryptoService<H, C>,
    payload: &[u8],
    tx_buf: &mut [u8],
) -> usize
where
    H: AteccHal,
    C: Clock,
    H::Error: core::fmt::Debug,
{
    // Payload: [slot: u8, value: [u8; 32]]. Writes a 32-byte cleartext
    // value into the requested slot. The service enforces the policy
    // that only slots 5, 6, 8 are accepted.
    let (slot_idx, value) = match parse_provision_slot(payload)
    {
        Ok(v) => v,
        Err(_) => return write_status(tx_buf, ResponseStatus::InvalidPayload, &[]),
    };
    let slot = match Slot::new(slot_idx)
    {
        Some(s) => s,
        None => return write_status(tx_buf, ResponseStatus::InvalidSlot, &[]),
    };
    match service.provision_slot(slot, &value).await
    {
        Ok(()) => write_status(tx_buf, ResponseStatus::Ok, &[]),
        Err(err) => write_error(tx_buf, &err),
    }
}

async fn handle_provision_initial_pin<H, C>
(
    service: &mut CryptoService<H, C>,
    tx_buf: &mut [u8],
) -> usize
where
    H: AteccHal,
    C: Clock,
    H::Error: core::fmt::Debug,
{
    match service.provision_initial_pin().await
    {
        Ok(()) => write_status(tx_buf, ResponseStatus::Ok, &[]),
        Err(err) => write_error(tx_buf, &err),
    }
}

async fn handle_provision_initial_puk<H, C>
(
    service: &mut CryptoService<H, C>,
    tx_buf: &mut [u8],
) -> usize
where
    H: AteccHal,
    C: Clock,
    H::Error: core::fmt::Debug,
{
    match service.provision_initial_puk().await
    {
        Ok(puk) => write_status(tx_buf, ResponseStatus::Ok, &puk),
        Err(err) => write_error(tx_buf, &err),
    }
}

async fn handle_provision_io_key<H, C>
(
    service: &mut CryptoService<H, C>,
    tx_buf: &mut [u8],
) -> usize
where
    H: AteccHal,
    C: Clock,
    H::Error: core::fmt::Debug,
{
    match service.provision_initial_io_key().await
    {
        Ok(io_key) => write_status(tx_buf, ResponseStatus::Ok, &io_key),
        Err(err) => write_error(tx_buf, &err),
    }
}

// -----------------------------------------------------------------------
// Lock handlers -- IRREVERSIBLE
// -----------------------------------------------------------------------
//
// All three follow the same pattern:
// 1. Parse the payload. A magic-mismatch maps to `LockMagicMismatch`,
//    a wrong length to `InvalidPayload`.
// 2. Forward the validated arg(s) to the service.
// 3. Map chip-side errors (most importantly, CRC mismatch reported by
//    the chip as ExecutionError) to `LockCrcMismatch` for clarity on
//    the host side.

async fn handle_lock_config_zone<H, C>
(
    service: &mut CryptoService<H, C>,
    payload: &[u8],
    tx_buf: &mut [u8],
) -> usize
where
    H: AteccHal,
    C: Clock,
    H::Error: core::fmt::Debug,
{
    let expected_crc = match parse_lock_config_zone(payload)
    {
        Ok(v) => v,
        Err(hsm_usb_protocol::commands::PayloadError::MagicMismatch) =>
        {
            return write_status(tx_buf, ResponseStatus::LockMagicMismatch, &[]);
        }
        Err(_) => return write_status(tx_buf, ResponseStatus::InvalidPayload, &[]),
    };
    match service.lock_config_zone(expected_crc).await
    {
        Ok(()) => write_status(tx_buf, ResponseStatus::Ok, &[]),
        Err(err) => write_lock_error(tx_buf, &err),
    }
}

async fn handle_lock_data_zone<H, C>
(
    service: &mut CryptoService<H, C>,
    payload: &[u8],
    tx_buf: &mut [u8],
) -> usize
where
    H: AteccHal,
    C: Clock,
    H::Error: core::fmt::Debug,
{
    let expected_crc = match parse_lock_data_zone(payload)
    {
        Ok(v) => v,
        Err(hsm_usb_protocol::commands::PayloadError::MagicMismatch) =>
        {
            return write_status(tx_buf, ResponseStatus::LockMagicMismatch, &[]);
        }
        Err(_) => return write_status(tx_buf, ResponseStatus::InvalidPayload, &[]),
    };
    match service.lock_data_zone(expected_crc).await
    {
        Ok(()) => write_status(tx_buf, ResponseStatus::Ok, &[]),
        Err(err) => write_lock_error(tx_buf, &err),
    }
}

async fn handle_lock_slot<H, C>
(
    service: &mut CryptoService<H, C>,
    payload: &[u8],
    tx_buf: &mut [u8],
) -> usize
where
    H: AteccHal,
    C: Clock,
    H::Error: core::fmt::Debug,
{
    let slot_idx = match parse_lock_slot(payload)
    {
        Ok(v) => v,
        Err(hsm_usb_protocol::commands::PayloadError::MagicMismatch) =>
        {
            return write_status(tx_buf, ResponseStatus::LockMagicMismatch, &[]);
        }
        Err(_) => return write_status(tx_buf, ResponseStatus::InvalidPayload, &[]),
    };
    let slot = match Slot::new(slot_idx)
    {
        Some(s) => s,
        None => return write_status(tx_buf, ResponseStatus::InvalidSlot, &[]),
    };
    match service.lock_slot(slot).await
    {
        Ok(()) => write_status(tx_buf, ResponseStatus::Ok, &[]),
        Err(err) => write_lock_error(tx_buf, &err),
    }
}

/// Map a service error to a response status, with a lock-specific bias:
/// the chip's "execution error" during a lock command almost always
/// means the CRC fed by the host did not match the chip's recomputed
/// CRC. Surface that as the dedicated `LockCrcMismatch` status to make
/// triage trivial on the host side.
fn write_lock_error<HalError>
(
    tx_buf: &mut [u8],
    err: &CryptoServiceError<HalError>,
) -> usize
where
    HalError: core::fmt::Debug,
{
    use atecc608b::{AteccError, ChipError};
    use CryptoServiceError as E;

    if let E::Atecc(AteccError::Chip(ChipError::ExecutionError)) = err
    {
        return write_status(tx_buf, ResponseStatus::LockCrcMismatch, &[]);
    }
    write_error(tx_buf, err)
}

async fn handle_verify_pin<H, C>
(
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
        Ok(()) =>
        {
            post_event(Event::PinVerified);
            write_status(tx_buf, ResponseStatus::Ok, &[])
        }
        Err(err) => write_error(tx_buf, &err),
    }
}

async fn handle_set_pin<H, C>
(
    service: &mut CryptoService<H, C>,
    payload: &[u8],
    tx_buf: &mut [u8],
) -> usize
where
    H: AteccHal,
    C: Clock,
    H::Error: core::fmt::Debug,
{
    let (old, new, io_key) = match parse_set_pin(payload)
    {
        Ok(v) => v,
        Err(_) => return write_status(tx_buf, ResponseStatus::InvalidPayload, &[]),
    };
    match service.set_pin(&old, &new, &io_key).await
    {
        Ok(()) => write_status(tx_buf, ResponseStatus::Ok, &[]),
        Err(err) => write_error(tx_buf, &err),
    }
}

async fn handle_unblock_pin<H, C>
(
    service: &mut CryptoService<H, C>,
    payload: &[u8],
    tx_buf: &mut [u8],
) -> usize
where
    H: AteccHal,
    C: Clock,
    H::Error: core::fmt::Debug,
{
    let (puk, new_pin, io_key) = match parse_unblock_pin(payload)
    {
        Ok(v) => v,
        Err(_) => return write_status(tx_buf, ResponseStatus::InvalidPayload, &[]),
    };
    match service.unblock_pin(&puk, &new_pin, &io_key).await
    {
        Ok(()) => write_status(tx_buf, ResponseStatus::Ok, &[]),
        Err(err) => write_error(tx_buf, &err),
    }
}

async fn handle_set_puk<H, C>
(
    service: &mut CryptoService<H, C>,
    payload: &[u8],
    tx_buf: &mut [u8],
) -> usize
where
    H: AteccHal,
    C: Clock,
    H::Error: core::fmt::Debug,
{
    let (old, new, io_key) = match parse_set_puk(payload)
    {
        Ok(v) => v,
        Err(_) => return write_status(tx_buf, ResponseStatus::InvalidPayload, &[]),
    };
    match service.set_puk(&old, &new, &io_key).await
    {
        Ok(()) => write_status(tx_buf, ResponseStatus::Ok, &[]),
        Err(err) => write_error(tx_buf, &err),
    }
}

/// Handler for the `EmergencyReset` opcode.
///
/// On success the response payload contains the freshly generated
/// 8-digit PUK so the caller can display it to the user. The handler
/// returns `EmergencyResetNotPermitted` (carrying the actual tries
/// remaining) if the user still has any PIN or PUK attempts.
async fn handle_emergency_reset<H, C>
(
    service: &mut CryptoService<H, C>,
    payload: &[u8],
    tx_buf: &mut [u8],
) -> usize
where
    H: AteccHal,
    C: Clock,
    H::Error: core::fmt::Debug,
{
    let io_key = match parse_emergency_reset(payload)
    {
        Ok(v) => v,
        Err(hsm_usb_protocol::commands::PayloadError::MagicMismatch) =>
        {
            return write_status(tx_buf, ResponseStatus::LockMagicMismatch, &[]);
        }
        Err(_) => return write_status(tx_buf, ResponseStatus::InvalidPayload, &[]),
    };
    match service.emergency_reset(&io_key).await
    {
        Ok(new_puk) => write_status(tx_buf, ResponseStatus::Ok, &new_puk),
        Err(err) => write_error(tx_buf, &err),
    }
}

/// Synchronous handler: closes the PIN session in the host-side state
/// only, no chip interaction. Always succeeds (idempotent).
fn handle_close_session<H, C>
(
    service: &mut CryptoService<H, C>,
    tx_buf: &mut [u8],
) -> usize
where
    H: AteccHal,
    C: Clock,
    H::Error: core::fmt::Debug,
{
    service.close_session();
    write_status(tx_buf, ResponseStatus::Ok, &[])
}

async fn handle_read_slot_block<H, C>
(
    service: &mut CryptoService<H, C>,
    payload: &[u8],
    tx_buf: &mut [u8],
) -> usize
where
    H: AteccHal,
    C: Clock,
    H::Error: core::fmt::Debug,
{
    let (slot_idx, block) = match parse_read_slot_block(payload)
    {
        Ok(v) => v,
        Err(_) => return write_status(tx_buf, ResponseStatus::InvalidPayload, &[]),
    };
    let slot = match Slot::new(slot_idx)
    {
        Some(s) => s,
        None => return write_status(tx_buf, ResponseStatus::InvalidSlot, &[]),
    };
    match service.read_slot_block(slot, block).await
    {
        Ok(data) => write_status(tx_buf, ResponseStatus::Ok, &data),
        Err(err) => write_error(tx_buf, &err),
    }
}

async fn handle_read_slot_word<H, C>
(
    service: &mut CryptoService<H, C>,
    payload: &[u8],
    tx_buf: &mut [u8],
) -> usize
where
    H: AteccHal,
    C: Clock,
    H::Error: core::fmt::Debug,
{
    let (slot_idx, block, offset) = match parse_read_slot_word(payload)
    {
        Ok(v) => v,
        Err(_) => return write_status(tx_buf, ResponseStatus::InvalidPayload, &[]),
    };
    let slot = match Slot::new(slot_idx)
    {
        Some(s) => s,
        None => return write_status(tx_buf, ResponseStatus::InvalidSlot, &[]),
    };
    match service.read_slot_word(slot, block, offset).await
    {
        Ok(data) => write_status(tx_buf, ResponseStatus::Ok, &data),
        Err(err) => write_error(tx_buf, &err),
    }
}

async fn handle_get_pin_status<H, C>
(
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

/// Read one of the chip's monotonic counters and return its raw value.
///
/// Payload format: `[counter_id: u8]` (0 = Counter0, 1 = Counter1). Any
/// other value yields [`ResponseStatus::InvalidPayload`].
///
/// Response payload: 4 bytes little-endian, the chip's `u32` count
/// unaltered. The host CLI decodes this into a decimal + hex value for
/// the operator. Unlike [`handle_get_pin_status`] this does **not** map
/// the count to "tries remaining" — the goal is diagnostic
/// transparency on what the chip actually stores.
async fn handle_read_counter<H, C>
(
    service: &mut CryptoService<H, C>,
    payload: &[u8],
    tx_buf: &mut [u8],
) -> usize
where
    H: AteccHal,
    C: Clock,
    H::Error: core::fmt::Debug,
{
    let counter_byte = match parse_slot_only(payload)
    {
        Ok(b) => b,
        Err(_) => return write_status(tx_buf, ResponseStatus::InvalidPayload, &[]),
    };
    let counter = match counter_byte
    {
        0 => atecc608b::command::counter::CounterId::Counter0,
        1 => atecc608b::command::counter::CounterId::Counter1,
        _ => return write_status(tx_buf, ResponseStatus::InvalidPayload, &[]),
    };
    match service.read_counter(counter).await
    {
        Ok(value) =>
        {
            let bytes = value.to_le_bytes();
            write_status(tx_buf, ResponseStatus::Ok, &bytes)
        }
        Err(err) => write_error(tx_buf, &err),
    }
}

/// Map a [`CryptoServiceError`] into a status + payload and write it.
///
/// Driver-level failures are split into two cases:
///
/// - [`AteccErrorKind::Chip`]: the chip itself returned a non-zero status
///   byte. Surface that as [`ResponseStatus::AteccChipError`] (0x05) with
///   the raw chip status byte in `payload[0]`. Lets the host translate to
///   `ParseError`, `ExecutionError`, etc., for triage.
/// - Anything else (HAL nack, wake failure, CRC mismatch, timeout, ...):
///   surface as [`ResponseStatus::AteccCommunicationError`] (0x04) with a
///   one-byte sub-code in `payload[0]` derived from
///   [`AteccErrorKind::as_sub_code`].
fn write_error<HalError>
(
    tx_buf: &mut [u8],
    err: &CryptoServiceError<HalError>,
) -> usize
where
    HalError: core::fmt::Debug,
{
    use CryptoServiceError as E;
    match err
    {
        E::Atecc(atecc_err) => match atecc_err.kind()
        {
            AteccErrorKind::Chip(chip_err) =>
            {
                write_status
                (
                    tx_buf,
                    ResponseStatus::AteccChipError,
                    &[chip_err.as_status_byte()],
                )
            }
            other =>
            {
                write_status
                (
                    tx_buf,
                    ResponseStatus::AteccCommunicationError,
                    &[other.as_sub_code()],
                )
            }
        },
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
        E::EmergencyResetNotPermitted { pin_tries_remaining, puk_tries_remaining } =>
        {
            write_status(
                tx_buf,
                ResponseStatus::EmergencyResetNotPermitted,
                &[*pin_tries_remaining, *puk_tries_remaining],
            )
        }
        E::InvalidSlot { slot } =>
        {
            write_status(tx_buf, ResponseStatus::InvalidSlot, &[slot.as_u8()])
        }
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