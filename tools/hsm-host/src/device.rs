//! HID device abstraction.
//!
//! Wraps `hidapi` to find the mini-HSM dongle by VID/PID and exchange
//! single 128-byte HID reports. The protocol is request/response: the
//! host sends one report and reads exactly one back.

use anyhow::{anyhow, bail, Context, Result};
use hidapi::{HidApi, HidDevice};

use hsm_usb_protocol::{Frame, HID_REPORT_SIZE, USB_PID, USB_VID};
use hsm_usb_protocol::responses::ResponseStatus;

/// Open the first HID device matching the mini-HSM VID/PID.
pub fn open() -> Result<HidDevice>
{
    let api = HidApi::new().context("failed to initialise hidapi")?;
    let device = api
        .open(USB_VID, USB_PID)
        .with_context(|| format!(
            "failed to open HID device {:04X}:{:04X} -- is the dongle plugged in?",
            USB_VID, USB_PID
        ))?;
    Ok(device)
}

/// Print one line per HID device on the bus, marking matches.
pub fn enumerate() -> Result<()>
{
    let api = HidApi::new().context("failed to initialise hidapi")?;
    let mut matches = 0;
    for info in api.device_list()
    {
        let is_mini_hsm = info.vendor_id() == USB_VID && info.product_id() == USB_PID;
        if is_mini_hsm
        {
            matches += 1;
        }
        let marker = if is_mini_hsm { "<-- mini-HSM" } else { "" };
        println!(
            "{:04x}:{:04x} {} / {} {}",
            info.vendor_id(),
            info.product_id(),
            info.manufacturer_string().unwrap_or("(no manufacturer)"),
            info.product_string().unwrap_or("(no product)"),
            marker,
        );
    }
    println!();
    println!("{matches} mini-HSM device(s) found.");
    Ok(())
}

/// Send a command and return the response payload (without the 3-byte
/// frame header).
///
/// Returns `Err` if the chip responded with a non-`Ok` status. The error
/// message includes the status code and any payload bytes the firmware
/// included alongside (e.g. tries_remaining on WrongPin).
pub fn send_command(
    device: &HidDevice,
    opcode: u8,
    payload: &[u8],
) -> Result<Vec<u8>>
{
    let request = Frame::to_report(opcode, payload)
        .map_err(|e| anyhow!("failed to encode request frame: {:?}", e))?;

    // hidapi requires a leading report-ID byte of 0 on platforms that do
    // not use numbered reports.
    let mut wire = [0u8; HID_REPORT_SIZE + 1];
    wire[0] = 0;
    wire[1..].copy_from_slice(&request);
    device
        .write(&wire)
        .context("HID write failed")?;

    let mut response = [0u8; HID_REPORT_SIZE];
    let n = device
        .read_timeout(&mut response, 60_000)
        .context("HID read failed")?;
    if n != HID_REPORT_SIZE
    {
        bail!("short HID read: got {n} bytes, expected {HID_REPORT_SIZE}");
    }

    let frame = Frame::parse(&response)
        .map_err(|e| anyhow!("malformed response frame: {:?}", e))?;

    if frame.opcode != ResponseStatus::Ok.as_u8()
    {
        let status_name = describe_status(frame.opcode);
        if frame.payload.is_empty()
        {
            bail!("chip returned status 0x{:02x} ({status_name})", frame.opcode);
        }
        else
        {
            bail!(
                "chip returned status 0x{:02x} ({status_name}), data: {}",
                frame.opcode,
                hex::encode(frame.payload),
            );
        }
    }

    Ok(frame.payload.to_vec())
}

fn describe_status(byte: u8) -> &'static str
{
    // Delegate to the protocol crate so this CLI stays in sync if new
    // status variants are added there. Returning a static str keeps the
    // helper allocation-free.
    match ResponseStatus::from_byte(byte)
    {
        Some(ResponseStatus::Ok)                      => "Ok",
        Some(ResponseStatus::InvalidCommand)          => "InvalidCommand",
        Some(ResponseStatus::InvalidPayload)          => "InvalidPayload",
        Some(ResponseStatus::InvalidSlot)             => "InvalidSlot",
        Some(ResponseStatus::AteccCommunicationError) => "AteccCommunicationError",
        Some(ResponseStatus::AteccChipError)          => "AteccChipError",
        Some(ResponseStatus::TouchTimeout)            => "TouchTimeout",
        Some(ResponseStatus::NotProvisioned)          => "NotProvisioned",
        Some(ResponseStatus::LockMagicMismatch)       => "LockMagicMismatch",
        Some(ResponseStatus::LockCrcMismatch)         => "LockCrcMismatch",
        Some(ResponseStatus::Busy)                    => "Busy",
        Some(ResponseStatus::WrongPin)                => "WrongPin",
        Some(ResponseStatus::PinRequired)             => "PinRequired",
        Some(ResponseStatus::PinBlocked)              => "PinBlocked",
        Some(ResponseStatus::WrongPuk)                => "WrongPuk",
        Some(ResponseStatus::Bricked)                 => "Bricked",
        None => "Unknown",
    }
}