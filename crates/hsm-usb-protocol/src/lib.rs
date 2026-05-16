//! USB-HID protocol used between the mini-HSM dongle and the host.
//!
//! This crate is `no_std` by default so the firmware can depend on it. The
//! `std` feature enables a few helpers used by the host CLI.
//!
//! The protocol uses 64-byte fixed-size HID reports in each direction. Layout:
//!
//! ```text
//! Byte 0   : Command / status opcode
//! Bytes 1..3: Payload length (little-endian u16)
//! Bytes 3..N: Payload
//! Bytes N..64: Padding (must be zero)
//! ```

#![cfg_attr(not(feature = "std"), no_std)]
#![deny(missing_docs)]
#![warn(clippy::pedantic)]

pub mod commands;
pub mod hid_descriptor;
pub mod responses;

/// VID assigned to the project. `0xCAFE` is a community convention for
/// open-source / hobby devices.
pub const USB_VID: u16 = 0xCAFE;

/// PID assigned to the project.
pub const USB_PID: u16 = 0x1312;

/// Fixed size of every HID report in either direction.
pub const HID_REPORT_SIZE: usize = 64;

/// Maximum payload size in a report (`HID_REPORT_SIZE` minus the 3-byte header).
pub const MAX_PAYLOAD_SIZE: usize = HID_REPORT_SIZE - 3;
