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

//! USB-HID protocol used between the mini-HSM dongle and the host.
//!
//! This crate is `no_std` by default so the firmware can depend on it. The
//! `std` feature toggles a handful of niceties (currently nothing, kept as
//! a future extension point).
//!
//! # Wire format
//!
//! Every exchange consists of fixed-size HID reports of [`HID_REPORT_SIZE`]
//! bytes. The same 3-byte header is used in both directions:
//!
//! ```text
//! Byte 0           : Opcode (command opcode for IN reports, status byte for OUT)
//! Byte 1..3        : Payload length, little-endian u16
//! Byte 3..3+len    : Payload
//! Byte 3+len..end  : Zero padding (sent zero, ignored on receive)
//! ```
//!
//! `len` is the host-meaningful payload size, not the wire size. The wire
//! size is always [`HID_REPORT_SIZE`] regardless. `len` must not exceed
//! [`MAX_PAYLOAD_SIZE`].
//!
//! # Layering
//!
//! [`Frame`] encodes/decodes the byte layout. It is opcode-agnostic and
//! deals only with `(u8, &[u8])`. Both the firmware and `hsm-host` build
//! one [`Frame`] per HID report, then interpret the payload with helpers
//! defined in [`commands`] and [`responses`]. There is no big `enum
//! Command { Info, Sign { slot, digest }, ... }`: that pattern scales
//! poorly with size and pays runtime cost for static information.

#![cfg_attr(not(feature = "std"), no_std)]
#![deny(missing_docs)]
#![warn(clippy::pedantic)]

pub mod commands;
pub mod frame;
pub mod hid_descriptor;
pub mod responses;

pub use commands::CommandOpcode;
pub use frame::{Frame, FrameParseError};
pub use hid_descriptor::HID_REPORT_DESCRIPTOR;
pub use responses::ResponseStatus;

/// USB vendor identifier for this project. `0xCAFE` is a community
/// convention for open-source / hobby devices (no USB-IF assignment).
pub const USB_VID: u16 = 0xCAFE;

/// USB product identifier for this project.
pub const USB_PID: u16 = 0x1312;

/// Fixed size of every HID report in either direction.
///
/// 128 bytes is enough to carry a single ECDSA P-256 signature (64 bytes)
/// or a single public key (64 bytes) in one report with room to spare for
/// the 3-byte header and any prefix bytes (slot id, block index, etc).
/// Larger transfers like the 128-byte config zone are split across multiple
/// reports by the caller.
pub const HID_REPORT_SIZE: usize = 128;

/// Size of the 3-byte header (`opcode | len_lo | len_hi`).
pub const HEADER_SIZE: usize = 3;

/// Maximum payload size in a report (`HID_REPORT_SIZE` - [`HEADER_SIZE`]).
pub const MAX_PAYLOAD_SIZE: usize = HID_REPORT_SIZE - HEADER_SIZE;