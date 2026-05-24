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

//! `no_std` asynchronous driver for the Microchip ATECC608B secure element.
//!
//! This crate is intentionally generic over a [`hal::AteccHal`] trait so it can
//! be built against any concrete hardware backend (RP2040 + `embassy-rp`, an
//! STM32, or an in-memory mock for host-side tests). The crate is `no_std` and
//! does not allocate on the heap.
//!
//! # Layered architecture
//!
//! The driver is split into several internal modules that map one-to-one to
//! the layers of the protocol:
//!
//! - [`crc`]       - CRC-16/DNP implementation used by every command frame.
//! - [`packet`]    - Encoding and decoding of the command/response packet.
//! - [`wake`]      - Wake / idle / sleep sequence and the response polling
//!   loop.
//! - [`command`]   - One module per high-level command (Info, Random, Sign,
//!   `GenKey`, etc). Each one exposes a typed async function on the
//!   [`driver::AteccChannel`] handle.
//! - [`error`]     - Error types for each layer, with `From` conversions for
//!   chaining.
//! - [`opcodes`]   - Numeric constants extracted from the Microchip
//!   `CryptoAuthLib` reference. Treat this as the single source of truth for
//!   on-the-wire values.
//! - [`hal`]       - The [`hal::AteccHal`] trait every backend must implement.
//! - [`slot`]      - Slot identifiers and helpers.
//! - [`driver`]    - The top-level [`driver::Atecc`] handle (sleeping) and
//!   [`driver::AteccChannel`] (awake) that together model the chip's
//!   wake / idle lifecycle.

#![no_std]
#![deny(missing_docs)]
#![deny(unsafe_code)]
#![warn(clippy::pedantic)]

pub mod command;
pub mod crc;
pub mod driver;
pub(crate) mod error;
pub mod hal;
pub mod opcodes;
pub(crate) mod packet;
pub(crate) mod slot;
pub(crate) mod wake;

pub use driver::Atecc;
pub use driver::AteccChannel;
pub use error::AteccError;
pub use error::ChipError;
pub use error::AteccErrorKind;
pub use hal::AteccHal;
pub use slot::Slot;
