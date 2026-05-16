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
//!   GenKey, …). Each one exposes a typed async function on the
//!   [`driver::Atecc`] handle.
//! - [`error`]     - Error types for each layer, with `From` conversions for
//!   chaining.
//! - [`opcodes`]   - Numeric constants extracted from the Microchip
//!   CryptoAuthLib reference. Treat this as the single source of truth for
//!   on-the-wire values.
//! - [`hal`]       - The [`hal::AteccHal`] trait every backend must implement.
//! - [`slot`]      - Slot identifiers and helpers.
//! - [`driver`]    - The top-level [`driver::Atecc`] handle that ties
//!   everything together.

#![no_std]
#![deny(missing_docs)]
#![deny(unsafe_code)]
#![warn(clippy::pedantic)]

pub mod command;
pub mod crc;
pub mod driver;
pub mod error;
pub mod hal;
pub mod opcodes;
pub mod packet;
pub mod slot;
pub mod wake;

pub use driver::Atecc;
pub use error::{AteccError, ChipError};
pub use hal::AteccHal;
pub use slot::Slot;
