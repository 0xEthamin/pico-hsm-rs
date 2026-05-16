//! High-level typed commands exposed on [`crate::Atecc`].
//!
//! Each sub-module implements one command of the ATECC608B protocol. The
//! pattern is:
//!
//! 1. A function on [`crate::Atecc`] taking typed parameters.
//! 2. Internally, it builds a [`crate::packet::CommandPacket`], hands it to
//!    the packet layer for serialization, and uses the wake/polling logic to
//!    receive and decode the response.
pub mod genkey;
pub mod info;
pub mod lock;
pub mod nonce;
pub mod random;
pub mod read_write;
pub mod sign;
pub mod verify;
