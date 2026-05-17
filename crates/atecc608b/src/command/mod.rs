//! High-level typed commands exposed on [`crate::Atecc`].
//!
//! Each sub-module implements one command of the ATECC608B protocol. The
//! pattern is the same throughout:
//!
//! 1. A method on [`crate::Atecc`] that takes typed parameters.
//! 2. Internally it calls [`crate::Atecc::execute_command`] with the right
//!    opcode, params, and expected execution time.
//! 3. It parses the resulting payload into a strongly-typed return value.

pub mod genkey;
pub mod info;
pub mod lock;
pub mod nonce;
pub mod random;
pub mod read_write;
pub mod sign;
pub mod verify;
