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

//! High-level typed commands exposed on [`crate::Atecc`].
//!
//! Each sub-module implements one command of the ATECC608B protocol. The
//! pattern is the same throughout:
//!
//! 1. A method on [`crate::Atecc`] that takes typed parameters.
//! 2. Internally it calls [`crate::AteccChannel::execute_command`] with the right
//!    opcode, params, and expected execution time.
//! 3. It parses the resulting payload into a strongly-typed return value.

pub mod checkmac;
pub mod counter;
pub mod gendig;
pub mod genkey;
pub(crate) mod info;
pub(crate) mod lock;
pub mod nonce;
pub mod privwrite;
pub(crate) mod random;
pub mod read_write;
pub mod sign;
pub(crate) mod verify;