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

//! Crypto business logic for the mini-HSM.
//!
//! This crate sits between the low-level [`atecc608b`] driver and the USB
//! protocol layer. It owns the slot conventions, the PIN session state, and
//! the orchestration of the multi-step signing workflow (Nonce passthrough
//! followed by Sign external).

#![no_std]
#![deny(missing_docs)]
#![deny(unsafe_code)]
#![warn(clippy::pedantic)]

pub(crate) mod encrypted_write;
pub mod error;
pub(crate) mod pin;
pub(crate) mod service;
pub mod session;
pub(crate) mod slots;

pub use error::CryptoServiceError;
pub use service::CryptoService;
pub use session::{Clock, Session, SESSION_TIMEOUT_MS};