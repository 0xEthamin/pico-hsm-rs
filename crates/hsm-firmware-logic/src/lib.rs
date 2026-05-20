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

//! Host-testable logic for the mini-HSM firmware.
//!
//! This crate exists so the parts of the firmware that are pure logic
//! (state machine, debouncer, LED/button abstractions) can be unit-tested
//! on the host. The firmware binary [`crate::hsm_firmware`] depends on
//! this crate and supplies the hardware-facing trait impls.

#![cfg_attr(not(test), no_std)]
#![deny(missing_docs)]
#![deny(unsafe_code)]
#![warn(clippy::pedantic)]

pub mod io;
pub mod state_machine;

pub use io::{Button, Debouncer, Led, DEBOUNCE_STABLE_SAMPLES};
pub use state_machine::{Event, LedPattern, TokenState, ERROR_DISPLAY_MS, TOUCH_TIMEOUT_MS};