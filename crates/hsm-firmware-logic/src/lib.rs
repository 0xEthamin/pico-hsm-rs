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