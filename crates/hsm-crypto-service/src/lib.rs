//! Crypto business logic for the mini-HSM.
//!
//! This crate sits between the low-level [`atecc608b`] driver and the USB
//! protocol layer. It owns the slot conventions, the PIN session state, and
//! the orchestration of the multi-step signing workflow (Random -> Nonce ->
//! Sign).

#![no_std]
#![deny(missing_docs)]
#![deny(unsafe_code)]
#![warn(clippy::pedantic)]

pub mod error;
pub mod service;
pub mod slots;

pub use error::CryptoServiceError;
pub use service::CryptoService;
