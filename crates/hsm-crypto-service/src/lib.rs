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

pub mod encrypted_write;
pub mod error;
pub mod pin;
pub mod service;
pub mod session;
pub mod slots;

pub use error::CryptoServiceError;
pub use service::{CryptoService, DeviceInfo, PinStatus, PublicKey, ServiceResult, Signature};
pub use session::{Clock, Session, SESSION_TIMEOUT_MS};