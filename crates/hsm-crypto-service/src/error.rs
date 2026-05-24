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

//! Error type returned by the crypto service.

use core::fmt::Debug;

use atecc608b::{AteccError, AteccErrorKind, Slot};

use crate::pin::FormatError;

/// Error returned by [`crate::CryptoService`] methods.
#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum CryptoServiceError<HalError>
where
    HalError: Debug,
{
    /// Underlying driver error.
    Atecc(AteccError<HalError>),

    /// PIN or PUK format was rejected (wrong length or non-digit character).
    InvalidFormat(FormatError),

    /// PIN verification failed. Tries remaining counter is included.
    PinIncorrect
    {
        /// Number of attempts the user has left before the slot is blocked.
        tries_remaining: u8,
    },

    /// PIN slot is hardware-blocked. Only PUK reset can recover.
    PinBlocked,

    /// PUK was wrong. After [`crate::slots::PUK_MAX_RETRIES`] failures the
    /// chip is bricked.
    PukIncorrect
    {
        /// Number of PUK attempts the user has left before the chip is bricked.
        tries_remaining: u8,
    },

    /// PUK retry count exhausted. The chip is permanently unusable.
    Bricked,

    /// A signing operation was requested but the PIN session is not active.
    PinRequired,

    /// The chip has not been provisioned yet (config zone is unlocked, or
    /// SHA-256 hashes are not stored in the expected slots).
    NotProvisioned,

    /// The caller specified a slot index that is invalid for the
    /// requested operation (out of policy, e.g. `provision_slot` on an
    /// ECC slot, or `sign` on a slot not configured for ECC).
    InvalidSlot
    {
        /// The slot the caller tried to use.
        slot: Slot,
    },

    /// The caller asked for [`crate::CryptoService::emergency_reset`] but
    /// the precondition (both PIN and PUK batches fully exhausted) is
    /// not met. The user must use the normal recovery paths
    /// (`unblock_pin`) instead.
    EmergencyResetNotPermitted
    {
        /// Number of PIN attempts the user still has in the current batch.
        pin_tries_remaining: u8,
        /// Number of PUK attempts the user still has in the current batch.
        puk_tries_remaining: u8,
    },
}

impl<HalError> CryptoServiceError<HalError>
where
    HalError: Debug,
{
    /// Return the non-generic [`AteccErrorKind`] if this error wraps a
    /// driver-level failure.
    ///
    /// Returns `None` for variants that originated above the driver layer
    /// (PIN/PUK failures, format errors, session policy violations).
    ///
    /// Intended for layers that must serialize the error over a wire
    /// format without naming the concrete `HalError` type, in particular
    /// the firmware's USB-HID dispatcher.
    #[must_use]
    pub fn atecc_kind(&self) -> Option<AteccErrorKind>
    {
        match self
        {
            CryptoServiceError::Atecc(err) => Some(err.kind()),
            _                                                     => None,
        }
    }
}

impl<HalError> From<AteccError<HalError>> for CryptoServiceError<HalError>
where
    HalError: Debug,
{
    fn from(err: AteccError<HalError>) -> Self
    {
        CryptoServiceError::Atecc(err)
    }
}

impl<HalError> From<FormatError> for CryptoServiceError<HalError>
where
    HalError: Debug,
{
    fn from(err: FormatError) -> Self
    {
        CryptoServiceError::InvalidFormat(err)
    }
}