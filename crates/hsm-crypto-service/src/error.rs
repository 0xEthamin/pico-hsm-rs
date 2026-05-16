//! Error type returned by the crypto service.

use core::fmt::Debug;

use atecc608b::AteccError;

/// Error returned by [`crate::CryptoService`] methods.
#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum CryptoServiceError<HalError>
where
    HalError: Debug,
{
    /// Underlying driver error.
    Atecc(AteccError<HalError>),

    /// PIN format was rejected (wrong length or non-digit character).
    InvalidPinFormat,

    /// PIN verification failed; tries remaining counter is included.
    PinIncorrect { tries_remaining: u8 },

    /// PIN slot is hardware-blocked. Only PUK reset can recover.
    PinBlocked,

    /// PUK was wrong. After [`crate::slots::PUK_MAX_RETRIES`] failures the
    /// chip is bricked.
    PukIncorrect { tries_remaining: u8 },

    /// PUK retry count exhausted; the chip is permanently unusable.
    Bricked,

    /// A signing operation was requested but the PIN session is not active.
    PinRequired,

    /// The chip has not been provisioned yet (config zone is unlocked, or
    /// SHA-256 hashes are not stored in the expected slots).
    NotProvisioned,
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
