//! Error types for the ATECC608B driver.
//!
//! Each layer maps its specific failure modes to a variant of [`AteccError`].
//! The error type is generic over the HAL error so callers can match on the
//! exact reason without losing typing information.

use core::fmt::Debug;

/// Error returned by every public method of [`crate::Atecc`].
#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum AteccError<HalError>
where
    HalError: Debug,
{
    /// The HAL itself reported an error (I2C bus, GPIO, …).
    Hal(HalError),

    /// The wake response did not match `04 11 33 43`. The chip is either
    /// unpowered, miswired, or in self-test failure mode.
    WakeFailed,

    /// The chip returned the self-test-failure pattern `04 07 C4 40` after
    /// wake. Hardware is unusable until power-cycle.
    SelfTestFailure,

    /// CRC-16 of a received frame did not match. The frame is discarded; the
    /// caller may retry.
    BadCrc,

    /// The chip returned a 4-byte status frame indicating an error.
    Chip(ChipError),

    /// Polling for a command response exceeded the watchdog window (~1.3 s
    /// nominal, 2.5 s upper bound).
    Timeout,

    /// A received frame has an inconsistent length byte.
    MalformedResponse,

    /// A caller-supplied buffer is too small for the response.
    BufferTooSmall,
}

impl<HalError> From<HalError> for AteccError<HalError>
where
    HalError: Debug,
{
    fn from(err: HalError) -> Self
    {
        AteccError::Hal(err)
    }
}

/// Errors reported by the chip itself via a 4-byte response frame.
///
/// Status byte values are taken from the Microchip CryptoAuthLib
/// `isATCAError()` function.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum ChipError
{
    /// `0x01` - CheckMac or Verify failed.
    CheckMacOrVerifyFailed,

    /// `0x03` - Command byte length, opcode or parameter was illegal.
    ParseError,

    /// `0x05` - Computation error during ECC processing causing invalid
    /// results.
    EccFault,

    /// `0x07` - Chip is in self test failure mode.
    SelfTestFailed,

    /// `0x08` - RNG health test error.
    HealthTestFailed,

    /// `0x0F` - Unspecified execution error.
    ExecutionError,

    /// `0xEE` - Watchdog about to expire - command not executed.
    WatchdogAboutToExpire,

    /// `0xFF` - CRC or other communication error on the command sent to the
    /// chip.
    CommandCrcError,

    /// An unknown status byte. The raw value is preserved for diagnosis.
    Unknown(u8),
}

impl ChipError
{
    /// Map a raw status byte returned by the chip to a [`ChipError`].
    ///
    /// Returns `None` for `0x00` which means success.
    #[must_use]
    pub fn from_status_byte(byte: u8) -> Option<Self>
    {
        match byte
        {
            0x00 => None,
            0x01 => Some(Self::CheckMacOrVerifyFailed),
            0x03 => Some(Self::ParseError),
            0x05 => Some(Self::EccFault),
            0x07 => Some(Self::SelfTestFailed),
            0x08 => Some(Self::HealthTestFailed),
            0x0F => Some(Self::ExecutionError),
            0xEE => Some(Self::WatchdogAboutToExpire),
            0xFF => Some(Self::CommandCrcError),
            other => Some(Self::Unknown(other)),
        }
    }
}
