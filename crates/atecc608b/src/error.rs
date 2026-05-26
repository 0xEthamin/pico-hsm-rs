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

//! Error types for the ATECC608B driver.
//!
//! Each layer maps its specific failure modes to a variant of [`AteccError`].
//! The error type is generic over the HAL error so callers can match on the
//! exact reason without losing typing information.
//!
//! Upper layers (the firmware HID dispatcher, the host CLI) often need to
//! distinguish *categories* of failure (chip-side vs. communication-side)
//! without naming the concrete `HalError` type. [`AteccErrorKind`] is the
//! non-generic projection of [`AteccError`] intended for that use: it carries
//! the same shape information (which variant fired) but no HAL payload, so it
//! can travel through generic-erased layers and be serialized as a single
//! `u8` for transport over the USB-HID protocol.

use core::fmt::Debug;

/// Error returned by every public method of [`crate::Atecc`].
#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum AteccError<HalError>
where
    HalError: Debug,
{
    /// The HAL itself reported an error (I2C bus, GPIO, etc).
    Hal(HalError),

    /// The wake response did not match `04 11 33 43`. The chip is either
    /// unpowered, miswired, or in self-test failure mode.
    WakeFailed,

    /// The chip returned the self-test-failure pattern `04 07 C4 40` after
    /// wake. Hardware is unusable until power-cycle.
    SelfTestFailure,

    /// CRC-16 of a received frame did not match. The frame is discarded. The
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

impl<HalError> AteccError<HalError>
where
    HalError: Debug,
{
    /// Project this error onto its non-generic [`AteccErrorKind`].
    ///
    /// Useful for layers that must report the error over a wire format
    /// without leaking the concrete `HalError` type. The returned value
    /// preserves the variant identity and, for [`AteccError::Chip`], the
    /// inner [`ChipError`].
    #[must_use]
    pub fn kind(&self) -> AteccErrorKind
    {
        match self
        {
            AteccError::Hal(_)            => AteccErrorKind::Hal,
            AteccError::WakeFailed        => AteccErrorKind::WakeFailed,
            AteccError::SelfTestFailure   => AteccErrorKind::SelfTestFailure,
            AteccError::BadCrc            => AteccErrorKind::BadCrc,
            AteccError::Chip(err)         => AteccErrorKind::Chip(*err),
            AteccError::Timeout           => AteccErrorKind::Timeout,
            AteccError::MalformedResponse => AteccErrorKind::MalformedResponse,
            AteccError::BufferTooSmall    => AteccErrorKind::BufferTooSmall,
        }
    }
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

/// Non-generic projection of [`AteccError`].
///
/// Carries the same variant identity (and, for [`AteccErrorKind::Chip`], the
/// inner [`ChipError`]) but drops the HAL payload. Cheap to copy and safe to
/// pass across layers that don't want to be generic over `HalError`.
///
/// The non-`Chip` variants are encoded as stable `u8` sub-codes by
/// [`AteccErrorKind::as_sub_code`], used by the USB-HID protocol to expose
/// the failure category to the host CLI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum AteccErrorKind
{
    /// HAL error (I2C nack, GPIO failure, etc).
    Hal,
    /// Chip did not return the expected wake-response pattern.
    WakeFailed,
    /// Chip returned the self-test-failure pattern after wake.
    SelfTestFailure,
    /// CRC-16 of a received frame did not match.
    BadCrc,
    /// Chip-side error status. The inner [`ChipError`] carries the raw byte.
    Chip(ChipError),
    /// Polling exceeded the watchdog window.
    Timeout,
    /// A received frame has an inconsistent length byte.
    MalformedResponse,
    /// A caller-supplied buffer was too small for the response.
    BufferTooSmall,
}

/// Stable wire-format sub-code for the HAL-error variant.
pub const ATECC_ERR_SUB_HAL:                u8 = 0x01;
/// Stable wire-format sub-code for the wake-failed variant.
pub const ATECC_ERR_SUB_WAKE_FAILED:        u8 = 0x02;
/// Stable wire-format sub-code for the self-test-failure variant.
pub const ATECC_ERR_SUB_SELF_TEST_FAILURE:  u8 = 0x03;
/// Stable wire-format sub-code for the bad-CRC variant.
pub const ATECC_ERR_SUB_BAD_CRC:            u8 = 0x04;
/// Stable wire-format sub-code for the timeout variant.
pub const ATECC_ERR_SUB_TIMEOUT:            u8 = 0x05;
/// Stable wire-format sub-code for the malformed-response variant.
pub const ATECC_ERR_SUB_MALFORMED_RESPONSE: u8 = 0x06;
/// Stable wire-format sub-code for the buffer-too-small variant.
pub const ATECC_ERR_SUB_BUFFER_TOO_SMALL:   u8 = 0x07;

impl AteccErrorKind
{
    /// Return the stable `u8` sub-code identifying this variant.
    ///
    /// `Chip(_)` is not assigned a sub-code here because chip errors carry
    /// their own dedicated status byte (the chip's raw response byte,
    /// available via [`ChipError::as_status_byte`]) and are routed to a
    /// distinct top-level HID status. The fallback value `0x00` is reserved
    /// for that case and indicates "see the dedicated chip-error path".
    #[must_use]
    pub const fn as_sub_code(self) -> u8
    {
        match self
        {
            AteccErrorKind::Hal               => ATECC_ERR_SUB_HAL,
            AteccErrorKind::WakeFailed        => ATECC_ERR_SUB_WAKE_FAILED,
            AteccErrorKind::SelfTestFailure   => ATECC_ERR_SUB_SELF_TEST_FAILURE,
            AteccErrorKind::BadCrc            => ATECC_ERR_SUB_BAD_CRC,
            AteccErrorKind::Timeout           => ATECC_ERR_SUB_TIMEOUT,
            AteccErrorKind::MalformedResponse => ATECC_ERR_SUB_MALFORMED_RESPONSE,
            AteccErrorKind::BufferTooSmall    => ATECC_ERR_SUB_BUFFER_TOO_SMALL,
            AteccErrorKind::Chip(_)           => 0x00,
        }
    }

    /// Map a wire-format sub-code back to a non-`Chip` variant.
    ///
    /// Returns `None` for `0x00` (reserved for the chip-error path) and for
    /// any byte outside the assigned range. Callers reconstructing an error
    /// from the wire should handle the chip path through
    /// [`ChipError::from_status_byte`] separately.
    #[must_use]
    pub const fn from_sub_code(byte: u8) -> Option<Self>
    {
        match byte
        {
            ATECC_ERR_SUB_HAL                => Some(Self::Hal),
            ATECC_ERR_SUB_WAKE_FAILED        => Some(Self::WakeFailed),
            ATECC_ERR_SUB_SELF_TEST_FAILURE  => Some(Self::SelfTestFailure),
            ATECC_ERR_SUB_BAD_CRC            => Some(Self::BadCrc),
            ATECC_ERR_SUB_TIMEOUT            => Some(Self::Timeout),
            ATECC_ERR_SUB_MALFORMED_RESPONSE => Some(Self::MalformedResponse),
            ATECC_ERR_SUB_BUFFER_TOO_SMALL   => Some(Self::BufferTooSmall),
            _                                => None,
        }
    }
}

/// Errors reported by the chip itself via a 4-byte response frame.
///
/// Status byte values are taken from the Microchip `CryptoAuthLib`
/// `isATCAError()` function.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum ChipError
{
    /// `0x01` - `CheckMac` or Verify failed.
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
    /// Returns `None` for `0x00` which means success. Exposed as `pub` so
    /// host-side decoders (e.g. the CLI) can reconstruct the variant from
    /// the wire byte received in the USB-HID payload.
    #[must_use]
    pub const fn from_status_byte(byte: u8) -> Option<Self>
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

    /// Return the raw status byte this variant came from.
    ///
    /// Inverse of [`Self::from_status_byte`]. For
    /// [`ChipError::Unknown`] returns the preserved raw byte.
    #[must_use]
    pub const fn as_status_byte(self) -> u8
    {
        match self
        {
            Self::CheckMacOrVerifyFailed => 0x01,
            Self::ParseError             => 0x03,
            Self::EccFault               => 0x05,
            Self::SelfTestFailed         => 0x07,
            Self::HealthTestFailed       => 0x08,
            Self::ExecutionError         => 0x0F,
            Self::WatchdogAboutToExpire  => 0xEE,
            Self::CommandCrcError        => 0xFF,
            Self::Unknown(byte)          => byte,
        }
    }
}

#[cfg(test)]
mod tests
{
    use super::*;

    #[test]
    fn kind_strips_hal_payload()
    {
        let err: AteccError<&'static str> = AteccError::Hal("nack");
        assert_eq!(err.kind(), AteccErrorKind::Hal);
    }

    #[test]
    fn kind_preserves_chip_variant()
    {
        let err: AteccError<()> = AteccError::Chip(ChipError::ParseError);
        assert_eq!(err.kind(), AteccErrorKind::Chip(ChipError::ParseError));
    }

    #[test]
    fn sub_codes_are_distinct_and_stable()
    {
        let codes =
        [
            AteccErrorKind::Hal.as_sub_code(),
            AteccErrorKind::WakeFailed.as_sub_code(),
            AteccErrorKind::SelfTestFailure.as_sub_code(),
            AteccErrorKind::BadCrc.as_sub_code(),
            AteccErrorKind::Timeout.as_sub_code(),
            AteccErrorKind::MalformedResponse.as_sub_code(),
            AteccErrorKind::BufferTooSmall.as_sub_code(),
        ];
        // None of them clash with the reserved Chip sentinel `0x00`.
        for c in codes
        {
            assert_ne!(c, 0x00);
        }
        // All distinct.
        for (i, a) in codes.iter().enumerate()
        {
            for b in &codes[i + 1..]
            {
                assert_ne!(a, b);
            }
        }
    }

    #[test]
    fn sub_code_round_trip()
    {
        for kind in
        [
            AteccErrorKind::Hal,
            AteccErrorKind::WakeFailed,
            AteccErrorKind::SelfTestFailure,
            AteccErrorKind::BadCrc,
            AteccErrorKind::Timeout,
            AteccErrorKind::MalformedResponse,
            AteccErrorKind::BufferTooSmall,
        ]
        {
            assert_eq!(AteccErrorKind::from_sub_code(kind.as_sub_code()), Some(kind));
        }
    }

    #[test]
    fn sub_code_zero_is_reserved_for_chip()
    {
        assert_eq!(AteccErrorKind::from_sub_code(0x00), None);
        assert_eq!(AteccErrorKind::Chip(ChipError::ParseError).as_sub_code(), 0x00);
    }

    #[test]
    fn chip_error_status_byte_round_trip()
    {
        for byte in [0x01u8, 0x03, 0x05, 0x07, 0x08, 0x0F, 0xEE, 0xFF, 0x42]
        {
            let err = ChipError::from_status_byte(byte).unwrap();
            assert_eq!(err.as_status_byte(), byte);
        }
        assert!(ChipError::from_status_byte(0x00).is_none());
    }
}