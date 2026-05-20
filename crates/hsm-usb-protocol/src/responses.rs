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

//! Status bytes returned by the token in every response report.
//!
//! Wire format mirrors [`crate::commands`]: a single 64-byte HID report
//! whose opcode is one of these [`ResponseStatus`] values and whose
//! payload depends on the originating command.

/// First byte of every HID response.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum ResponseStatus
{
    /// `0x00` - Operation succeeded. Payload depends on the originating
    /// command (e.g. 64-byte pubkey for `GetPubkey`, 64-byte signature for
    /// `Sign`, empty for `VerifyPin`).
    Ok                       = 0x00,
    /// `0x01` - Command opcode unknown.
    InvalidCommand           = 0x01,
    /// `0x02` - Payload size or shape is invalid.
    InvalidPayload           = 0x02,
    /// `0x03` - Slot index out of range.
    InvalidSlot              = 0x03,
    /// `0x04` - I2C / wake error talking to the ATECC.
    AteccCommunicationError  = 0x04,
    /// `0x05` - Chip returned an error status. The chip's raw status byte
    /// is in `payload[0]`.
    AteccChipError           = 0x05,
    /// `0x06` - The user did not press the button within the 30 s window.
    TouchTimeout             = 0x06,
    /// `0x07` - Token has not been provisioned yet.
    NotProvisioned           = 0x07,
    /// `0x08` - Magic word for a `Lock*` command did not match.
    LockMagicMismatch        = 0x08,
    /// `0x09` - CRC of the expected config does not match what's on chip.
    LockCrcMismatch          = 0x09,
    /// `0x0A` - Another operation is in progress.
    Busy                     = 0x0A,
    /// `0x0B` - PIN was wrong. Tries remaining in `payload[0]`.
    WrongPin                 = 0x0B,
    /// `0x0C` - A PIN session is required before signing.
    PinRequired              = 0x0C,
    /// `0x0D` - PIN slot is blocked. Only PUK unblock can recover.
    PinBlocked               = 0x0D,
    /// `0x0E` - PUK was wrong. Tries remaining in `payload[0]`.
    WrongPuk                 = 0x0E,
    /// `0x0F` - PUK retries exhausted. Chip is bricked.
    Bricked                  = 0x0F,
    /// `0x10` - `EmergencyReset` was requested but the user still has
    /// PIN or PUK attempts remaining. Payload is 2 bytes:
    /// `[pin_tries_remaining, puk_tries_remaining]`.
    EmergencyResetNotPermitted = 0x10,
}

impl ResponseStatus
{
    /// Map a raw byte to a [`ResponseStatus`], if recognized.
    #[must_use]
    pub const fn from_byte(byte: u8) -> Option<Self>
    {
        match byte
        {
            0x00 => Some(Self::Ok),
            0x01 => Some(Self::InvalidCommand),
            0x02 => Some(Self::InvalidPayload),
            0x03 => Some(Self::InvalidSlot),
            0x04 => Some(Self::AteccCommunicationError),
            0x05 => Some(Self::AteccChipError),
            0x06 => Some(Self::TouchTimeout),
            0x07 => Some(Self::NotProvisioned),
            0x08 => Some(Self::LockMagicMismatch),
            0x09 => Some(Self::LockCrcMismatch),
            0x0A => Some(Self::Busy),
            0x0B => Some(Self::WrongPin),
            0x0C => Some(Self::PinRequired),
            0x0D => Some(Self::PinBlocked),
            0x0E => Some(Self::WrongPuk),
            0x0F => Some(Self::Bricked),
            0x10 => Some(Self::EmergencyResetNotPermitted),
            _    => None,
        }
    }

    /// The raw status byte that goes on the wire.
    #[must_use]
    pub const fn as_u8(self) -> u8
    {
        self as u8
    }
}

impl TryFrom<u8> for ResponseStatus
{
    type Error = UnknownStatus;

    fn try_from(byte: u8) -> Result<Self, Self::Error>
    {
        Self::from_byte(byte).ok_or(UnknownStatus { byte })
    }
}

/// Returned when a byte cannot be mapped to a known [`ResponseStatus`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct UnknownStatus
{
    /// The raw byte that was not recognized.
    pub byte: u8,
}

#[cfg(test)]
mod tests
{
    use super::*;

    #[test]
    fn from_byte_round_trips()
    {
        for status in [
            ResponseStatus::Ok,
            ResponseStatus::InvalidCommand,
            ResponseStatus::InvalidPayload,
            ResponseStatus::InvalidSlot,
            ResponseStatus::AteccCommunicationError,
            ResponseStatus::AteccChipError,
            ResponseStatus::TouchTimeout,
            ResponseStatus::NotProvisioned,
            ResponseStatus::LockMagicMismatch,
            ResponseStatus::LockCrcMismatch,
            ResponseStatus::Busy,
            ResponseStatus::WrongPin,
            ResponseStatus::PinRequired,
            ResponseStatus::PinBlocked,
            ResponseStatus::WrongPuk,
            ResponseStatus::Bricked,
            ResponseStatus::EmergencyResetNotPermitted,
        ]
        {
            assert_eq!(ResponseStatus::from_byte(status.as_u8()), Some(status));
        }
    }

    #[test]
    fn try_from_returns_error_with_byte()
    {
        let err = ResponseStatus::try_from(0x99u8).unwrap_err();
        assert_eq!(err.byte, 0x99);
    }

    #[test]
    fn from_byte_returns_none_for_unknown()
    {
        assert!(ResponseStatus::from_byte(0x11).is_none());
        assert!(ResponseStatus::from_byte(0x42).is_none());
        assert!(ResponseStatus::from_byte(0x99).is_none());
        assert!(ResponseStatus::from_byte(0xFF).is_none());
    }
}