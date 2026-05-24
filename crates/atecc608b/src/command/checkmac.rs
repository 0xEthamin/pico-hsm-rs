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

//! `CheckMac` command.
//!
//! Verifies a host-computed MAC against the contents of a slot. The chip
//! takes the slot value as key, computes `SHA256(key || challenge ||
//! other_data || padding)`, and compares the result with the host-supplied
//! `client_resp`. A match yields status byte `0x00`, a mismatch yields
//! `0x01` ([`crate::error::ChipError::CheckMacOrVerifyFailed`]).
//!
//! The flow used in this project is PIN verification. Slot 5 stores
//! `SHA256(PIN || salt)`. The host computes the same digest from the PIN
//! the user typed, builds the corresponding MAC, and asks the chip to
//! cross-check it. If the user has fat-fingered the PIN, the MAC does not
//! match, the chip reports miscompare, and the relevant counter is bumped.
//! That counter eventually reaches the `LimitedUse` threshold (5 for PIN,
//! 10 for PUK) and blocks the slot from any further `CheckMac`.
//!
//! Reference: `CryptoAuthLib` `lib/calib/calib_checkmac.c`, constants
//! `CHECKMAC_MODE_CHALLENGE` (0x00),
//! `CHECKMAC_CHALLENGE_SIZE` (32),
//! `CHECKMAC_CLIENT_RESPONSE_SIZE` (32),
//! `CHECKMAC_OTHER_DATA_SIZE` (13).

use crate::driver::AteccChannel;
use crate::error::{AteccError, ChipError};
use crate::hal::AteccHal;
use crate::opcodes::{EXEC_TIME_CHECKMAC_MS, OP_CHECKMAC};
use crate::slot::Slot;

/// Size of the challenge block sent to the chip.
pub const CHECKMAC_CHALLENGE_SIZE: usize = 32;

/// Size of the client response block (the host-computed MAC under test).
pub const CHECKMAC_CLIENT_RESPONSE_SIZE: usize = 32;

/// Size of the `other_data` block.
///
/// `other_data` mirrors the parameters the chip uses internally to compute
/// the MAC against. It encodes the opcode, mode, key id, and OTP fields
/// that participate in the hash. Layout per `CryptoAuthLib`:
///
/// ```text
/// [0]    : opcode (must match the CheckMac call, 0x28)
/// [1]    : mode (must match param1)
/// [2..4] : key id LE (must match param2)
/// [4..7] : OTP bytes 8..10 (zero on a chip without OTP usage)
/// [7..11]: SN[4..7] (chip serial number, can be left zero)
/// [11..13]: SN[2..3]
/// ```
///
/// For PIN verification with no OTP coupling, all 13 bytes can be zero.
pub const CHECKMAC_OTHER_DATA_SIZE: usize = 13;

/// Total size of the data field sent with a `CheckMac` command.
pub const CHECKMAC_DATA_SIZE: usize =
    CHECKMAC_CHALLENGE_SIZE + CHECKMAC_CLIENT_RESPONSE_SIZE + CHECKMAC_OTHER_DATA_SIZE;

/// `param1` mode: challenge is taken from the input `data` field, key from
/// the slot identified by `param2`.
const CHECKMAC_MODE_CHALLENGE: u8 = 0x00;

impl<H> AteccChannel<'_, H>
where
    H: AteccHal,
{
    /// Verify a host-computed MAC against the contents of `slot`.
    ///
    /// `challenge` is the random nonce used as input. `client_resp` is the
    /// MAC the host computed. `other_data` lays out the metadata fields
    /// the chip will hash into its own MAC.
    ///
    /// Returns `Ok(true)` on match (chip status `0x00`), `Ok(false)` on
    /// miscompare (chip status `0x01`). Any other error condition surfaces
    /// as [`AteccError`].
    ///
    /// # Counter side-effect
    ///
    /// If the target slot has a `LimitedUse` counter (slots 5 and 6 in this
    /// project), each `CheckMac` call bumps the counter regardless of the
    /// outcome. Reaching the threshold permanently blocks the slot.
    ///
    /// # Errors
    /// See [`AteccChannel::execute_command_status`]. A miscompare (`0x01`)
    /// is returned as `Ok(false)`.
    pub async fn checkmac
    (
        &mut self,
        slot: Slot,
        challenge: &[u8; CHECKMAC_CHALLENGE_SIZE],
        client_resp: &[u8; CHECKMAC_CLIENT_RESPONSE_SIZE],
        other_data: &[u8; CHECKMAC_OTHER_DATA_SIZE],
    ) -> Result<bool, AteccError<H::Error>>
    {
        let mut data = [0u8; CHECKMAC_DATA_SIZE];
        data[..CHECKMAC_CHALLENGE_SIZE].copy_from_slice(challenge);
        data[CHECKMAC_CHALLENGE_SIZE..CHECKMAC_CHALLENGE_SIZE + CHECKMAC_CLIENT_RESPONSE_SIZE]
            .copy_from_slice(client_resp);
        data[CHECKMAC_CHALLENGE_SIZE + CHECKMAC_CLIENT_RESPONSE_SIZE..]
            .copy_from_slice(other_data);

        let result = self
            .execute_command_status
            (
                OP_CHECKMAC,
                CHECKMAC_MODE_CHALLENGE,
                u16::from(slot.as_u8()),
                &data,
                EXEC_TIME_CHECKMAC_MS,
            )
            .await;

        match result
        {
            Ok(()) => Ok(true),
            Err(AteccError::Chip(ChipError::CheckMacOrVerifyFailed)) => Ok(false),
            Err(other) => Err(other),
        }
    }
}

#[cfg(test)]
mod tests
{
    use super::*;

    #[test]
    fn data_size_is_77()
    {
        assert_eq!(CHECKMAC_DATA_SIZE, 77);
    }

    #[test]
    fn challenge_mode_matches_cryptoauthlib_constant()
    {
        assert_eq!(CHECKMAC_MODE_CHALLENGE, 0x00);
    }
}