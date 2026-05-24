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

//! `Verify` command.
//!
//! Verifies an ECDSA P-256 signature on-chip.
//!
//! The driver exposes the "External" verify mode only: the host provides the
//! 64-byte public key (uncompressed `X || Y`), the 64-byte signature
//! (`R || S`), and the 32-byte digest is taken from `TempKey` (loaded via
//! [`AteccChannel::nonce_passthrough`]). The "Stored" mode (verify against a
//! public key already in a slot) and "Validate" mode (chained validation
//! of a previously-stored signature) are not used in this project's
//! workflow.
//!
//! Reference: `CryptoAuthLib` `lib/calib/calib_verify.c`, constants
//! `VERIFY_MODE_EXTERNAL` (0x02), `VERIFY_KEY_P256` (0x0004).

use crate::driver::AteccChannel;
use crate::error::AteccError;
use crate::hal::AteccHal;
use crate::opcodes::{EXEC_TIME_VERIFY_MS, OP_VERIFY};

use crate::command::genkey::PUBLIC_KEY_SIZE;
use crate::command::sign::SIGNATURE_SIZE;

/// Size of the `Verify External` data payload (signature || pubkey).
pub(crate) const VERIFY_EXTERNAL_DATA_SIZE: usize = SIGNATURE_SIZE + PUBLIC_KEY_SIZE;

/// `param1` mode: External verify.
const VERIFY_MODE_EXTERNAL: u8 = 0x02;

/// `param2` key id for the P-256 (NIST secp256r1) curve.
const VERIFY_KEY_P256: u16 = 0x0004;

impl<H> AteccChannel<'_, H>
where
    H: AteccHal,
{
    /// Verify an ECDSA P-256 signature against the digest currently loaded
    /// in `TempKey`.
    ///
    /// Callers must load the digest via [`AteccChannel::nonce_passthrough`]
    /// with target [`crate::command::nonce::NonceTarget::TempKey`]
    /// immediately before this call.
    ///
    /// `signature` is the 64-byte raw `R || S` returned by `Sign`.
    /// `public_key` is the 64-byte raw `X || Y` returned by `GenKey`.
    ///
    /// On success returns `Ok(true)` when the signature matches the digest
    /// under the given public key, and `Ok(false)` when the chip cleanly
    /// rejects the signature. Any other error condition surfaces as
    /// [`AteccError`].
    ///
    /// # Errors
    /// See [`AteccChannel::execute_command_status`]. A signature mismatch
    /// surfaces here as `Ok(false)`, not as an error: the chip uses
    /// [`crate::error::ChipError::CheckMacOrVerifyFailed`] (status 0x01)
    /// specifically to flag this case, and the driver maps it back to a
    /// boolean for ergonomics.
    pub async fn verify_external
    (
        &mut self,
        signature: &[u8; SIGNATURE_SIZE],
        public_key: &[u8; PUBLIC_KEY_SIZE],
    ) -> Result<bool, AteccError<H::Error>>
    {
        let mut data = [0u8; VERIFY_EXTERNAL_DATA_SIZE];
        data[..SIGNATURE_SIZE].copy_from_slice(signature);
        data[SIGNATURE_SIZE..].copy_from_slice(public_key);

        let result = self
            .execute_command_status
            (
                OP_VERIFY,
                VERIFY_MODE_EXTERNAL,
                VERIFY_KEY_P256,
                &data,
                EXEC_TIME_VERIFY_MS,
            )
            .await;

        match result
        {
            Ok(()) => Ok(true),
            Err(AteccError::Chip(crate::error::ChipError::CheckMacOrVerifyFailed)) =>
            {
                Ok(false)
            }
            Err(other) => Err(other),
        }
    }
}

#[cfg(test)]
mod tests
{
    use super::*;

    #[test]
    fn external_mode_matches_cryptoauthlib_constant()
    {
        assert_eq!(VERIFY_MODE_EXTERNAL, 0x02);
    }

    #[test]
    fn p256_key_id_matches_cryptoauthlib_constant()
    {
        assert_eq!(VERIFY_KEY_P256, 0x0004);
    }

    #[test]
    fn external_data_size_is_128()
    {
        assert_eq!(VERIFY_EXTERNAL_DATA_SIZE, 128);
    }
}