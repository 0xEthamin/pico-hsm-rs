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

//! `Sign` command.
//!
//! Produces an ECDSA P-256 signature using a private key stored in a slot.
//!
//! The driver exposes the "External" sign mode only: the host first loads
//! a 32-byte message digest into the chip's `TempKey` register via a
//! passthrough [`AteccChannel::nonce_passthrough`] call, then issues
//! [`AteccChannel::sign_external`]. The "Internal" sign mode (where the chip
//! signs a digest it computed itself in a previous operation) is not used
//! in this project's workflow and is therefore not exposed.
//!
//! Reference: `CryptoAuthLib` `lib/calib/calib_sign.c`, constants
//! `SIGN_MODE_EXTERNAL` (0x80), `SIGN_MODE_INTERNAL` (0x00).
//!
//! # Signature format
//!
//! The returned 64 bytes are the raw `R || S` form (each 32 bytes,
//! big-endian). To convert to the ASN.1 DER form used by many TLS or
//! certificate libraries, the higher layer must do so explicitly: the
//! driver returns the chip output verbatim.

use crate::driver::AteccChannel;
use crate::error::AteccError;
use crate::hal::AteccHal;
use crate::opcodes::{EXEC_TIME_SIGN_MS, OP_SIGN};
use crate::slot::Slot;

/// Size of the returned ECDSA P-256 signature (`R || S`).
pub const SIGNATURE_SIZE: usize = 64;

/// `param1` mode bits: external mode (sign the 32-byte digest pre-loaded in
/// `TempKey`).
const SIGN_MODE_EXTERNAL: u8 = 0x80;

impl<'a, H> AteccChannel<'a, H>
where
    H: AteccHal,
{
    /// Sign the 32-byte digest currently loaded in `TempKey` with the
    /// private key in `slot`.
    ///
    /// Callers must load the digest via [`AteccChannel::nonce_passthrough`]
    /// with target [`crate::command::nonce::NonceTarget::TempKey`]
    /// immediately before this call. Any intervening command that
    /// overwrites `TempKey` invalidates the operation.
    ///
    /// Returns the 64-byte raw signature `R || S`.
    ///
    /// # Errors
    /// See [`AteccChannel::execute_command`]. The chip rejects this command
    /// if the target slot has `ReqAuth=1` and no authenticated session is
    /// active, or if `TempKey` was not properly seeded.
    pub async fn sign_external
    (
        &mut self,
        slot: Slot,
    ) -> Result<[u8; SIGNATURE_SIZE], AteccError<H::Error>>
    {
        // Response: count(1) + 64 signature + crc(2) = 67 bytes.
        let mut response_buf = [0u8; 1 + SIGNATURE_SIZE + 2];
        let param2 = u16::from(slot.as_u8());
        let payload = self
            .execute_command
            (
                OP_SIGN,
                SIGN_MODE_EXTERNAL,
                param2,
                &[],
                EXEC_TIME_SIGN_MS,
                &mut response_buf,
            )
            .await?;

        let bytes: &[u8; SIGNATURE_SIZE] = payload
            .try_into()
            .map_err(|_| AteccError::MalformedResponse)?;
        Ok(*bytes)
    }
}

#[cfg(test)]
mod tests
{
    use super::*;

    #[test]
    fn external_mode_matches_cryptoauthlib_constant()
    {
        assert_eq!(SIGN_MODE_EXTERNAL, 0x80);
    }

    #[test]
    fn signature_size_is_64()
    {
        assert_eq!(SIGNATURE_SIZE, 64);
    }
}