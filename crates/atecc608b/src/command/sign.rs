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

/// `param1` mode bits for `Sign(external)` on the ATECC608.
///
/// Combines two sub-flags:
/// - bit 7 (`0x80`) — `SIGN_MODE_EXTERNAL`: the message-to-sign is a
///   32-byte digest supplied by the host, not an internal chip state.
/// - bit 5 (`0x20`) — `SIGN_MODE_SOURCE_MSGDIGBUF`: take the digest
///   from the Message Digest Buffer (the 608's dedicated 32-byte
///   register), as opposed to `TempKey`.
///
/// **The 608's `Sign(external)` strictly requires the `MsgDigBuf` source.**
/// Sending `0x80` alone (no source bit) on a 608 makes the chip include
/// extra context bytes — serial number, OTP, etc. — in what it actually
/// signs, so the resulting signature does NOT verify against the raw
/// digest off-chip. Reference: `lib/calib/calib_sign.c::calib_sign` in
/// `CryptoAuthLib`, which selects this mode for `ATECC608`. The legacy
/// `0x80`-only encoding still works on the older ATECC108A / ATECC508A.
///
/// Callers must load the digest via
/// [`AteccChannel::nonce_passthrough`] with target
/// [`crate::command::nonce::NonceTarget::MsgDigBuf`] immediately before
/// this command.
const SIGN_MODE_EXTERNAL_FROM_MSGDIGBUF: u8 = 0xA0;

impl<H> AteccChannel<'_, H>
where
    H: AteccHal,
{
    /// Sign the 32-byte digest currently loaded in the Message Digest
    /// Buffer with the private key in `slot`.
    ///
    /// Callers must load the digest via [`AteccChannel::nonce_passthrough`]
    /// with target [`crate::command::nonce::NonceTarget::MsgDigBuf`]
    /// immediately before this call. Any intervening command that
    /// overwrites `MsgDigBuf` invalidates the operation.
    ///
    /// Returns the 64-byte raw signature `R || S`, both big-endian.
    /// `R` then `S`, each 32 bytes; this is the on-the-wire layout the
    /// chip returns and matches the convention used by every standard
    /// ECDSA verifier when the signature components are passed
    /// separately.
    ///
    /// # Errors
    /// See [`AteccChannel::execute_command`]. The chip rejects this
    /// command if the target slot has `ReqAuth=1` and no authenticated
    /// session is active, or if `MsgDigBuf` was not properly seeded by a
    /// preceding `Nonce(passthrough, target=MsgDigBuf)`.
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
                SIGN_MODE_EXTERNAL_FROM_MSGDIGBUF,
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
        // CryptoAuthLib `calib_sign` for ATECC608 selects
        // `SIGN_MODE_EXTERNAL | SIGN_MODE_SOURCE_MSGDIGBUF` = `0x80 | 0x20`.
        assert_eq!(SIGN_MODE_EXTERNAL_FROM_MSGDIGBUF, 0xA0);
    }

    #[test]
    fn signature_size_is_64()
    {
        assert_eq!(SIGNATURE_SIZE, 64);
    }
}