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

//! `PrivWrite` command.
//!
//! Writes a P-256 private key from the host into a slot.
//!
//! # Project policy
//!
//! **This command is intentionally NOT used for the user identity key.**
//! User identity keys (slots 0..=4 in this project) are generated on-chip
//! via [`crate::command::genkey::AteccChannel::genkey_create`] so that the private
//! material never traverses the host or the USB bus. `PrivWrite` exists
//! here for bring-up and for the V3 attestation slot (slot 7) only, both
//! controlled by a privileged path in `tools/hsm-host`.
//!
//! # Modes
//!
//! Two modes exist:
//!
//! - **Cleartext** (`param1 = 0x00`). Only accepted before the data zone is
//!   locked. Used during bring-up to load known test keys.
//! - **Encrypted** (`param1 = 0x40`). Required after data zone lock. The
//!   data field carries ciphertext plus a 32-byte MAC. The driver does not
//!   currently expose the encrypted path: the orchestration is
//!   service-layer work that depends on
//!   [`crate::command::nonce::AteccChannel::nonce_random`] +
//!   [`crate::command::gendig::AteccChannel::gendig`] and the matching host-side
//!   key derivation. It will be added when that orchestration lands.
//!
//! Reference: `CryptoAuthLib` `lib/calib/calib_priv_write.c`, constants
//! `PRIV_WRITE_MODE_ENCRYPT` (0x40).
//!
//! # Data layout
//!
//! Cleartext: 4-byte zero padding then the 32-byte raw private scalar
//! (big-endian, the natural P-256 byte order).
//!
//! ```text
//! [00 00 00 00] [P-256 scalar, 32 bytes BE]
//! ```

use crate::driver::AteccChannel;
use crate::error::AteccError;
use crate::hal::AteccHal;
use crate::opcodes::{EXEC_TIME_PRIVWRITE_MS, OP_PRIVWRITE};
use crate::slot::Slot;

/// Cleartext `PrivWrite` payload size (4 padding + 32 scalar).
pub const PRIVWRITE_CLEARTEXT_SIZE: usize = 36;

/// `param1` mode for cleartext `PrivWrite` (data zone unlocked only).
const PRIVWRITE_MODE_CLEARTEXT: u8 = 0x00;

impl<H> AteccChannel<'_, H>
where
    H: AteccHal,
{
    /// Write a 32-byte P-256 private scalar into `slot` in cleartext.
    ///
    /// **Only valid while the data zone is unlocked**, which on this project
    /// means before the irreversible data-zone Lock has been performed.
    /// Calling this after lock returns a chip error.
    ///
    /// **Not for the user identity key.** The user identity key is created
    /// on-chip via `genkey_create`. This entry point exists for bring-up
    /// helpers (loading a known test key into a scratch slot) and for the
    /// attestation slot if used.
    ///
    /// `private_key` is the raw 32-byte scalar in big-endian form, the
    /// natural P-256 byte order matching the output of standard libraries
    /// (`p256`, OpenSSL, etc.).
    ///
    /// # Errors
    /// See [`AteccChannel::execute_command_status`]. Returns a chip error if
    /// the data zone is already locked.
    pub async fn privwrite_cleartext
    (
        &mut self,
        slot: Slot,
        private_key: &[u8; 32],
    ) -> Result<(), AteccError<H::Error>>
    {
        let mut data = [0u8; PRIVWRITE_CLEARTEXT_SIZE];
        // First 4 bytes are zero padding as required by the chip.
        data[4..].copy_from_slice(private_key);

        self.execute_command_status
        (
            OP_PRIVWRITE,
            PRIVWRITE_MODE_CLEARTEXT,
            u16::from(slot.as_u8()),
            &data,
            EXEC_TIME_PRIVWRITE_MS,
        )
        .await
    }
}

#[cfg(test)]
mod tests
{
    use super::*;

    #[test]
    fn cleartext_payload_size_is_36()
    {
        assert_eq!(PRIVWRITE_CLEARTEXT_SIZE, 36);
    }

    #[test]
    fn cleartext_mode_is_zero()
    {
        assert_eq!(PRIVWRITE_MODE_CLEARTEXT, 0x00);
    }
}