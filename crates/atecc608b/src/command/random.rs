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

//! `Random` command.
//!
//! Returns 32 cryptographically random bytes from the chip's hardware RNG.
//! The default mode `0x00` updates the chip's internal seed before
//! generating the output, which is what we always want for production use.
//! Mode `0x01` skips the seed update and exists only for development.
//!
//! Reference: `CryptoAuthLib` `lib/calib/calib_random.c`.

use crate::driver::Atecc;
use crate::error::AteccError;
use crate::hal::AteccHal;
use crate::opcodes::{EXEC_TIME_RANDOM_MS, OP_RANDOM};

/// Number of random bytes returned by the chip in one Random command.
pub const RANDOM_OUTPUT_LEN: usize = 32;

impl<H> Atecc<H>
where
    H: AteccHal,
{
    /// Request 32 random bytes from the chip.
    ///
    /// The chip reseeds its internal RNG before producing the output.
    ///
    /// # Errors
    /// See [`Atecc::execute_command`].
    pub async fn random(&mut self) -> Result<[u8; RANDOM_OUTPUT_LEN], AteccError<H::Error>>
    {
        // Response: count(1) + 32 data + crc(2) = 35 bytes.
        let mut response_buf = [0u8; 35];
        let payload = self
            .execute_command(
                OP_RANDOM,
                0x00,
                0x0000,
                &[],
                EXEC_TIME_RANDOM_MS,
                &mut response_buf,
            )
            .await?;

        if payload.len() != RANDOM_OUTPUT_LEN
        {
            return Err(AteccError::MalformedResponse);
        }

        let mut out = [0u8; RANDOM_OUTPUT_LEN];
        out.copy_from_slice(payload);
        Ok(out)
    }
}
