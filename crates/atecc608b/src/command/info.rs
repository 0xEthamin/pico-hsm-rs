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

//! `Info` command.
//!
//! The `Info` command (opcode `0x30`) returns 4 bytes of status. Several
//! modes are available, the most commonly used one being `Revision` which
//! returns the silicon revision code. For an ATECC608B in M0 clock divider
//! mode this is `00 00 60 02`, and `00 00 60 03` for M1.
//!
//! Reference: `CryptoAuthLib` `lib/calib/calib_info.c`.

use crate::driver::AteccChannel;
use crate::error::AteccError;
use crate::hal::AteccHal;
use crate::opcodes::{EXEC_TIME_INFO_MS, OP_INFO};

/// `Info` mode bytes (Param1).
///
/// Source: `CryptoAuthLib` `lib/calib/calib_command.h`, `INFO_MODE_*` constants.
#[repr(u8)]
#[non_exhaustive]
#[derive(Debug, Clone, Copy)]
pub(crate) enum InfoMode
{
    /// Return the silicon revision (4 bytes).
    Revision      = 0x00,
    /// Return the key valid bit for a slot.
    KeyValid      = 0x01,
    /// Return general device state (zero / not-zero, lock state, etc.).
    State         = 0x02,
    /// Return the GPIO state byte. Only meaningful when the chip's optional
    /// GPIO pin is enabled.
    Gpio          = 0x03,
    /// Return the persistent latch state.
    VolatileKeyPermission = 0x04,
}

impl<'a, H> AteccChannel<'a, H>
where
    H: AteccHal,
{
    /// Read the chip's revision bytes.
    ///
    /// Returns the 4-byte revision code. The first two bytes are reserved
    /// and always zero. The third byte is the device family (`0x60` for
    /// ATECC608B). The fourth byte distinguishes the clock divider variant
    /// (`0x02` for M0, `0x03` for M1, `0x04` for M2).
    ///
    /// # Errors
    /// See [`AteccChannel::execute_command`].
    pub async fn info_revision(&mut self) -> Result<[u8; 4], AteccError<H::Error>>
    {
        let mut response_buf = [0u8; 7];
        let payload = self
            .execute_command
            (
                OP_INFO,
                InfoMode::Revision as u8,
                0x0000,
                &[],
                EXEC_TIME_INFO_MS,
                &mut response_buf,
            )
            .await?;

        if payload.len() != 4
        {
            return Err(AteccError::MalformedResponse);
        }

        let mut out = [0u8; 4];
        out.copy_from_slice(payload);
        Ok(out)
    }

    /// Read the State byte from the chip.
    ///
    /// Returns the raw 4-byte response. Only the low byte conveys
    /// information (lock and config status bits). The other three bytes are
    /// reserved.
    ///
    /// # Errors
    /// See [`Atecc::execute_command`].
    pub(crate) async fn info_state(&mut self) -> Result<[u8; 4], AteccError<H::Error>>
    {
        let mut response_buf = [0u8; 7];
        let payload = self
            .execute_command(
                OP_INFO,
                InfoMode::State as u8,
                0x0000,
                &[],
                EXEC_TIME_INFO_MS,
                &mut response_buf,
            )
            .await?;

        if payload.len() != 4
        {
            return Err(AteccError::MalformedResponse);
        }

        let mut out = [0u8; 4];
        out.copy_from_slice(payload);
        Ok(out)
    }
}
