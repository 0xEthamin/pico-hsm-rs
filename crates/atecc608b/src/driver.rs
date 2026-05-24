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

//! Top-level driver handle.
//!
//! The driver is split into two types that together model the chip's
//! lifecycle explicitly:
//!
//! - [`Atecc`] owns the HAL and represents a chip that is asleep (or about
//!   to be: the chip's actual state is unknown until a channel is opened).
//!   It has no command API. Its sole role is to hand out [`AteccChannel`]
//!   instances.
//! - [`AteccChannel`] is the awake-and-talking handle. All high-level
//!   commands (`Info`, `Sign`, `GenKey`, etc.) live as methods on this type
//!   in the [`crate::command`] modules. They share the same execution
//!   skeleton implemented here as [`AteccChannel::execute_command`] (for
//!   commands returning a data payload) and
//!   [`AteccChannel::execute_command_status`] (for commands that signal
//!   success with a single `0x00` status byte).
//!
//! # Lifecycle
//!
//! Every command goes through the same dance:
//!
//! 1. **Open a channel**: [`Atecc::open_channel`] wakes the chip and
//!    returns an [`AteccChannel`].
//! 2. **Send** the command frame, prefixed with the command word address.
//! 3. **Poll** for the response. The driver waits the nominal execution time
//!    for that opcode, then re-reads at fixed intervals until the chip
//!    responds or until the global timeout elapses.
//! 4. **Verify** the response CRC and parse it into either a payload or a
//!    chip status byte.
//! 5. **Close the channel**: [`AteccChannel::close`] sends the idle token
//!    so the watchdog does not fire on the next call. The borrow on
//!    [`Atecc`] is released.
//!
//! Within one channel the caller may run as many commands as needed (this
//! is how multi-step workflows like Nonce + Sign or Nonce + `GenDig` + Write
//! keep `TempKey` alive between steps). The channel must always be closed
//! explicitly so the chip's state stays in sync with the driver's view.
//!
//! # Why a separate `AteccChannel` type
//!
//! The ATECC608B requires a wake pulse before any command. After commands
//! are done, it must be put back to idle (or sleep), otherwise the chip's
//! internal watchdog (~1.3 s) silently transitions it to sleep without
//! informing the driver. A subsequent command would then see a NACK because
//! the driver still believes the chip is awake.
//!
//! Modeling "awake" as a separate type tied to a lifetime forces the caller
//! to acquire a channel for every command sequence and close it when done,
//! which keeps the chip's state synchronized with the driver's view at
//! every program point. The borrow checker enforces that you cannot
//! "forget" to wake, and a `Drop` warning (see [`AteccChannel`]) catches
//! the case where a channel is dropped without `close()`.

use crate::error::{AteccError, ChipError};
use crate::hal::AteccHal;
use crate::opcodes::
{
    I2C_ADDRESS,
    MAX_PACKET_SIZE,
    MAX_RESPONSE_SIZE,
    POLLING_MAX_MS,
    POLLING_PERIOD_MS,
    WORD_ADDRESS_COMMAND,
};
use crate::packet::
{
    build_command_frame,
    parse_response_frame,
    PacketBuildError,
    PacketParseError,
    ResponseFrame,
};
use crate::wake::{idle, sleep, wake};

/// Smallest valid response frame: count + status + crc(2).
const STATUS_RESPONSE_LEN: usize = 4;

/// Driver handle owning the HAL.
///
/// Does not, by itself, expose any chip command. Use [`Self::open_channel`]
/// to wake the chip and obtain an [`AteccChannel`] on which the command
/// API lives.
pub struct Atecc<H>
where
    H: AteccHal,
{
    hal:         H,
    device_addr: u8,
}

impl<H> Atecc<H>
where
    H: AteccHal,
{
    /// Build a new driver around an existing HAL, using the chip's default
    /// I2C address ([`I2C_ADDRESS`]).
    pub fn new(hal: H) -> Self
    {
        Self::with_address(hal, I2C_ADDRESS)
    }

    /// Build a new driver against a chip with a non-default I2C address.
    pub(crate) fn with_address(hal: H, addr: u8) -> Self
    {
        Self
        {
            hal,
            device_addr: addr,
        }
    }

    /// Consume the driver and return the underlying HAL.
    pub fn into_hal(self) -> H
    {
        self.hal
    }

    /// Open a communication channel with the chip.
    ///
    /// Performs the wake sequence and returns an [`AteccChannel`] that
    /// exposes the typed command API. The channel borrows `self` mutably
    /// for as long as it exists, which prevents accidentally opening two
    /// channels concurrently.
    ///
    /// The caller is expected to close the channel via
    /// [`AteccChannel::close`] when finished. Dropping a channel without
    /// closing leaves the chip awake; its watchdog will eventually idle it,
    /// but the next [`Self::open_channel`] call may observe a transient
    /// state. A `defmt::warn!` is emitted in that case to flag the
    /// protocol violation.
    ///
    /// # Errors
    /// Forwards every variant from [`crate::wake::wake`].
    pub async fn open_channel(&mut self) -> Result<AteccChannel<'_, H>, AteccError<H::Error>>
    {
        wake(&mut self.hal, self.device_addr).await?;
        Ok(AteccChannel
        {
            driver: self,
            closed: false,
        })
    }
}

/// An open communication channel with a woken chip.
///
/// Holds a mutable borrow of the parent [`Atecc`] for the duration of the
/// channel. All high-level chip commands are exposed as methods on this
/// type (see the [`crate::command`] modules: `info`, `random`, `sign`, etc.).
///
/// # Closing
///
/// The channel must be closed via [`Self::close`] when commands are done.
/// Closing sends the idle token, which preserves volatile state (`TempKey`,
/// RNG seed) and resets the chip's watchdog. After close, the parent
/// [`Atecc`] becomes usable again for a new channel.
///
/// To put the chip into its lowest-power mode and clear volatile state
/// instead of just idling, use [`Self::close_to_sleep`].
///
/// If the channel is dropped without `close` being called, the chip is
/// left awake. Its watchdog will eventually time it out to sleep, and the
/// next [`Atecc::open_channel`] call will wake it normally. The [`Drop`]
/// impl emits a `defmt::warn!` to flag the protocol violation in
/// development; nothing breaks, but it indicates a bug to fix.
pub struct AteccChannel<'a, H>
where
    H: AteccHal,
{
    driver: &'a mut Atecc<H>,
    closed: bool,
}

impl<H> AteccChannel<'_, H>
where
    H: AteccHal,
{
    /// Close the channel by sending the idle token to the chip and
    /// consuming the channel handle.
    ///
    /// Idle preserves volatile chip state (`TempKey`, RNG seed) and resets
    /// the chip's watchdog. To clear volatile state and put the chip into
    /// its lowest-power mode instead, use [`Self::close_to_sleep`].
    ///
    /// # Errors
    /// Forwards [`AteccError::Hal`] from the I2C layer.
    pub async fn close(mut self) -> Result<(), AteccError<H::Error>>
    {
        idle(&mut self.driver.hal, self.driver.device_addr).await?;
        self.closed = true;
        Ok(())
    }

    /// Close the channel by sending the sleep token to the chip.
    ///
    /// Unlike [`Self::close`], sleep clears volatile state (`TempKey`, RNG
    /// seed) and brings the chip to its low power consumption level. The
    /// next [`Atecc::open_channel`] will re-wake the chip from a clean
    /// state.
    ///
    /// # Errors
    /// Forwards [`AteccError::Hal`] from the I2C layer.
    pub async fn close_to_sleep(mut self) -> Result<(), AteccError<H::Error>>
    {
        sleep(&mut self.driver.hal, self.driver.device_addr).await?;
        self.closed = true;
        Ok(())
    }

    /// Force a fresh wake mid-channel.
    ///
    /// Useful after an HAL-level error suggests the chip's state has become
    /// uncertain (a NACK during a command, for example). Equivalent to
    /// closing and reopening the channel, but cheaper because it does not
    /// idle first.
    ///
    /// # Errors
    /// Forwards every variant from [`crate::wake::wake`].
    pub async fn refresh(&mut self) -> Result<(), AteccError<H::Error>>
    {
        wake(&mut self.driver.hal, self.driver.device_addr).await
    }

    /// Execute one full command round-trip and return the data payload.
    ///
    /// Use this overload for commands that return data (Info, Random, Read,
    /// `GenKey`, Sign, Verify, ECDH). The chip responds with `count >= 5`
    /// bytes (count + payload + CRC).
    ///
    /// For commands that only signal success or failure via a 4-byte status
    /// frame (Write, Lock, Counter set), use [`Self::execute_command_status`].
    /// This method does not accept the `0x00` success byte because a
    /// data-returning command never emits a bare `0x00`. If it appears
    /// here, the frame is malformed.
    ///
    /// `data` is the command-specific payload, `expected_exec_ms` is the
    /// typical execution time for that opcode (consult the `EXEC_TIME_*`
    /// constants in [`crate::opcodes`]), and `response_buf` is filled with
    /// the raw response frame (count byte and CRC included).
    ///
    /// On success returns a `&[u8]` slice over the payload section of
    /// `response_buf` (excluding count and CRC).
    ///
    /// This method does not idle the chip on its own. Callers that have
    /// finished their command sequence should drop the channel via
    /// [`Self::close`]. Callers chaining multiple commands that share
    /// volatile state (Nonce followed by Sign for example) keep the
    /// channel open between calls.
    ///
    /// # Errors
    /// Every variant of [`AteccError`] is reachable. See its documentation.
    pub(crate) async fn execute_command<'r>
    (
        &mut self,
        opcode: u8,
        param1: u8,
        param2: u16,
        data: &[u8],
        expected_exec_ms: u32,
        response_buf: &'r mut [u8],
    ) -> Result<&'r [u8], AteccError<H::Error>>
    {
        let response_len = self
            .run_command(opcode, param1, param2, data, expected_exec_ms, response_buf)
            .await?;
        let response = &response_buf[..response_len];

        match parse_response_frame(response).map_err(map_parse_error)?
        {
            ResponseFrame::Payload(_) =>
            {
                // Re-borrow the payload from response_buf with the caller's
                // lifetime. The slice indexes are count byte (1) up to the
                // two trailing CRC bytes.
                Ok(&response_buf[1..response_len - 2])
            }
            ResponseFrame::Status(status_byte) =>
            {
                match ChipError::from_status_byte(status_byte)
                {
                    Some(err) => Err(AteccError::Chip(err)),
                    None =>
                    {
                        // A bare 0x00 status here means the chip returned a
                        // 4-byte success frame for a data-returning command.
                        // That should not happen for the opcodes that use
                        // this method. Treat as malformed.
                        Err(AteccError::MalformedResponse)
                    }
                }
            }
        }
    }

    /// Execute one full command round-trip and expect a status-only response.
    ///
    /// Use this overload for commands that signal completion with a 4-byte
    /// status frame (Write, Lock, Counter set, Nonce mode 0x03). A status
    /// byte of `0x00` is the success indicator. Any non-zero status maps to
    /// an [`AteccError::Chip`] variant.
    ///
    /// A response longer than 4 bytes here means the chip returned data
    /// when none was expected. This is treated as a malformed response.
    ///
    /// # Errors
    /// Every variant of [`AteccError`] is reachable. See its documentation.
    pub(crate) async fn execute_command_status
    (
        &mut self,
        opcode: u8,
        param1: u8,
        param2: u16,
        data: &[u8],
        expected_exec_ms: u32,
    ) -> Result<(), AteccError<H::Error>>
    {
        let mut response_buf = [0u8; STATUS_RESPONSE_LEN];
        let response_len = self
            .run_command
            (
                opcode,
                param1,
                param2,
                data,
                expected_exec_ms,
                &mut response_buf,
            )
            .await?;

        if response_len != STATUS_RESPONSE_LEN
        {
            return Err(AteccError::MalformedResponse);
        }

        match parse_response_frame(&response_buf[..response_len]).map_err(map_parse_error)?
        {
            ResponseFrame::Status(0x00) => Ok(()),
            ResponseFrame::Status(status_byte) => Err(AteccError::Chip(
                ChipError::from_status_byte(status_byte)
                    .unwrap_or(ChipError::Unknown(status_byte)),
            )),
            ResponseFrame::Payload(_) => Err(AteccError::MalformedResponse),
        }
    }

    /// Send the command frame and poll for the raw response.
    ///
    /// Returns the total number of bytes written into `response_buf` (count
    /// byte included). Parsing of the response frame is the caller's
    /// responsibility, so this helper can be shared between the data-payload
    /// and status-only entry points above.
    ///
    /// This helper does NOT idle the chip after the response: the channel
    /// model means idling is the explicit job of [`Self::close`]. That
    /// keeps multi-step workflows (Nonce + Sign, Nonce + `GenDig` + Write)
    /// working naturally inside a single channel.
    async fn run_command
    (
        &mut self,
        opcode: u8,
        param1: u8,
        param2: u16,
        data: &[u8],
        expected_exec_ms: u32,
        response_buf: &mut [u8],
    ) -> Result<usize, AteccError<H::Error>>
    {
        // Build the command frame. We use a stack buffer sized to the
        // protocol maximum so this works in pure no_std without an allocator.
        let mut tx = [0u8; MAX_PACKET_SIZE];
        // First byte sent on I2C is the command word address. The CRC of the
        // frame does not cover it.
        tx[0] = WORD_ADDRESS_COMMAND;
        let frame_len = build_command_frame(opcode, param1, param2, data, &mut tx[1..])
            .map_err(map_build_error)?;
        let total_tx = 1 + frame_len;

        self.driver.hal.i2c_write(self.driver.device_addr, &tx[..total_tx]).await?;

        // Wait the nominal execution time before the first attempt.
        self.driver.hal.delay_ms(expected_exec_ms).await;

        self.poll_for_response(response_buf).await
    }

    /// Poll the chip's response register until a frame is available or the
    /// global timeout elapses.
    ///
    /// The ATECC608B signals "I am ready" by responding to the read with the
    /// frame proper. While it is still busy it NACKs the read, which
    /// surfaces as an HAL error. We treat any HAL error during this phase as
    /// "not yet ready" and retry after [`POLLING_PERIOD_MS`].
    ///
    /// On success returns the number of bytes written into `response_buf`.
    async fn poll_for_response
    (
        &mut self,
        response_buf: &mut [u8],
    ) -> Result<usize, AteccError<H::Error>>
    {
        let max_buf_len = response_buf.len().min(MAX_RESPONSE_SIZE);
        let mut elapsed_ms: u32 = 0;

        loop
        {
            // First read the count byte alone. This tells us how big the
            // rest of the frame is.
            let mut count = [0u8; 1];
            if let Ok(()) = self.driver.hal.i2c_read(self.driver.device_addr, &mut count).await
            {
                let total = count[0] as usize;
                if total < 4 || total > max_buf_len
                {
                    return Err(AteccError::MalformedResponse);
                }

                response_buf[0] = count[0];
                self.driver.hal
                    .i2c_read(self.driver.device_addr, &mut response_buf[1..total])
                    .await?;

                return Ok(total);
            }
            // Treated as "chip still busy". Back off and retry.
            if elapsed_ms >= POLLING_MAX_MS
            {
                return Err(AteccError::Timeout);
            }
            self.driver.hal.delay_ms(POLLING_PERIOD_MS).await;
            elapsed_ms = elapsed_ms.saturating_add(POLLING_PERIOD_MS);
        }
    }
}

impl<H> Drop for AteccChannel<'_, H>
where
    H: AteccHal,
{
    /// On drop without an explicit `close`, emit a `defmt::warn!` to flag
    /// the protocol violation.
    ///
    /// The chip is left awake; its watchdog (~1.3 s) will eventually idle
    /// it, but the next channel may observe a transient state for that
    /// duration. The drop itself cannot send the idle token because Drop
    /// is synchronous and the HAL is async; the warn-on-drop is the only
    /// signal we can emit without a `block_on` of unknown safety.
    fn drop(&mut self)
    {
        if !self.closed
        {
            #[cfg(feature = "defmt")]
            defmt::warn!
            (
                "AteccChannel dropped without close(); chip left awake. \
                 Its watchdog (~1.3 s) will eventually idle it, but the \
                 next open_channel may observe a transient state. Fix \
                 the caller to call channel.close().await explicitly."
            );
        }
    }
}

fn map_build_error<E: core::fmt::Debug>(err: PacketBuildError) -> AteccError<E>
{
    match err
    {
        PacketBuildError::DataTooLong { .. } | PacketBuildError::OutputBufferTooSmall { .. } =>
        {
            AteccError::BufferTooSmall
        }
    }
}

fn map_parse_error<E: core::fmt::Debug>(err: PacketParseError) -> AteccError<E>
{
    match err
    {
        PacketParseError::TooShort | PacketParseError::LengthMismatch { .. } =>
        {
            AteccError::MalformedResponse
        }
        PacketParseError::BadCrc => AteccError::BadCrc,
    }
}
