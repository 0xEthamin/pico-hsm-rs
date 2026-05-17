//! Top-level driver handle.
//!
//! [`Atecc`] owns the HAL and exposes the typed command API. High-level
//! commands like `Info` or `Sign` live in [`crate::command`]. They share the
//! same execution skeleton, which is implemented here as
//! [`Atecc::execute_command`].
//!
//! # Lifecycle
//!
//! Every command goes through the same dance:
//!
//! 1. **Wake** the chip if it is not already awake.
//! 2. **Send** the command frame, prefixed with the command word address.
//! 3. **Poll** for the response. The driver waits the nominal execution time
//!    for that opcode, then re-reads at fixed intervals until the chip
//!    responds or until the global timeout elapses.
//! 4. **Verify** the response CRC and parse it into either a payload or a
//!    chip error code.
//! 5. **Idle** the chip so the watchdog does not fire on the next call.
//!
//! Wake state is tracked by an internal `is_awake` flag so consecutive
//! commands skip the wake pulse. A successful `idle()` resets the flag.

use crate::error::{AteccError, ChipError};
use crate::hal::AteccHal;
use crate::opcodes::{
    I2C_ADDRESS,
    MAX_PACKET_SIZE,
    MAX_RESPONSE_SIZE,
    POLLING_MAX_MS,
    POLLING_PERIOD_MS,
    WORD_ADDRESS_COMMAND,
};
use crate::packet::{
    build_command_frame,
    parse_response_frame,
    PacketBuildError,
    PacketParseError,
    ResponseFrame,
};
use crate::wake::{idle, sleep, wake};

/// Driver handle owning the HAL and tracking the chip's awake/sleep state.
pub struct Atecc<H>
where
    H: AteccHal,
{
    hal:         H,
    device_addr: u8,
    is_awake:    bool,
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
    pub fn with_address(hal: H, addr: u8) -> Self
    {
        Self
        {
            hal,
            device_addr: addr,
            is_awake:    false,
        }
    }

    /// Consume the driver and return the underlying HAL.
    pub fn into_hal(self) -> H
    {
        self.hal
    }

    /// Borrow the underlying HAL mutably.
    ///
    /// Useful for tests that need to manipulate the mock directly. Most
    /// production code should never need this.
    pub fn hal_mut(&mut self) -> &mut H
    {
        &mut self.hal
    }

    /// Run the wake sequence if the driver does not believe the chip is
    /// already awake.
    ///
    /// # Errors
    /// Forwards every variant from [`crate::wake::wake`].
    pub async fn ensure_awake(&mut self) -> Result<(), AteccError<H::Error>>
    {
        if !self.is_awake
        {
            wake(&mut self.hal, self.device_addr).await?;
            self.is_awake = true;
        }
        Ok(())
    }

    /// Force a fresh wake regardless of the current state. Useful after a
    /// suspected sleep or after a communication error.
    ///
    /// # Errors
    /// Forwards every variant from [`crate::wake::wake`].
    pub async fn wake(&mut self) -> Result<(), AteccError<H::Error>>
    {
        self.is_awake = false;
        self.ensure_awake().await
    }

    /// Put the chip into idle.
    ///
    /// # Errors
    /// Forwards [`AteccError::Hal`] from the I2C layer.
    pub async fn idle(&mut self) -> Result<(), AteccError<H::Error>>
    {
        idle(&mut self.hal, self.device_addr).await?;
        // The watchdog is reset but the chip is now sleeping until the next
        // command. We will need a fresh wake next time.
        self.is_awake = false;
        Ok(())
    }

    /// Put the chip into deep sleep.
    ///
    /// # Errors
    /// Forwards [`AteccError::Hal`] from the I2C layer.
    pub async fn sleep(&mut self) -> Result<(), AteccError<H::Error>>
    {
        sleep(&mut self.hal, self.device_addr).await?;
        self.is_awake = false;
        Ok(())
    }

    /// Execute one full command round-trip.
    ///
    /// `data` is the command-specific payload, `expected_exec_ms` is the
    /// typical execution time for that opcode (consult the `EXEC_TIME_*`
    /// constants in [`crate::opcodes`]), and `response_buf` is filled with
    /// the raw response frame (count byte and CRC included).
    ///
    /// On success returns a `&[u8]` slice over the payload section of
    /// `response_buf` (excluding count and CRC).
    ///
    /// This function does not put the chip back to idle on its own. Callers
    /// that issue a single command should call [`Atecc::idle`] afterwards.
    /// Callers that chain commands (Nonce followed by Sign for example) can
    /// keep the chip awake between calls.
    ///
    /// # Errors
    /// Every variant of [`AteccError`] is reachable. See its documentation.
    pub async fn execute_command<'r>(
        &mut self,
        opcode: u8,
        param1: u8,
        param2: u16,
        data: &[u8],
        expected_exec_ms: u32,
        response_buf: &'r mut [u8],
    ) -> Result<&'r [u8], AteccError<H::Error>>
    {
        self.ensure_awake().await?;

        // Build the command frame. We use a stack buffer sized to the
        // protocol maximum so this works in pure no_std without an allocator.
        let mut tx = [0u8; MAX_PACKET_SIZE];
        // First byte sent on I2C is the command word address. The CRC of the
        // frame does not cover it.
        tx[0] = WORD_ADDRESS_COMMAND;
        let frame_len = build_command_frame(opcode, param1, param2, data, &mut tx[1..])
            .map_err(map_build_error)?;
        let total_tx = 1 + frame_len;

        self.hal.i2c_write(self.device_addr, &tx[..total_tx]).await?;

        // Wait the nominal execution time before the first attempt.
        self.hal.delay_ms(expected_exec_ms).await;

        let response_len = self.poll_for_response(response_buf).await?;
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
                        // A bare 0x00 status byte is not emitted by the chip
                        // in practice. Treat as malformed.
                        Err(AteccError::MalformedResponse)
                    }
                }
            }
        }
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
    async fn poll_for_response(
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
            match self.hal.i2c_read(self.device_addr, &mut count).await
            {
                Ok(()) =>
                {
                    let total = count[0] as usize;
                    if total < 4 || total > max_buf_len
                    {
                        return Err(AteccError::MalformedResponse);
                    }

                    response_buf[0] = count[0];
                    self.hal
                        .i2c_read(self.device_addr, &mut response_buf[1..total])
                        .await?;

                    return Ok(total);
                }
                Err(_) =>
                {
                    // Treated as "chip still busy". Back off and retry.
                    if elapsed_ms >= POLLING_MAX_MS
                    {
                        return Err(AteccError::Timeout);
                    }
                    self.hal.delay_ms(POLLING_PERIOD_MS).await;
                    elapsed_ms = elapsed_ms.saturating_add(POLLING_PERIOD_MS);
                }
            }
        }
    }
}

fn map_build_error<E: core::fmt::Debug>(err: PacketBuildError) -> AteccError<E>
{
    match err
    {
        PacketBuildError::DataTooLong { .. } => AteccError::BufferTooSmall,
        PacketBuildError::OutputBufferTooSmall { .. } => AteccError::BufferTooSmall,
    }
}

fn map_parse_error<E: core::fmt::Debug>(err: PacketParseError) -> AteccError<E>
{
    match err
    {
        PacketParseError::TooShort => AteccError::MalformedResponse,
        PacketParseError::LengthMismatch { .. } => AteccError::MalformedResponse,
        PacketParseError::BadCrc => AteccError::BadCrc,
    }
}
