//! `Counter` command.
//!
//! Reads or increments one of the chip's two 21-bit monotonic counters
//! (Counter0 and Counter1). Counters never decrease and cannot be reset
//! once the data zone is locked.
//!
//! In this project's slot model:
//!
//! - Counter0 backs Slot 5 (PIN hash). It is bumped by 1 on every CheckMac
//!   against slot 5, with the convention that the driver rounds the counter
//!   up to the next multiple of 5 on successful verification so the user
//!   always gets a fresh batch of 5 attempts.
//! - Counter1 backs Slot 6 (PUK hash). Same mechanism with batches of 10.
//!
//! Reference: CryptoAuthLib `lib/calib/calib_counter.c`, constants
//! `COUNTER_MODE_READ` (0x00), `COUNTER_MODE_INCREMENT` (0x01).

use crate::driver::Atecc;
use crate::error::AteccError;
use crate::hal::AteccHal;
use crate::opcodes::{EXEC_TIME_COUNTER_MS, OP_COUNTER};

/// `param1` mode bits: read the counter without modifying it.
const COUNTER_MODE_READ: u8 = 0x00;

/// `param1` mode bits: increment the counter by 1, then return the new
/// value.
const COUNTER_MODE_INCREMENT: u8 = 0x01;

/// One of the chip's two monotonic counters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum CounterId
{
    /// Counter0. Used for PIN attempt tracking in this project.
    Counter0,
    /// Counter1. Used for PUK attempt tracking in this project.
    Counter1,
}

impl CounterId
{
    /// Numeric value used as `param2`.
    const fn as_param2(self) -> u16
    {
        match self
        {
            CounterId::Counter0 => 0x0000,
            CounterId::Counter1 => 0x0001,
        }
    }
}

impl<H> Atecc<H>
where
    H: AteccHal,
{
    /// Read the current value of a counter without modifying it.
    ///
    /// # Errors
    /// See [`Atecc::execute_command`].
    pub async fn counter_read(
        &mut self,
        counter: CounterId,
    ) -> Result<u32, AteccError<H::Error>>
    {
        self.counter_internal(COUNTER_MODE_READ, counter).await
    }

    /// Increment a counter by 1 and return its new value.
    ///
    /// # Errors
    /// See [`Atecc::execute_command`]. The chip returns
    /// [`crate::error::ChipError::ExecutionError`] when the counter has
    /// reached its maximum value of `2^21 - 1`.
    pub async fn counter_increment(
        &mut self,
        counter: CounterId,
    ) -> Result<u32, AteccError<H::Error>>
    {
        self.counter_internal(COUNTER_MODE_INCREMENT, counter).await
    }

    async fn counter_internal(
        &mut self,
        mode: u8,
        counter: CounterId,
    ) -> Result<u32, AteccError<H::Error>>
    {
        // Response: count(1) + 4 little-endian counter + crc(2) = 7 bytes.
        let mut response_buf = [0u8; 1 + 4 + 2];
        let payload = self
            .execute_command(
                OP_COUNTER,
                mode,
                counter.as_param2(),
                &[],
                EXEC_TIME_COUNTER_MS,
                &mut response_buf,
            )
            .await?;

        let bytes: &[u8; 4] = payload
            .try_into()
            .map_err(|_| AteccError::MalformedResponse)?;
        Ok(u32::from_le_bytes(*bytes))
    }
}

#[cfg(test)]
mod tests
{
    use super::*;

    #[test]
    fn counter_modes_match_cryptoauthlib_constants()
    {
        assert_eq!(COUNTER_MODE_READ, 0x00);
        assert_eq!(COUNTER_MODE_INCREMENT, 0x01);
    }

    #[test]
    fn counter_id_encodes_as_param2()
    {
        assert_eq!(CounterId::Counter0.as_param2(), 0x0000);
        assert_eq!(CounterId::Counter1.as_param2(), 0x0001);
    }
}