//! ATECC HAL implementation for the RP2040.
//!
//! **NOT YET IMPLEMENTED.** This file currently exposes only a [`StubHal`]
//! that returns an error on every operation. It exists so the firmware
//! compiles and the USB stack can come up. The real RP2040 backend (I2C0
//! at 400 kHz on GP4/GP5, plus GPIO bit-bang for the wake pulse on SDA)
//! lands in a follow-up commit, against the hardware.

use atecc608b::AteccHal;
use embassy_time::{Duration, Timer};

/// Error type for the stub HAL.
#[derive(Debug)]
pub struct StubHalError;

/// Stub implementation of [`AteccHal`].
///
/// Every I2C operation returns [`StubHalError`]. Delays still go through
/// the real `embassy_time::Timer` so timing-sensitive driver code stays
/// exercised in a way that resembles the final behaviour.
pub struct StubHal;

impl StubHal
{
    /// Build a new stub HAL.
    #[must_use]
    pub const fn new() -> Self
    {
        Self
    }
}

impl Default for StubHal
{
    fn default() -> Self
    {
        Self::new()
    }
}

impl AteccHal for StubHal
{
    type Error = StubHalError;

    async fn i2c_write(&mut self, _addr: u8, _data: &[u8]) -> Result<(), Self::Error>
    {
        Err(StubHalError)
    }

    async fn i2c_read(&mut self, _addr: u8, _buf: &mut [u8]) -> Result<(), Self::Error>
    {
        Err(StubHalError)
    }

    async fn pulse_sda_low(&mut self, duration_us: u32) -> Result<(), Self::Error>
    {
        Timer::after(Duration::from_micros(u64::from(duration_us))).await;
        Ok(())
    }

    async fn delay_us(&mut self, duration_us: u32)
    {
        Timer::after(Duration::from_micros(u64::from(duration_us))).await;
    }

    async fn delay_ms(&mut self, duration_ms: u32)
    {
        Timer::after(Duration::from_millis(u64::from(duration_ms))).await;
    }
}