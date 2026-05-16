//! Hardware Abstraction Layer (HAL) the driver depends on.
//!
//! Concrete backends (RP2040, STM32, host-side mock, …) implement
//! [`AteccHal`]. The driver itself never touches a register directly: every
//! external action (I2C transfer, GPIO toggle, time delay) is mediated through
//! this trait.
//!
//! The trait is `async` because polling an ATECC608B for a `Sign` command may
//! take up to ~220 ms; doing this synchronously would starve other Embassy
//! tasks (USB, button handling, LED animation). The same trait can be wired up
//! to a non-Embassy executor as long as it understands `core::future::Future`.

use core::fmt::Debug;

/// Hardware operations the driver needs.
///
/// All operations are `async` to play nicely with Embassy. A backend that runs
/// on a blocking platform can return `core::future::ready(_)`.
pub trait AteccHal
{
    /// Backend-specific error type (`embassy_rp::i2c::Error`, a mock variant,
    /// etc.).
    type Error: Debug;

    /// Write a buffer to the chip over I2C.
    ///
    /// `device_addr` is the 7-bit slave address (typically `0x60` for the
    /// ATECC608B-SSHDA at default factory configuration).
    async fn i2c_write(
        &mut self,
        device_addr: u8,
        data: &[u8],
    ) -> Result<(), Self::Error>;

    /// Read a buffer from the chip over I2C. `buf` is filled exactly to its
    /// length.
    async fn i2c_read(
        &mut self,
        device_addr: u8,
        buf: &mut [u8],
    ) -> Result<(), Self::Error>;

    /// Pull the SDA line low for `duration_us` microseconds.
    ///
    /// This is the wake pulse: the ATECC608B leaves deep sleep when SDA is
    /// held low for at least `tWLO` ≈ 60 μs. The backend is responsible for
    /// temporarily detaching SDA from the I2C controller, driving it as a
    /// plain GPIO output, then restoring it. Callers must follow this with a
    /// 1.5 ms delay before issuing the first I2C transfer (see [`crate::wake`]).
    async fn pulse_sda_low(
        &mut self,
        duration_us: u32,
    ) -> Result<(), Self::Error>;

    /// Sleep for `duration_us` microseconds.
    ///
    /// On the RP2040 implementation this is backed by `embassy_time::Timer`.
    /// On the mock HAL it advances a simulated clock.
    async fn delay_us(
        &mut self,
        duration_us: u32,
    );

    /// Sleep for `duration_ms` milliseconds.
    async fn delay_ms(
        &mut self,
        duration_ms: u32,
    );
}
