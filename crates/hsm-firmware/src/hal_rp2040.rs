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

//! ATECC HAL implementation for the RP2040.
//!
//! Backs the [`atecc608b::AteccHal`] trait by `embassy_rp::i2c` for normal
//! transactions and by a brief `Output` reconfiguration of the SDA pin
//! for the ATECC wake pulse.
//!
//! # Wake pulse rationale
//!
//! The ATECC608B distinguishes a host-driven wake pulse from regular I2C
//! traffic by SDA being held low for at least `tWLO = 60 us`. Standard
//! I2C peripherals do not expose a way to hold a single line low for an
//! arbitrary duration without sending START / data / STOP, so we
//! temporarily reclaim the SDA pin from the I2C controller, drive it as
//! an output low for the requested duration, then release it. Pull-ups
//! on the bus return SDA to high after the release.
//!
//! The post-pulse wait (`tHTSU`, ~4.1 ms before the chip responds to I2C)
//! is the **driver's** responsibility, not the HAL's: [`crate::tasks`]
//! calls `atecc608b::wake::wake`, which performs `pulse_sda_low` followed
//! by a `delay_us(WAKE_DELAY_US)` of its own. Keeping the delay in the
//! driver lets us tune it without recompiling the firmware crate and
//! avoids a duplicated source of truth.
//!
//! # Resource management
//!
//! Because the I2C peripheral and the SDA pin are needed alternately in
//! two different modes, this HAL owns the [`Peri`] singletons directly
//! rather than holding a long-lived `I2c` instance. Each transaction
//! creates a fresh [`I2c`] via [`Peri::reborrow`], performs the
//! operation, and drops the controller. The peripherals are released for
//! the next transaction or for the wake pulse.

use embassy_rp::gpio::{Level, Output};
use embassy_rp::i2c::{self, Async, Config as I2cConfig, I2c, InterruptHandler};
use embassy_rp::peripherals::{I2C0, PIN_4, PIN_5};
use embassy_rp::{bind_interrupts, Peri};
use embassy_time::{Duration, Timer};

use atecc608b::AteccHal;

bind_interrupts!(pub(crate) struct Irqs
{
    I2C0_IRQ => InterruptHandler<I2C0>;
});

/// I2C bus frequency. The ATECC608B supports up to 1 MHz; we run at the
/// "fast mode" 400 kHz to match the typical layout constraints of
/// breadboard / 2-layer PCB hardware. Lower if signal integrity is poor.
pub(crate) const I2C_FREQ_HZ: u32 = 400_000;

/// Error type returned by the RP2040 HAL.
#[derive(Debug, defmt::Format)]
pub(crate) enum Rp2040HalError
{
    /// An I2C transfer failed (NACK, arbitration loss, abort, etc).
    I2c(i2c::Error),
}

impl From<i2c::Error> for Rp2040HalError
{
    fn from(err: i2c::Error) -> Self
    {
        Rp2040HalError::I2c(err)
    }
}

/// ATECC HAL bound to I2C0 on the RP2040.
///
/// Hard-wired to SCL=GP5, SDA=GP4 per the project schematic. To use a
/// different pin pair, change the concrete `PIN_*` types in the struct
/// fields and the `new` constructor signature.
pub(crate) struct Rp2040Hal
{
    /// Owned I2C0 instance, used by [`Peri::reborrow`] on each
    /// transaction.
    i2c_peri: Peri<'static, I2C0>,
    /// SCL pin (GP5).
    scl: Peri<'static, PIN_5>,
    /// SDA pin (GP4). Re-borrowed in either I2C mode or GPIO output
    /// mode depending on whether a wake pulse is in progress.
    sda: Peri<'static, PIN_4>,
}

impl Rp2040Hal
{
    /// Build the HAL from the three peripherals.
    ///
    /// The caller passes `peripherals.I2C0`, `peripherals.PIN_5` (SCL),
    /// and `peripherals.PIN_4` (SDA).
    #[must_use]
    pub(crate) fn new
    (
        i2c_peri: Peri<'static, I2C0>,
        scl: Peri<'static, PIN_5>,
        sda: Peri<'static, PIN_4>,
    ) -> Self
    {
        Self { i2c_peri, scl, sda }
    }

    /// Build a fresh `I2c` for one transaction. The instance is dropped
    /// when this function returns (or when the caller drops the
    /// returned `I2c`).
    fn build_i2c(&mut self) -> I2c<'_, I2C0, Async>
    {
        let mut config = I2cConfig::default();
        config.frequency = I2C_FREQ_HZ;
        I2c::new_async
        (
            self.i2c_peri.reborrow(),
            self.scl.reborrow(),
            self.sda.reborrow(),
            Irqs,
            config,
        )
    }
}

impl AteccHal for Rp2040Hal
{
    type Error = Rp2040HalError;

    async fn i2c_write(&mut self, addr: u8, data: &[u8]) -> Result<(), Self::Error>
    {
        let mut i2c = self.build_i2c();
        i2c.write_async(addr, data.iter().copied()).await?;
        Ok(())
    }

    async fn i2c_read(&mut self, addr: u8, buf: &mut [u8]) -> Result<(), Self::Error>
    {
        let mut i2c = self.build_i2c();
        i2c.read_async(addr, buf).await?;
        Ok(())
    }

    async fn pulse_sda_low(&mut self, duration_us: u32) -> Result<(), Self::Error>
    {
        // Drive SDA low for the requested duration. While this Output is
        // alive, the I2C controller cannot use SDA. We deliberately do
        // NOT hold an I2c instance across this call: the I2c gets
        // reconstructed on the next i2c_write / i2c_read, which
        // reconfigures the pin in alternate function mode.
        //
        // The post-pulse `tHTSU` wait happens in the driver (`wake::wake`
        // calls `delay_us(WAKE_DELAY_US)` right after this returns), so
        // this method does the pulse only.
        let mut sda_out = Output::new(self.sda.reborrow(), Level::Low);
        Timer::after(Duration::from_micros(u64::from(duration_us))).await;
        // Drive high briefly before releasing, to avoid a high-Z window
        // where the line could droop on weak pull-ups.
        sda_out.set_high();
        // Dropping the Output here returns SDA to high-Z input mode. The
        // external pull-ups (and the chip's internal pull-up) keep the
        // line high.
        drop(sda_out);
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