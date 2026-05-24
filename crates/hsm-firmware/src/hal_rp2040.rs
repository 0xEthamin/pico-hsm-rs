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
//! transactions and by a temporary 100 kHz I2C write to address `0x00`
//! for the ATECC wake token.
//!
//! # Wake-token rationale
//!
//! The ATECC608B detects a host-driven wake when SDA is held low for at
//! least `tWLO = 60 us`. There are two ways to produce that waveform:
//!
//! 1. **GPIO bit-bang**: reconfigure SDA as an output, drive it low for
//!    the required duration, release.
//! 2. **I2C wake token at 100 kHz** (what CryptoAuthLib does in
//!    `lib/calib/calib_basic.c::calib_wakeup_i2c` and every
//!    `lib/hal/hal_i2c_*.c::hal_i2c_wake`): drop the bus to 100 kHz so
//!    that the address byte of a regular I2C write to a NACK address
//!    (`0x00`) takes long enough to satisfy `tWLO`, then issue that
//!    write and ignore the inevitable NACK.
//!
//! We use the second method. The first one ran into stability problems
//! during bring-up: reconfiguring SDA between GPIO output and I2C
//! alternate function created transient transitions that the dormant
//! chip sometimes mis-interpreted as protocol noise, and led to
//! intermittent `0x04` HAL errors on subsequent reads. The CryptoAuthLib
//! method keeps the I2C controller in continuous control of the line
//! and matches the reference implementation byte-for-byte. Restoring the
//! bus to 400 kHz is automatic on the next [`Self::build_i2c`] call.
//!
//! The post-pulse wait (`tHTSU`, ~4.5 ms before the chip responds to
//! I2C) is the **driver's** responsibility, not the HAL's:
//! [`crate::tasks`] indirectly calls `atecc608b::wake::wake`, which
//! performs `pulse_sda_low` followed by a `delay_us(WAKE_DELAY_US)` of
//! its own. Keeping the delay in the driver lets us tune it without
//! recompiling the firmware crate and avoids a duplicated source of
//! truth.
//!
//! # Resource management
//!
//! Because the I2C peripheral and the SDA/SCL pins are needed at two
//! different bus frequencies (100 kHz for the wake token, 400 kHz
//! otherwise), this HAL owns the [`Peri`] singletons directly rather
//! than holding a long-lived `I2c` instance. Each transaction creates a
//! fresh [`I2c`] via [`Peri::reborrow`], performs the operation, and
//! drops the controller. The peripherals are released for the next
//! transaction or for the next wake token.

use embassy_rp::i2c::{self, Async, Config as I2cConfig, I2c, InterruptHandler};
use embassy_rp::peripherals::{I2C0, PIN_4, PIN_5};
use embassy_rp::{bind_interrupts, Peri};
use embassy_time::{Duration, Timer};

use atecc608b::AteccHal;

bind_interrupts!(pub(crate) struct Irqs
{
    I2C0_IRQ => InterruptHandler<I2C0>;
});

/// I2C bus frequency for normal command traffic. The ATECC608B supports
/// up to 1 MHz; we run at the "fast mode" 400 kHz to match the typical
/// layout constraints of breadboard / 2-layer PCB hardware. Lower if
/// signal integrity is poor.
pub(crate) const I2C_FREQ_HZ: u32 = 400_000;

/// I2C bus frequency used **only** for the wake token. CryptoAuthLib
/// drops to 100 kHz so a single byte time on the bus (~90 us address
/// phase) exceeds the chip's tWLO of 60 us. At 400 kHz an address byte
/// is too short to be seen as a wake token, hence the temporary slowdown.
pub(crate) const WAKE_TOKEN_FREQ_HZ: u32 = 100_000;

/// I2C address used to generate the wake token. CryptoAuthLib writes to
/// address `0x00` (general call) so the dormant chip NACKs cleanly. Any
/// address the chip does not respond to would do; sticking to `0x00`
/// matches the reference implementation.
pub(crate) const WAKE_TOKEN_ADDR: u8 = 0x00;

/// Filler byte for the wake-token write. RP2040's I2C peripheral refuses
/// zero-length writes; one filler byte is enough to make the controller
/// happy, and the byte is never actually clocked out because the address
/// is NACKed.
pub(crate) const WAKE_TOKEN_FILLER: u8 = 0x00;

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
    /// SDA pin (GP4). The pin is always driven by the I2C controller,
    /// at either 400 kHz (normal traffic) or 100 kHz (wake token). It
    /// is never reconfigured to GPIO output.
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

    async fn pulse_sda_low(&mut self, _duration_us: u32) -> Result<(), Self::Error>
    {
        // Wake-token method, faithful to CryptoAuthLib
        // (`lib/calib/calib_basic.c::calib_wakeup_i2c` and
        // `lib/hal/hal_i2c_*.c::hal_i2c_wake`):
        //
        // 1. Drop the bus to 100 kHz so a single I2C byte time exceeds
        //    `tWLO` (60 us, the chip's minimum wake-pulse low time).
        // 2. Issue a write to a deliberate-NACK address (here `0x00`,
        //    matching CryptoAuthLib). The address phase of that byte at
        //    100 kHz holds SDA in a pattern that the dormant chip
        //    detects as a wake token. The chip NACKs because it is
        //    asleep and `0x00` is not its address anyway; we ignore
        //    the result.
        // 3. The post-pulse `tHTSU` wait happens in the driver
        //    (`wake::wake` calls `delay_us(WAKE_DELAY_US)` right after
        //    this returns), so this method only generates the token.
        //
        // The `duration_us` argument is ignored: in CryptoAuthLib the
        // pulse duration is derived from the bus baud rate, not from
        // an external parameter. We keep the parameter in the trait to
        // accommodate alternative HALs (e.g. a SoftI2C HAL that does
        // need to bit-bang the line for a precise duration).
        //
        // RP2040 specific: `embassy_rp::i2c` refuses zero-length writes
        // because its FIFO state machine requires at least one byte to
        // queue, so we send one filler byte. The chip NACKs during the
        // address phase, the filler is never clocked out anyway.
        let mut config = I2cConfig::default();
        config.frequency = WAKE_TOKEN_FREQ_HZ;
        let mut i2c = I2c::new_async
        (
            self.i2c_peri.reborrow(),
            self.scl.reborrow(),
            self.sda.reborrow(),
            Irqs,
            config,
        );
        // The result is intentionally discarded: a NACK from address
        // `0x00` is the expected outcome, and any other I2C error here
        // is also moot since the only point of the call is the
        // waveform it places on SDA.
        let _ = i2c.write_async(WAKE_TOKEN_ADDR, [WAKE_TOKEN_FILLER]).await;
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