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

//! Hardware Abstraction Layer (HAL) the driver depends on.
//!
//! Concrete backends (RP2040, STM32, host-side mock, etc.) implement
//! [`AteccHal`]. The driver itself never touches a register directly. Every
//! external action (I2C transfer, GPIO toggle, time delay) is mediated through
//! this trait.
//!
//! The trait is `async` because polling an ATECC608B for a `Sign` command may
//! take up to 220 ms. Doing this synchronously would starve other Embassy
//! tasks (USB, button handling, LED animation). The same trait can be wired up
//! to a non-Embassy executor as long as it understands `core::future::Future`.

use core::fmt::Debug;

/// Hardware operations the driver needs.
///
/// All operations are `async` to play nicely with Embassy. A backend that runs
/// on a blocking platform can return `core::future::ready(_)`.
///
/// `async fn` in a public trait normally triggers a lint because the returned
/// future is not `Send` and the caller has no way to add that bound. We
/// silence it deliberately. The driver and its backends are all consumed by a
/// single-threaded Embassy executor, where `Send` is irrelevant.
#[allow(async_fn_in_trait)]
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
    /// This is the wake pulse. The ATECC608B leaves deep sleep when SDA is
    /// held low for at least `tWLO` (about 60 us). The backend is responsible
    /// for temporarily detaching SDA from the I2C controller, driving it as a
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
