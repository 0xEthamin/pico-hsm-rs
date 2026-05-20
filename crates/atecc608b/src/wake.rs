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

//! Wake, idle, and sleep sequences for the ATECC608B.
//!
//! The chip spends most of its life in deep sleep (under 150 nA). To talk to
//! it the driver must first perform a wake sequence. After commands have been
//! issued, the driver should put the chip back to idle or sleep before its
//! watchdog (about 1.3 s nominal) elapses on its own.
//!
//! The functions in this module are agnostic to the high-level command flow.
//! They live one level below [`crate::driver::Atecc`] and operate directly on
//! a HAL plus an I2C address.
//!
//! # Wake protocol
//!
//! 1. Pull SDA low for at least
//!    [`crate::opcodes::WAKE_LOW_DURATION_US`] microseconds.
//! 2. Release SDA and wait [`crate::opcodes::WAKE_DELAY_US`] microseconds.
//! 3. Read 4 bytes back over I2C. They must equal
//!    [`crate::opcodes::WAKE_RESPONSE_OK`] (`04 11 33 43`).
//!
//! If the chip's power-on self-test failed, the response is
//! [`crate::opcodes::WAKE_RESPONSE_SELFTEST_FAIL`] (`04 07 C4 40`) instead.
//!
//! # Idle and sleep
//!
//! - **Idle** preserves the contents of `TempKey` and the random number
//!   generator state. Useful between two related commands.
//! - **Sleep** clears volatile state and brings the chip back to its low
//!   power consumption level.
//!
//! Both are issued as a single I2C write of the corresponding word address
//! byte, with no payload.

use crate::error::AteccError;
use crate::hal::AteccHal;
use crate::opcodes::{
    WAKE_DELAY_US,
    WAKE_LOW_DURATION_US,
    WAKE_RESPONSE_OK,
    WAKE_RESPONSE_SELFTEST_FAIL,
    WORD_ADDRESS_IDLE,
    WORD_ADDRESS_SLEEP,
};

/// Perform the wake sequence and verify the chip's response.
///
/// On success the chip is awake and ready to receive a command.
///
/// # Errors
/// - [`AteccError::WakeFailed`] if the response does not match
///   [`WAKE_RESPONSE_OK`].
/// - [`AteccError::SelfTestFailure`] if the response is the self-test failure
///   pattern. The chip is unusable until the next power cycle.
/// - [`AteccError::Hal`] if the HAL itself reports an I2C or GPIO error.
pub async fn wake<H>(hal: &mut H, device_addr: u8) -> Result<(), AteccError<H::Error>>
where
    H: AteccHal,
{
    // Step 1: hold SDA low long enough for the chip to detect a wake pulse.
    hal.pulse_sda_low(WAKE_LOW_DURATION_US).await?;

    // Step 2: let the chip's internal logic come up.
    hal.delay_us(WAKE_DELAY_US).await;

    // Step 3: read 4 bytes and compare against the known good and known bad
    // patterns.
    let mut response = [0u8; 4];
    hal.i2c_read(device_addr, &mut response).await?;

    if response == WAKE_RESPONSE_OK
    {
        Ok(())
    }
    else if response == WAKE_RESPONSE_SELFTEST_FAIL
    {
        Err(AteccError::SelfTestFailure)
    }
    else
    {
        Err(AteccError::WakeFailed)
    }
}

/// Put the chip into idle.
///
/// Idle preserves volatile state (`TempKey`, RNG seed) but resets the watchdog.
/// Useful between two commands that share `TempKey`, like Nonce followed by
/// Sign.
///
/// # Errors
/// [`AteccError::Hal`] if the I2C write fails.
pub async fn idle<H>(hal: &mut H, device_addr: u8) -> Result<(), AteccError<H::Error>>
where
    H: AteccHal,
{
    hal.i2c_write(device_addr, &[WORD_ADDRESS_IDLE]).await?;
    Ok(())
}

/// Put the chip into deep sleep.
///
/// Volatile state is cleared. The next operation will need a fresh wake.
///
/// # Errors
/// [`AteccError::Hal`] if the I2C write fails.
pub async fn sleep<H>(hal: &mut H, device_addr: u8) -> Result<(), AteccError<H::Error>>
where
    H: AteccHal,
{
    hal.i2c_write(device_addr, &[WORD_ADDRESS_SLEEP]).await?;
    Ok(())
}
