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

//! In-memory mock implementation of [`atecc608b::hal::AteccHal`] used by all
//! integration tests in this crate.
//!
//! The mock holds a script of expected operations and a queue of canned read
//! payloads. Each method call pops the next expectation, compares it to the
//! actual arguments, and (for reads) returns the next canned payload.
//!
//! Test files in `tests/` declare `mod common;` to import this module.

#![allow(dead_code)]

use std::collections::VecDeque;

use atecc608b::AteccHal;

/// A single recorded interaction with the HAL.
#[derive(Debug, PartialEq, Eq, Clone)]
pub(crate) enum MockOp
{
    /// I2C master write of `data` to `addr`.
    I2cWrite
    {
        /// 7-bit I2C slave address.
        addr: u8,
        /// Bytes written.
        data: Vec<u8>,
    },
    /// I2C master read of exactly `len` bytes from `addr`.
    I2cRead
    {
        /// 7-bit I2C slave address.
        addr: u8,
        /// Number of bytes to read.
        len: usize,
    },
    /// I2C master read that the chip NACKs. No bytes are exchanged. Used to
    /// simulate the chip being busy while executing a command.
    I2cReadNack
    {
        /// 7-bit I2C slave address.
        addr: u8,
        /// Number of bytes the driver attempted to read.
        len: usize,
    },
    /// SDA held low for `duration_us` microseconds (wake pulse).
    PulseSdaLow
    {
        /// Pulse duration in microseconds.
        duration_us: u32,
    },
    /// Synchronous microsecond delay.
    DelayUs
    {
        /// Delay in microseconds.
        duration_us: u32,
    },
    /// Synchronous millisecond delay.
    DelayMs
    {
        /// Delay in milliseconds.
        duration_ms: u32,
    },
}

/// Error type for the mock HAL. The mock panics on mismatched expectations,
/// so this only exists to satisfy the `AteccHal::Error` associated type.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct MockHalError;

/// Scriptable mock that records each call and verifies it against a queue of
/// expectations.
#[derive(Debug, Default)]
pub(crate) struct MockHal
{
    expectations: VecDeque<MockOp>,
    read_data:    VecDeque<Vec<u8>>,
}

impl MockHal
{
    /// Create an empty mock.
    pub(crate) fn new() -> Self
    {
        Self::default()
    }

    /// Queue an expected I2C write.
    pub(crate) fn expect_i2c_write(&mut self, addr: u8, data: &[u8])
    {
        self.expectations.push_back(MockOp::I2cWrite
        {
            addr,
            data: data.to_vec(),
        });
    }

    /// Queue an expected I2C read together with the bytes the mock will
    /// return when that read is performed.
    pub(crate) fn expect_i2c_read(&mut self, addr: u8, response: &[u8])
    {
        self.expectations.push_back(MockOp::I2cRead
        {
            addr,
            len: response.len(),
        });
        self.read_data.push_back(response.to_vec());
    }

    /// Queue an expected I2C read that the mock will reject with an error
    /// (simulated NACK). Used to test the polling loop: while the chip is
    /// still executing a command it NACKs subsequent reads.
    pub(crate) fn expect_i2c_read_nack(&mut self, addr: u8, len: usize)
    {
        self.expectations.push_back(MockOp::I2cReadNack { addr, len });
    }

    /// Queue an expected SDA wake pulse.
    pub(crate) fn expect_pulse_sda_low(&mut self, duration_us: u32)
    {
        self.expectations.push_back(MockOp::PulseSdaLow { duration_us });
    }

    /// Queue an expected microsecond delay.
    pub(crate) fn expect_delay_us(&mut self, duration_us: u32)
    {
        self.expectations.push_back(MockOp::DelayUs { duration_us });
    }

    /// Queue an expected millisecond delay.
    pub(crate) fn expect_delay_ms(&mut self, duration_ms: u32)
    {
        self.expectations.push_back(MockOp::DelayMs { duration_ms });
    }

    /// Panic if any expectation remains unfulfilled.
    ///
    /// Call this at the end of each test.
    pub(crate) fn verify(&self)
    {
        assert!(
            self.expectations.is_empty(),
            "{} expectation(s) remain unfulfilled: {:?}",
            self.expectations.len(),
            self.expectations,
        );
    }

    fn pop_expectation(&mut self, actual: &MockOp) -> MockOp
    {
        let Some(expected) = self.expectations.pop_front()
        else
        {
            panic!("MockHal received unexpected call: {actual:?}");
        };
        expected
    }
}

impl AteccHal for MockHal
{
    type Error = MockHalError;

    async fn i2c_write(
        &mut self,
        device_addr: u8,
        data: &[u8],
    ) -> Result<(), Self::Error>
    {
        let actual = MockOp::I2cWrite
        {
            addr: device_addr,
            data: data.to_vec(),
        };
        let expected = self.pop_expectation(&actual);
        assert_eq!(actual, expected, "MockHal: i2c_write mismatch");
        Ok(())
    }

    async fn i2c_read(
        &mut self,
        device_addr: u8,
        buf: &mut [u8],
    ) -> Result<(), Self::Error>
    {
        // Peek the next expectation to decide between success and NACK.
        let expected = self
            .expectations
            .pop_front()
            .unwrap_or_else(||
            {
                panic!("MockHal: i2c_read with no expectation queued");
            });

        match expected
        {
            MockOp::I2cReadNack { addr, len } =>
            {
                assert_eq!(addr, device_addr, "MockHal: i2c_read_nack address mismatch");
                assert_eq!(len, buf.len(), "MockHal: i2c_read_nack length mismatch");
                Err(MockHalError)
            }
            MockOp::I2cRead { addr, len } =>
            {
                assert_eq!(addr, device_addr, "MockHal: i2c_read address mismatch");
                assert_eq!(len, buf.len(), "MockHal: i2c_read length mismatch");

                let canned = self
                    .read_data
                    .pop_front()
                    .expect("MockHal: i2c_read with no canned response queued");
                assert_eq!(
                    canned.len(),
                    buf.len(),
                    "MockHal: canned read length does not match buffer length",
                );
                buf.copy_from_slice(&canned);
                Ok(())
            }
            other =>
            {
                panic!(
                    "MockHal: expected {other:?} but driver called i2c_read({device_addr:#04x}, len={})",
                    buf.len(),
                );
            }
        }
    }

    async fn pulse_sda_low
    (
        &mut self,
        duration_us: u32,
    ) -> Result<(), Self::Error>
    {
        let actual = MockOp::PulseSdaLow { duration_us };
        let expected = self.pop_expectation(&actual);
        assert_eq!(actual, expected, "MockHal: pulse_sda_low mismatch");
        Ok(())
    }

    async fn delay_us(&mut self, duration_us: u32)
    {
        let actual = MockOp::DelayUs { duration_us };
        let expected = self.pop_expectation(&actual);
        assert_eq!(actual, expected, "MockHal: delay_us mismatch");
    }

    async fn delay_ms(&mut self, duration_ms: u32)
    {
        let actual = MockOp::DelayMs { duration_ms };
        let expected = self.pop_expectation(&actual);
        assert_eq!(actual, expected, "MockHal: delay_ms mismatch");
    }
}

/// Tiny async runner for integration tests. Polls a future to completion.
/// The mock never returns `Pending`, so a single poll cycle is enough in
/// practice, but the loop handles potential future runtime additions.
pub(crate) fn block_on<F: core::future::Future>(f: F) -> F::Output
{
    use core::pin::pin;
    use core::task::{Context, Poll};

    let mut f = pin!(f);
    let mut cx = Context::from_waker(core::task::Waker::noop());
    loop
    {
        if let Poll::Ready(output) = f.as_mut().poll(&mut cx)
        {
            return output;
        }
    }
}
