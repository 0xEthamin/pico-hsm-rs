//! In-memory mock implementation of [`atecc608b::hal::AteccHal`] for host-side
//! unit tests.
//!
//! The mock records every operation in a `Vec<MockOp>` and matches it against
//! a script of expected operations declared by the test. Reads are fulfilled
//! from a queue of canned responses.
//!
//! Usage pattern:
//!
//! ```ignore
//! let mut hal = MockHal::new();
//! hal.expect_pulse_sda_low(60);
//! hal.expect_delay_us(1500);
//! hal.expect_i2c_read(0x60, &[0x04, 0x11, 0x33, 0x43]);
//! // … run the driver against `hal` …
//! hal.verify();
//! ```

#![allow(dead_code)]

use core::cell::RefCell;

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum MockOp
{
    I2cWrite { addr: u8, data: Vec<u8> },
    I2cRead  { addr: u8, expected_len: usize },
    PulseSdaLow { duration_us: u32 },
    DelayUs { duration_us: u32 },
    DelayMs { duration_ms: u32 },
}

#[derive(Debug)]
pub struct MockHal
{
    expectations: RefCell<Vec<MockOp>>,
    read_data:    RefCell<Vec<Vec<u8>>>,
    cursor:       RefCell<usize>,
}

impl MockHal
{
    pub fn new() -> Self
    {
        Self
        {
            expectations: RefCell::new(Vec::new()),
            read_data:    RefCell::new(Vec::new()),
            cursor:       RefCell::new(0),
        }
    }

    pub fn expect_i2c_write(&self, addr: u8, data: &[u8])
    {
        self.expectations.borrow_mut().push(MockOp::I2cWrite { addr, data: data.to_vec() });
    }

    pub fn expect_i2c_read(&self, addr: u8, response: &[u8])
    {
        self.expectations.borrow_mut().push(MockOp::I2cRead { addr, expected_len: response.len() });
        self.read_data.borrow_mut().push(response.to_vec());
    }

    pub fn expect_pulse_sda_low(&self, duration_us: u32)
    {
        self.expectations.borrow_mut().push(MockOp::PulseSdaLow { duration_us });
    }

    pub fn expect_delay_us(&self, duration_us: u32)
    {
        self.expectations.borrow_mut().push(MockOp::DelayUs { duration_us });
    }

    pub fn expect_delay_ms(&self, duration_ms: u32)
    {
        self.expectations.borrow_mut().push(MockOp::DelayMs { duration_ms });
    }

    pub fn verify(&self)
    {
        let expectations = self.expectations.borrow();
        let cursor = *self.cursor.borrow();
        assert_eq!(
            cursor,
            expectations.len(),
            "MockHal: {} expectations remain unfulfilled",
            expectations.len() - cursor,
        );
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct MockHalError;
