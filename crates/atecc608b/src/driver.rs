//! Top-level driver handle.
//!
//! [`Atecc`] owns the HAL and exposes the high-level command API. Every
//! command in [`crate::command`] is implemented as a method on this struct via
//! `impl` blocks split per file.
//!
//! The fields stay private on purpose: callers go through methods only, which
//! ensures the wake -> command -> idle lifecycle is respected.

use crate::hal::AteccHal;
use crate::opcodes::I2C_ADDRESS;

/// Driver handle owning the HAL and tracking the chip's awake/sleep state.
pub struct Atecc<H>
where
    H: AteccHal,
{
    pub(crate) hal:           H,
    pub(crate) device_addr:   u8,
    pub(crate) is_awake:      bool,
}

impl<H> Atecc<H>
where
    H: AteccHal,
{
    /// Build a new driver around an existing HAL, using the chip's default
    /// I2C address ([`crate::opcodes::I2C_ADDRESS`]).
    pub fn new(hal: H) -> Self
    {
        Self
        {
            hal,
            device_addr: I2C_ADDRESS,
            is_awake:    false,
        }
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
}
