//! Wake / idle / sleep sequence handling.
//!
//! The ATECC608B spends most of its life in deep sleep (< 150 nA). To talk to
//! it the driver must first perform the wake sequence:
//!
//! 1. Pull SDA low for at least [`crate::opcodes::WAKE_LOW_DURATION_US`]
//!    microseconds.
//! 2. Release SDA and wait
//!    [`crate::opcodes::WAKE_DELAY_US`] microseconds.
//! 3. Read 4 bytes back over I2C. The chip is ready when these match
//!    [`crate::opcodes::WAKE_RESPONSE_OK`].
//!
//! After the response is consumed, the chip's watchdog starts counting down
//! from ~1.3 s. The driver puts the chip back to idle or sleep between
//! command sequences to avoid hitting the watchdog unexpectedly.
