//! CRC-16 implementation used to compute the lock-confirmation hash of
//! the writable portion of the configuration zone.
//!
//! This is a deliberate duplicate of the same algorithm used in the
//! firmware (`crates/atecc608b/src/crc.rs`). The duplication keeps the
//! generator self-contained: it does not pull the embedded driver crate
//! and its no_std machinery into a host build. Both implementations are
//! tested against the same set of reference vectors taken from the
//! Microchip CryptoAuthLib C source.
//!
//! Parameters:
//! - Polynomial:    0x8005
//! - Initial value: 0x0000
//! - Reflect in:    false (MSB first)
//! - Reflect out:   false
//! - XOR out:       0x0000

/// Compute the CRC-16 over `data`.
#[must_use]
pub fn crc16(data: &[u8]) -> u16
{
    const POLY: u16 = 0x8005;
    let mut crc: u16 = 0x0000;
    for byte in data
    {
        for bit_index in 0..8u8
        {
            let data_bit = (byte >> bit_index) & 0x01;
            let crc_bit  = ((crc >> 15) & 0x0001) as u8;
            crc <<= 1;
            if data_bit != crc_bit
            {
                crc ^= POLY;
            }
        }
    }
    crc
}

#[cfg(test)]
mod tests
{
    use super::*;

    /// Reference vectors taken from `crates/atecc608b/src/crc.rs` tests.
    /// Both implementations must agree on these.

    #[test]
    fn empty_input_is_zero()
    {
        assert_eq!(crc16(&[]), 0x0000);
    }

    #[test]
    fn info_command_frame()
    {
        // Frame { count=0x07, opcode=Info=0x30, p1=0, p2=0,0 }
        let frame = [0x07, 0x30, 0x00, 0x00, 0x00];
        assert_eq!(crc16(&frame), 0x5D03);
    }

    #[test]
    fn random_command_frame()
    {
        let frame = [0x07, 0x1B, 0x00, 0x00, 0x00];
        assert_eq!(crc16(&frame), 0xCD24);
    }

    #[test]
    fn wake_response_prefix()
    {
        let prefix = [0x04, 0x11];
        assert_eq!(crc16(&prefix), 0x4333);
    }
}
