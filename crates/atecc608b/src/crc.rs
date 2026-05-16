//! CRC-16/DNP as used by the ATECC608B protocol.
//!
//! The chip uses the polynomial `0x8005`, initial value `0x0000`,
//! MSB-first bit order, with little-endian output on the wire (low byte first
//! in the packet, high byte second).

/// Compute the CRC-16/DNP over `data`.
#[must_use]
pub fn crc16(_data: &[u8]) -> u16
{
    unimplemented!("CRC-16 to be implemented")
}
