//! CRC-16 as used by the ATECC608B protocol.
//!
//! Parameters of the algorithm (Microchip uses the name "CRC-16/DNP" loosely.
//! The chip's variant matches none of the standard catalog entries exactly,
//! the parameters below are the source of truth):
//!
//! - Polynomial    : `0x8005`
//! - Initial value : `0x0000`
//! - Reflect input : false (MSB first)
//! - Reflect output: false
//! - XOR output    : `0x0000`
//! - Byte order    : low byte first when serialized on the wire
//!
//! The implementation is a faithful translation of the bit-by-bit routine in
//! `lib/calib/calib_command.c` of Microchip's CryptoAuthLib. We deliberately
//! avoid a table-driven approach. The driver only computes a CRC over short
//! packets at human time scales (microseconds), so the gain would be
//! negligible while flash usage would grow.

/// Compute the CRC-16 over `data`.
///
/// Returns the CRC as a `u16` in native byte order. To write it into a
/// packet, use [`crc16_to_bytes`] which lays it out low byte first as the
/// protocol expects.
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
            let crc_bit = ((crc >> 15) & 0x0001) as u8;

            crc <<= 1;

            if data_bit != crc_bit
            {
                crc ^= POLY;
            }
        }
    }

    crc
}

/// Serialize a CRC into the two-byte little-endian form expected on the wire.
///
/// The chip transmits and expects the low byte first, then the high byte.
#[must_use]
pub fn crc16_to_bytes(crc: u16) -> [u8; 2]
{
    [(crc & 0xFF) as u8, ((crc >> 8) & 0xFF) as u8]
}

/// Verify the trailing two bytes of `frame` against a freshly computed CRC of
/// everything before them.
///
/// Returns `true` if the CRC matches. Returns `false` if `frame` has fewer
/// than 3 bytes (no room for at least one payload byte plus 2 CRC bytes).
#[must_use]
pub fn verify_trailing_crc(frame: &[u8]) -> bool
{
    if frame.len() < 3
    {
        return false;
    }

    let split = frame.len() - 2;
    let computed = crc16(&frame[..split]);
    let received = u16::from_le_bytes([frame[split], frame[split + 1]]);

    computed == received
}

#[cfg(test)]
mod tests
{
    use super::*;

    /// An Info command frame, without word address and without the trailing
    /// CRC. Length byte is 7 (count includes itself and the CRC). Opcode is
    /// 0x30, param1=0, param2=0x0000.
    ///
    /// The reference CRC for this exact frame, cross-checked against the C
    /// implementation in CryptoAuthLib by running it on the same bytes, is
    /// 0x5D03. On the wire it is serialized as `0x03 0x5D`.
    const INFO_FRAME_NO_CRC: [u8; 5] = [0x07, 0x30, 0x00, 0x00, 0x00];
    const INFO_FRAME_CRC: u16 = 0x5D03;

    /// A Random command frame (opcode 0x1B), same shape, returns 32 random
    /// bytes. Reference CRC computed the same way.
    const RANDOM_FRAME_NO_CRC: [u8; 5] = [0x07, 0x1B, 0x00, 0x00, 0x00];
    const RANDOM_FRAME_CRC: u16 = 0xCD24;

    /// The 4-byte chip wake response `04 11 33 43`. The two trailing bytes
    /// `33 43` are the CRC of `04 11` on the wire (low byte first), which
    /// means the raw CRC value of `[0x04, 0x11]` is `0x4333`.
    const WAKE_RESPONSE_PREFIX: [u8; 2] = [0x04, 0x11];
    const WAKE_RESPONSE_CRC: u16 = 0x4333;

    #[test]
    fn empty_input_yields_zero()
    {
        assert_eq!(crc16(&[]), 0x0000);
    }

    #[test]
    fn single_zero_byte()
    {
        assert_eq!(crc16(&[0x00]), 0x0000);
    }

    #[test]
    fn info_command_frame()
    {
        assert_eq!(crc16(&INFO_FRAME_NO_CRC), INFO_FRAME_CRC);
    }

    #[test]
    fn random_command_frame()
    {
        assert_eq!(crc16(&RANDOM_FRAME_NO_CRC), RANDOM_FRAME_CRC);
    }

    #[test]
    fn wake_response_crc()
    {
        assert_eq!(crc16(&WAKE_RESPONSE_PREFIX), WAKE_RESPONSE_CRC);
    }

    #[test]
    fn crc_to_bytes_is_little_endian()
    {
        assert_eq!(crc16_to_bytes(0x5D03), [0x03, 0x5D]);
        assert_eq!(crc16_to_bytes(0x0000), [0x00, 0x00]);
        assert_eq!(crc16_to_bytes(0xFFFF), [0xFF, 0xFF]);
    }

    #[test]
    fn verify_accepts_valid_info_frame()
    {
        // Append CRC bytes to the Info frame and check.
        let mut full = [0u8; 7];
        full[..5].copy_from_slice(&INFO_FRAME_NO_CRC);
        full[5..].copy_from_slice(&crc16_to_bytes(INFO_FRAME_CRC));
        assert!(verify_trailing_crc(&full));
    }

    #[test]
    fn verify_rejects_corrupted_frame()
    {
        let mut full = [0u8; 7];
        full[..5].copy_from_slice(&INFO_FRAME_NO_CRC);
        full[5..].copy_from_slice(&crc16_to_bytes(INFO_FRAME_CRC));
        // Flip a bit in the payload, CRC should no longer match.
        full[1] ^= 0x01;
        assert!(!verify_trailing_crc(&full));
    }

    #[test]
    fn verify_rejects_too_short_frame()
    {
        assert!(!verify_trailing_crc(&[]));
        assert!(!verify_trailing_crc(&[0xAB]));
        assert!(!verify_trailing_crc(&[0xAB, 0xCD]));
    }

    #[test]
    fn crc_is_deterministic()
    {
        // Same input must always yield the same output.
        let bytes = [0xDE, 0xAD, 0xBE, 0xEF];
        let a = crc16(&bytes);
        let b = crc16(&bytes);
        let c = crc16(&bytes);
        assert_eq!(a, b);
        assert_eq!(b, c);
    }
}
