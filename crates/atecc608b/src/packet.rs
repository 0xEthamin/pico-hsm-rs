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

//! Encoding and decoding of ATECC608B command and response frames.
//!
//! # Command frame layout (sent host to chip)
//!
//! ```text
//! +---------+--------+---------+---------+-----------+---------+
//! |  Count  | Opcode | Param1  | Param2  |   Data... |  CRC16  |
//! |  (1 B)  | (1 B)  |  (1 B)  | (2 B,LE)|  (0..155) | (2 B,LE)|
//! +---------+--------+---------+---------+-----------+---------+
//!
//!  ^                                                  ^
//!  |                                                  |
//!  +-- Count includes itself, the CRC, and ---------- +
//!      everything in between.
//! ```
//!
//! The byte sent before this frame on I2C is the "word address"
//! [`crate::opcodes::WORD_ADDRESS_COMMAND`] (`0x03`). It is not part of the
//! frame proper and is not covered by the CRC.
//!
//! # Response frame layout (sent chip to host)
//!
//! ```text
//! +---------+----------------+---------+
//! |  Count  |    Payload     |  CRC16  |
//! |  (1 B)  |   (Count-3 B)  | (2 B,LE)|
//! +---------+----------------+---------+
//! ```
//!
//! When the chip reports an error, the response is exactly 4 bytes:
//! `04 <status> <crc_lo> <crc_hi>`. The 1-byte status is one of the values
//! mapped by [`crate::error::ChipError::from_status_byte`].

use crate::crc::{crc16, crc16_to_bytes, verify_trailing_crc};
use crate::opcodes::{COMMAND_FRAME_OVERHEAD, MAX_COMMAND_DATA_LEN};

/// Errors that can arise while parsing a response frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum PacketParseError
{
    /// The received slice is shorter than the minimum 4-byte response.
    TooShort,
    /// The count byte does not match the actual slice length.
    LengthMismatch
    {
        /// Value of the count byte advertised by the chip.
        declared: u8,
        /// Number of bytes actually present in the slice.
        actual:   usize,
    },
    /// The trailing CRC does not match a CRC computed over the rest of the
    /// frame.
    BadCrc,
}

/// Errors that can arise while serializing a command frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum PacketBuildError
{
    /// The provided data buffer would make the frame exceed
    /// [`crate::opcodes::MAX_PACKET_SIZE`].
    DataTooLong
    {
        /// Length the caller attempted to write.
        attempted: usize,
        /// Maximum length the protocol allows.
        max:       usize,
    },
    /// The output buffer cannot hold the resulting frame.
    OutputBufferTooSmall
    {
        /// Required output buffer size in bytes.
        required: usize,
        /// Size of the buffer the caller provided.
        provided: usize,
    },
}

/// Build a command frame into `out` and return the number of bytes written.
///
/// The frame is laid out exactly as the chip expects to receive it, starting
/// with the count byte. The caller is responsible for prepending the word
/// address byte at the I2C transmission layer.
///
/// # Arguments
/// - `opcode`: One of the `OP_*` constants from [`crate::opcodes`].
/// - `param1`: First single-byte parameter (command-specific meaning).
/// - `param2`: Two-byte parameter, written in little-endian.
/// - `data`  : Optional command-specific payload, up to
///   [`MAX_COMMAND_DATA_LEN`] bytes.
/// - `out`   : Buffer that receives the encoded frame. Must hold at least
///   `COMMAND_FRAME_OVERHEAD + data.len()` bytes.
///
/// # Errors
/// Returns [`PacketBuildError::DataTooLong`] if `data` exceeds the protocol
/// maximum, or [`PacketBuildError::OutputBufferTooSmall`] if `out` is too
/// small to hold the result.
pub fn build_command_frame(
    opcode: u8,
    param1: u8,
    param2: u16,
    data: &[u8],
    out: &mut [u8],
) -> Result<usize, PacketBuildError>
{
    if data.len() > MAX_COMMAND_DATA_LEN
    {
        return Err(PacketBuildError::DataTooLong
        {
            attempted: data.len(),
            max:       MAX_COMMAND_DATA_LEN,
        });
    }

    let total_len = COMMAND_FRAME_OVERHEAD + data.len();

    if out.len() < total_len
    {
        return Err(PacketBuildError::OutputBufferTooSmall
        {
            required: total_len,
            provided: out.len(),
        });
    }

    // The count byte counts itself and everything that follows including the
    // CRC. total_len already accounts for all of that.
    out[0] = u8::try_from(total_len).map_err(|_| PacketBuildError::DataTooLong 
    {
        attempted: data.len(),
        max:       MAX_COMMAND_DATA_LEN,
    })?;
    out[1] = opcode;
    out[2] = param1;
    let param2_bytes = param2.to_le_bytes();
    out[3] = param2_bytes[0];
    out[4] = param2_bytes[1];

    out[5..5 + data.len()].copy_from_slice(data);

    // CRC is computed over the entire frame except the two trailing CRC
    // bytes themselves.
    let crc = crc16(&out[..5 + data.len()]);
    let crc_bytes = crc16_to_bytes(crc);
    out[5 + data.len()] = crc_bytes[0];
    out[6 + data.len()] = crc_bytes[1];

    Ok(total_len)
}

/// A parsed and CRC-verified response frame.
///
/// Borrows from the receive buffer. The lifetime ties the parsed structure to
/// the buffer so the caller cannot reuse it while still reading the payload.
#[derive(Debug, PartialEq, Eq)]
pub enum ResponseFrame<'a>
{
    /// Standard payload response. The slice contains the bytes between the
    /// count byte and the CRC.
    Payload(&'a [u8]),
    /// 4-byte status response. The chip reports a one-byte status code that
    /// is non-zero. Callers should pass this byte to
    /// [`crate::error::ChipError::from_status_byte`].
    Status(u8),
}

/// Parse a response frame.
///
/// `frame` is the exact slice read from the chip, starting with the count
/// byte and ending with the two CRC bytes.
///
/// # Errors
/// Returns [`PacketParseError`] if the frame is too short, has an inconsistent
/// count byte, or fails CRC verification.
pub fn parse_response_frame(frame: &[u8]) -> Result<ResponseFrame<'_>, PacketParseError>
{
    // Minimum response is 4 bytes: count, status, crc_lo, crc_hi.
    if frame.len() < 4
    {
        return Err(PacketParseError::TooShort);
    }

    let declared = frame[0];

    if declared as usize != frame.len()
    {
        return Err(PacketParseError::LengthMismatch
        {
            declared,
            actual: frame.len(),
        });
    }

    if !verify_trailing_crc(frame)
    {
        return Err(PacketParseError::BadCrc);
    }

    // A 4-byte frame carries a single status byte rather than a payload.
    if frame.len() == 4
    {
        return Ok(ResponseFrame::Status(frame[1]));
    }

    // Payload is everything between the count byte and the two CRC bytes.
    Ok(ResponseFrame::Payload(&frame[1..frame.len() - 2]))
}

#[cfg(test)]
mod tests
{
    use super::*;
    use crate::opcodes::{OP_INFO, OP_RANDOM};

    /// Verify that an Info command with no data is serialized to the exact
    /// reference bytes seen on the wire. The reference CRC bytes (`0x03,
    /// 0x5D`) come from the unit tests of the CRC module.
    #[test]
    fn build_info_command()
    {
        let mut buf = [0u8; 32];
        let written = build_command_frame(OP_INFO, 0x00, 0x0000, &[], &mut buf).unwrap();

        assert_eq!(written, 7);
        assert_eq!(
            &buf[..7],
            &[0x07, 0x30, 0x00, 0x00, 0x00, 0x03, 0x5D],
        );
    }

    /// Random command frame, similar shape as Info but a different opcode.
    #[test]
    fn build_random_command()
    {
        let mut buf = [0u8; 32];
        let written = build_command_frame(OP_RANDOM, 0x00, 0x0000, &[], &mut buf).unwrap();

        assert_eq!(written, 7);
        assert_eq!(buf[0], 0x07);
        assert_eq!(buf[1], OP_RANDOM);
        // CRC bytes were computed independently in the crc tests as 0xCD24.
        assert_eq!(buf[5], 0x24);
        assert_eq!(buf[6], 0xCD);
    }

    #[test]
    fn build_with_data_payload()
    {
        let mut buf = [0u8; 32];
        let data: [u8; 4] = [0xDE, 0xAD, 0xBE, 0xEF];
        let written = build_command_frame(OP_INFO, 0xAA, 0x1234, &data, &mut buf).unwrap();

        // 7 overhead + 4 data = 11
        assert_eq!(written, 11);
        assert_eq!(buf[0], 11);
        assert_eq!(buf[1], OP_INFO);
        assert_eq!(buf[2], 0xAA);
        // Param2 little-endian.
        assert_eq!(buf[3], 0x34);
        assert_eq!(buf[4], 0x12);
        // Data block.
        assert_eq!(&buf[5..9], &data);
        // CRC is verifiable.
        assert!(verify_trailing_crc(&buf[..11]));
    }

    #[test]
    fn build_rejects_oversized_data()
    {
        let mut buf = [0u8; 256];
        let huge = [0xFFu8; MAX_COMMAND_DATA_LEN + 1];
        let err = build_command_frame(OP_INFO, 0, 0, &huge, &mut buf).unwrap_err();
        assert_eq!(
            err,
            PacketBuildError::DataTooLong
            {
                attempted: MAX_COMMAND_DATA_LEN + 1,
                max:       MAX_COMMAND_DATA_LEN,
            },
        );
    }

    #[test]
    fn build_rejects_small_output_buffer()
    {
        let mut buf = [0u8; 5];
        let err = build_command_frame(OP_INFO, 0, 0, &[], &mut buf).unwrap_err();
        assert_eq!(
            err,
            PacketBuildError::OutputBufferTooSmall
            {
                required: 7,
                provided: 5,
            },
        );
    }

    /// Round-trip: build a frame, then verify its CRC parses correctly.
    #[test]
    fn build_then_parse_payload()
    {
        // Build a frame that simulates a chip response.
        // We use build_command_frame as a CRC-generating helper here, even
        // though responses do not have opcode/param1/param2 fields. The CRC
        // mechanism is identical.
        let mut buf = [0u8; 32];
        let count = 5u8; // 1 count + 2 payload + 2 crc
        buf[0] = count;
        buf[1] = 0x12;
        buf[2] = 0x34;
        let crc = crc16(&buf[..3]);
        let crc_bytes = crc16_to_bytes(crc);
        buf[3] = crc_bytes[0];
        buf[4] = crc_bytes[1];

        let parsed = parse_response_frame(&buf[..5]).unwrap();
        match parsed
        {
            ResponseFrame::Payload(p) => assert_eq!(p, &[0x12, 0x34]),
            ResponseFrame::Status(_) => panic!("expected payload, got status"),
        }
    }

    /// 4-byte status response, ie `04 <status> <crc_lo> <crc_hi>`.
    #[test]
    fn parse_status_response()
    {
        let mut buf = [0u8; 4];
        buf[0] = 0x04;
        buf[1] = 0x03; // ParseError chip code
        let crc = crc16(&buf[..2]);
        let crc_bytes = crc16_to_bytes(crc);
        buf[2] = crc_bytes[0];
        buf[3] = crc_bytes[1];

        let parsed = parse_response_frame(&buf).unwrap();
        match parsed
        {
            ResponseFrame::Status(s) => assert_eq!(s, 0x03),
            ResponseFrame::Payload(_) => panic!("expected status, got payload"),
        }
    }

    /// The known wake response `04 11 33 43` parses as a `Status(0x11)`.
    /// Note that 0x11 is the wake "success" sentinel.
    #[test]
    fn parse_wake_response()
    {
        let wake = [0x04, 0x11, 0x33, 0x43];
        let parsed = parse_response_frame(&wake).unwrap();
        assert_eq!(parsed, ResponseFrame::Status(0x11));
    }

    #[test]
    fn parse_rejects_too_short()
    {
        assert_eq!(
            parse_response_frame(&[0x04, 0x11, 0x33]).unwrap_err(),
            PacketParseError::TooShort,
        );
    }

    #[test]
    fn parse_rejects_length_mismatch()
    {
        // Count says 6 but we only give 4 bytes.
        let bad = [0x06, 0x11, 0x33, 0x43];
        let err = parse_response_frame(&bad).unwrap_err();
        assert_eq!(
            err,
            PacketParseError::LengthMismatch
            {
                declared: 6,
                actual:   4,
            },
        );
    }

    #[test]
    fn parse_rejects_bad_crc()
    {
        // Length matches but CRC is wrong.
        let bad = [0x04, 0x11, 0xFF, 0xFF];
        assert_eq!(
            parse_response_frame(&bad).unwrap_err(),
            PacketParseError::BadCrc,
        );
    }
}
