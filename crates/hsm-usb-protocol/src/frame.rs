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

//! Byte-level encoding and decoding of HID frames.
//!
//! [`Frame`] is opcode-agnostic: it holds a `u8` opcode and a payload slice.
//! Higher-level interpretation of the payload is the caller's job
//! (firmware-side or host-side).

use crate::{HEADER_SIZE, HID_REPORT_SIZE, MAX_PAYLOAD_SIZE};

/// One parsed HID frame.
///
/// Holds a borrow into the underlying buffer. Lifetimes are tied to
/// the buffer that was parsed, so a `Frame` is cheap to pass around without
/// copies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Frame<'a>
{
    /// First byte of the report: a `CommandOpcode` from the host or a
    /// `ResponseStatus` from the token, depending on direction.
    pub opcode: u8,

    /// Payload bytes (`len` bytes from the parsed report).
    pub payload: &'a [u8],
}

/// Errors returned when parsing a HID report.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum FrameParseError
{
    /// The buffer is not exactly [`HID_REPORT_SIZE`] bytes.
    WrongReportSize
    {
        /// Actual buffer size.
        actual: usize
    },

    /// The declared `len` exceeds [`MAX_PAYLOAD_SIZE`].
    PayloadLenTooLarge
    {
        /// Declared payload size in the header.
        declared: usize
    },
}

impl<'a> Frame<'a>
{
    /// Parse a HID report into a [`Frame`].
    ///
    /// Returns a frame borrowing into `buf`. The payload slice has the
    /// length declared in the header (`len`), not the report size. Padding
    /// bytes after the payload are not validated: they are ignored
    /// according to the protocol contract.
    ///
    /// # Errors
    /// See [`FrameParseError`].
    pub fn parse(buf: &'a [u8]) -> Result<Self, FrameParseError>
    {
        if buf.len() != HID_REPORT_SIZE
        {
            return Err(FrameParseError::WrongReportSize { actual: buf.len() });
        }

        let opcode = buf[0];
        let len = u16::from_le_bytes([buf[1], buf[2]]) as usize;

        if len > MAX_PAYLOAD_SIZE
        {
            return Err(FrameParseError::PayloadLenTooLarge { declared: len });
        }

        Ok(Self
        {
            opcode,
            payload: &buf[HEADER_SIZE..HEADER_SIZE + len],
        })
    }

    /// Build a HID report from an opcode and a payload.
    ///
    /// Writes into `out` (must be exactly [`HID_REPORT_SIZE`] long). All
    /// bytes past the payload are zeroed.
    ///
    /// # Errors
    /// Returns [`FrameBuildError::WrongOutputSize`] if `out` is not
    /// [`HID_REPORT_SIZE`] bytes, or
    /// [`FrameBuildError::PayloadTooLarge`] if `payload.len()` exceeds
    /// [`MAX_PAYLOAD_SIZE`].
    pub fn write
    (
        opcode: u8,
        payload: &[u8],
        out: &mut [u8],
    ) -> Result<(), FrameBuildError>
    {
        if out.len() != HID_REPORT_SIZE
        {
            return Err(FrameBuildError::WrongOutputSize { actual: out.len() });
        }
        if payload.len() > MAX_PAYLOAD_SIZE
        {
            return Err(FrameBuildError::PayloadTooLarge { len: payload.len() });
        }

        // Zero the whole buffer first so the padding bytes are explicitly
        // zero (the protocol requires it for the wire, even if receivers
        // are supposed to ignore them).
        for byte in out.iter_mut()
        {
            *byte = 0;
        }

        out[0] = opcode;
        // The length should fits in u16: payload.len() <= MAX_PAYLOAD_SIZE < 256.
        let len = u16::try_from(payload.len())
            .map_err(|_| FrameBuildError::PayloadTooLarge {len: payload.len()})?;
        let [lo, hi] = len.to_le_bytes();
        out[1] = lo;
        out[2] = hi;
        out[HEADER_SIZE..HEADER_SIZE + payload.len()].copy_from_slice(payload);
        Ok(())
    }

    /// Convenience wrapper around [`Frame::write`] that returns the report
    /// by value on the stack. Useful for callers that just want a buffer
    /// to hand to `embassy-usb` or to the OS HID layer.
    ///
    /// # Errors
    /// See [`Frame::write`].
    pub fn to_report(opcode: u8, payload: &[u8]) -> Result<[u8; HID_REPORT_SIZE], FrameBuildError>
    {
        let mut report = [0u8; HID_REPORT_SIZE];
        Self::write(opcode, payload, &mut report)?;
        Ok(report)
    }
}

/// Errors returned when building a HID report.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum FrameBuildError
{
    /// `out` was not exactly [`HID_REPORT_SIZE`] bytes long.
    WrongOutputSize
    {
        /// Actual size of the provided output buffer.
        actual: usize
    },

    /// `payload.len()` exceeds [`MAX_PAYLOAD_SIZE`].
    PayloadTooLarge
    {
        /// The would-be payload size.
        len: usize
    },
}

#[cfg(test)]
mod tests
{
    use super::*;

    #[test]
    fn write_then_parse_round_trip_with_empty_payload()
    {
        let report = Frame::to_report(0x01, &[]).unwrap();
        let frame = Frame::parse(&report).unwrap();
        assert_eq!(frame.opcode, 0x01);
        assert_eq!(frame.payload.len(), 0);
    }

    #[test]
    fn write_then_parse_round_trip_with_typical_payload()
    {
        let payload = [0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE];
        let report = Frame::to_report(0x03, &payload).unwrap();
        let frame = Frame::parse(&report).unwrap();
        assert_eq!(frame.opcode, 0x03);
        assert_eq!(frame.payload, &payload);
    }

    #[test]
    fn write_pads_with_zeros()
    {
        let report = Frame::to_report(0xAA, &[0x11, 0x22, 0x33]).unwrap();
        assert_eq!(report[0], 0xAA);
        assert_eq!(report[1], 3); // len_lo
        assert_eq!(report[2], 0); // len_hi
        assert_eq!(&report[3..6], &[0x11, 0x22, 0x33]);
        assert!(report[6..].iter().all(|b| *b == 0));
    }

    #[test]
    fn write_at_max_payload_succeeds()
    {
        let payload = [0x42u8; MAX_PAYLOAD_SIZE];
        let report = Frame::to_report(0x10, &payload).unwrap();
        let frame = Frame::parse(&report).unwrap();
        assert_eq!(frame.payload.len(), MAX_PAYLOAD_SIZE);
        assert_eq!(frame.payload, &payload);
    }

    #[test]
    fn write_rejects_oversized_payload()
    {
        let oversized = [0u8; MAX_PAYLOAD_SIZE + 1];
        let mut out = [0u8; HID_REPORT_SIZE];
        let err = Frame::write(0x00, &oversized, &mut out).unwrap_err();
        assert_eq!(err, FrameBuildError::PayloadTooLarge { len: MAX_PAYLOAD_SIZE + 1 });
    }

    #[test]
    fn write_rejects_wrong_output_size()
    {
        let mut out = [0u8; 63];
        let err = Frame::write(0x00, &[], &mut out).unwrap_err();
        assert_eq!(err, FrameBuildError::WrongOutputSize { actual: 63 });
    }

    #[test]
    fn parse_rejects_wrong_report_size()
    {
        let short = [0u8; 32];
        let err = Frame::parse(&short).unwrap_err();
        assert_eq!(err, FrameParseError::WrongReportSize { actual: 32 });
    }

    #[test]
    fn parse_rejects_oversized_payload_len()
    {
        let mut report = [0u8; HID_REPORT_SIZE];
        report[0] = 0x42;
        // Claim a payload of MAX_PAYLOAD_SIZE + 1 bytes. The value fits in u16
        // by construction (MAX_PAYLOAD_SIZE < 256), so the try_from is infallible
        // and we unwrap in the test.
        let oversized = u16::try_from(MAX_PAYLOAD_SIZE + 1).unwrap();
        let [lo, hi] = oversized.to_le_bytes();
        report[1] = lo;
        report[2] = hi;
        let err = Frame::parse(&report).unwrap_err();
        assert_eq!(
            err,
            FrameParseError::PayloadLenTooLarge { declared: MAX_PAYLOAD_SIZE + 1 }
        );
    }

    #[test]
    fn parse_ignores_padding_bytes()
    {
        let mut report = [0u8; HID_REPORT_SIZE];
        report[0] = 0x01;
        report[1] = 2;
        report[2] = 0;
        report[3] = 0xAB;
        report[4] = 0xCD;
        // Pollute padding bytes.
        for byte in report.iter_mut().skip(5)
        {
            *byte = 0xFF;
        }
        let frame = Frame::parse(&report).unwrap();
        assert_eq!(frame.opcode, 0x01);
        assert_eq!(frame.payload, &[0xAB, 0xCD]);
    }

    #[test]
    fn len_uses_little_endian_encoding()
    {
        // Encode a payload of 256 bytes worth. If MAX_PAYLOAD_SIZE were
        // larger it would fit, but here we just verify the byte order in
        // the header. We can't actually create such a payload, so we go
        // the other way: hand-craft a report with len = 0x0102 (258) which
        // is over MAX, and verify that the parser sees it correctly when
        // it complains.
        let mut report = [0u8; HID_REPORT_SIZE];
        report[0] = 0x00;
        report[1] = 0x02; // lo
        report[2] = 0x01; // hi -> declared = 0x0102 = 258
        let err = Frame::parse(&report).unwrap_err();
        assert_eq!(err, FrameParseError::PayloadLenTooLarge { declared: 258 });
    }
}