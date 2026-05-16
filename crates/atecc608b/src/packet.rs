//! Encoding and decoding of the ATECC608B command and response frames.
//!
//! # Command frame layout
//!
//! ```text
//! -------------------------------------------------------------------
//! |  Count  | Opcode  | Param1  |      Param2     | Data… |  CRC16  |
//! |  (1 B)  |  (1 B)  |  (1 B)  |   (2 B, LE)     |       |  (2 B,  |
//! |         |         |         |                 |       |  LE)    |
//! -------------------------------------------------------------------
//!  ^                                                       ^
//!  -- Count includes itself, the CRC, and everything in between.
//! ```
//!
//! Module bodies will be filled in during milestone M1.

/// In-memory representation of a command packet ready to be sent.
#[derive(Debug)]
pub struct CommandPacket
{
    /// Opcode (`OP_*` constants in [`crate::opcodes`]).
    pub opcode:  u8,
    /// First single-byte parameter.
    pub param1:  u8,
    /// Second two-byte parameter (little-endian on the wire).
    pub param2:  u16,
    /// Optional command-specific data block.
    pub data:    heapless::Vec<u8, { crate::opcodes::MAX_PACKET_SIZE - 8 }>,
}

/// Result of parsing a chip response: either a payload or a chip-side error
/// status byte.
#[derive(Debug)]
pub enum ResponseFrame<'a>
{
    /// Successful response. The payload excludes the count byte and the CRC.
    Payload(&'a [u8]),
    /// 4-byte response frame whose payload byte indicates a chip error.
    Status(u8),
}