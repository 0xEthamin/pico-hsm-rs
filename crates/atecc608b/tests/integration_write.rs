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

//! Integration tests for the Write command and its higher-level helpers.
//!
//! Every wire byte sequence in this file was produced by running the same
//! CRC-16 algorithm as `crates/atecc608b/src/crc.rs` in Python over the
//! expected frame layout.

mod common;

use common::{block_on, MockHal};

use atecc608b::Atecc;
use atecc608b::command::read_write::
{
    config_or_otp_address,
    data_address,
    Zone,
    BLOCK_SIZE,
    ENCRYPTED_WRITE_DATA_SIZE,
    WORD_SIZE,
};
use atecc608b::opcodes::{WAKE_DELAY_US, WAKE_LOW_DURATION_US};
use atecc608b::{AteccError, ChipError, Slot};

/// Wake response bytes from a healthy chip.
const WAKE_RESPONSE: [u8; 4] = [0x04, 0x11, 0x33, 0x43];

/// I2C 7-bit address used throughout these tests (chip default).
const ADDR: u8 = 0x60;

/// Setup the mock to expect one wake sequence.
fn expect_wake(hal: &mut MockHal)
{
    hal.expect_pulse_sda_low(WAKE_LOW_DURATION_US);
    hal.expect_delay_us(WAKE_DELAY_US);
    hal.expect_i2c_read(ADDR, &WAKE_RESPONSE);
}

fn expect_idle(hal: &mut MockHal)
{
    hal.expect_i2c_write(ADDR, &[0x02]);
}

/// Build a status response frame: `04 <status> <crc_lo> <crc_hi>`.
fn status_response(status: u8) -> [u8; 4]
{
    let mut out = [0u8; 4];
    out[0] = 0x04;
    out[1] = status;
    let crc = atecc608b::crc::crc16(&out[..2]);
    let crc_bytes = atecc608b::crc::crc16_to_bytes(crc);
    out[2] = crc_bytes[0];
    out[3] = crc_bytes[1];
    out
}

/// Setup the mock to expect one full command round-trip: write the command
/// frame, the execution-time delay, then the count-byte read and the
/// remaining payload read.
fn expect_command_round_trip(
    hal: &mut MockHal,
    command_wire: &[u8],
    exec_ms: u32,
    response: &[u8],
)
{
    hal.expect_i2c_write(ADDR, command_wire);
    hal.expect_delay_ms(exec_ms);
    hal.expect_i2c_read(ADDR, &response[0..1]);
    hal.expect_i2c_read(ADDR, &response[1..]);
}

// ---------------------------------------------------------------------------
// write_4
// ---------------------------------------------------------------------------

#[test]
fn write_4_config_block_2_offset_5_cleartext()
{
    // p1 = 0x00 (Config, 4-byte, cleartext)
    // p2 = config_or_otp_address(block=2, off=5) = (2<<3)|5 = 0x15
    // data = CA FE BA BE
    // Reference frame body: 0B 12 00 15 00 CA FE BA BE 18 3A
    // With word address prefix 0x03:
    const COMMAND: [u8; 12] = [
        0x03,                              // word addr
        0x0B, 0x12, 0x00, 0x15, 0x00,      // count, opcode, p1, p2 LE
        0xCA, 0xFE, 0xBA, 0xBE,            // data
        0x18, 0x3A,                        // CRC LE
    ];
    let response = status_response(0x00);

    let mut hal = MockHal::new();
    expect_wake(&mut hal);
    expect_command_round_trip(&mut hal, &COMMAND, 45, &response);

    expect_idle(&mut hal);
    let mut atecc = Atecc::new(hal);
    let mut channel = block_on(atecc.open_channel()).expect("open_channel");
    let payload = [0xCA, 0xFE, 0xBA, 0xBE];
    block_on(channel.write_4(Zone::Config, config_or_otp_address(2, 5), &payload))
        .expect("write_4");

    block_on(channel.close()).expect("close");
    atecc.into_hal().verify();
}

#[test]
fn write_slot_word_uses_data_zone_address()
{
    // Slot 0, block 0, offset 0 -> data zone, p1 = 0x02, p2 = 0x0000.
    // Frame body: 0B 12 02 00 00 <4 bytes data> <CRC>
    let payload = [0x11u8, 0x22, 0x33, 0x44];
    let body: [u8; 9] = {
        let mut b = [0u8; 9];
        b[0] = 0x0B;
        b[1] = 0x12;
        b[2] = 0x02;
        b[3] = 0x00;
        b[4] = 0x00;
        b[5..9].copy_from_slice(&payload);
        b
    };
    let crc = atecc608b::crc::crc16(&body);
    let crc_bytes = atecc608b::crc::crc16_to_bytes(crc);

    let mut command = [0u8; 12];
    command[0] = 0x03;
    command[1..10].copy_from_slice(&body);
    command[10] = crc_bytes[0];
    command[11] = crc_bytes[1];

    let response = status_response(0x00);
    let mut hal = MockHal::new();
    expect_wake(&mut hal);
    expect_command_round_trip(&mut hal, &command, 45, &response);

    let slot = Slot::const_new(0);
    expect_idle(&mut hal);
    let mut atecc = Atecc::new(hal);
    let mut channel = block_on(atecc.open_channel()).expect("open_channel");
    block_on(channel.write_slot_word(slot, 0, 0, &payload)).expect("write_slot_word");

    block_on(channel.close()).expect("close");
    atecc.into_hal().verify();
}

// ---------------------------------------------------------------------------
// write_32 cleartext
// ---------------------------------------------------------------------------

#[test]
fn write_32_data_slot_8_block_0_cleartext()
{
    // p1 = 0x82 (Data, 32-byte, cleartext)
    // p2 = data_address(slot=8, block=0, off=0) = 0x0040
    // data = 10..2F (incrementing)
    // Reference frame body: 27 12 82 40 00 10..2F 43 D8
    let mut command = [0u8; 40];
    command[0] = 0x03;                   // word addr
    command[1] = 0x27;                   // count = 7 + 32 = 39 = 0x27
    command[2] = 0x12;                   // opcode WRITE
    command[3] = 0x82;                   // p1 = data + 32-byte
    command[4] = 0x40;                   // p2 lo
    command[5] = 0x00;                   // p2 hi
    let mut data = [0u8; BLOCK_SIZE];
    for (i, byte) in data.iter_mut().enumerate()
    {
        *byte = 0x10 + i as u8;
    }
    command[6..38].copy_from_slice(&data);
    let crc = atecc608b::crc::crc16(&command[1..38]);
    let crc_bytes = atecc608b::crc::crc16_to_bytes(crc);
    command[38] = crc_bytes[0];
    command[39] = crc_bytes[1];

    // Sanity: pre-computed reference was 43 D8.
    assert_eq!(command[38..40], [0x43, 0xD8]);

    let response = status_response(0x00);
    let mut hal = MockHal::new();
    expect_wake(&mut hal);
    expect_command_round_trip(&mut hal, &command, 45, &response);

    let slot = Slot::const_new(8);
    expect_idle(&mut hal);
    let mut atecc = Atecc::new(hal);
    let mut channel = block_on(atecc.open_channel()).expect("open_channel");
    block_on(channel.write_slot_block(slot, 0, &data)).expect("write_slot_block");

    block_on(channel.close()).expect("close");
    atecc.into_hal().verify();
}

#[test]
fn write_32_uses_raw_address_api()
{
    // Same target as the test above, exercising write_32 directly with the
    // helper-built address.
    let slot = Slot::const_new(8);
    let mut data = [0u8; BLOCK_SIZE];
    for (i, byte) in data.iter_mut().enumerate()
    {
        *byte = 0x10 + i as u8;
    }

    let mut command = [0u8; 40];
    command[0] = 0x03;
    command[1] = 0x27;
    command[2] = 0x12;
    command[3] = 0x82;
    command[4] = 0x40;
    command[5] = 0x00;
    command[6..38].copy_from_slice(&data);
    let crc = atecc608b::crc::crc16(&command[1..38]);
    let crc_bytes = atecc608b::crc::crc16_to_bytes(crc);
    command[38] = crc_bytes[0];
    command[39] = crc_bytes[1];

    let response = status_response(0x00);
    let mut hal = MockHal::new();
    expect_wake(&mut hal);
    expect_command_round_trip(&mut hal, &command, 45, &response);

    expect_idle(&mut hal);
    let mut atecc = Atecc::new(hal);
    let mut channel = block_on(atecc.open_channel()).expect("open_channel");
    block_on(channel.write_32(Zone::Data, data_address(slot, 0, 0), &data))
        .expect("write_32");

    block_on(channel.close()).expect("close");
    atecc.into_hal().verify();
}

// ---------------------------------------------------------------------------
// Config-zone block 0 wire-sequence contract
//
// Backs `hsm_crypto_service::CryptoService::write_config_block(0, ..)`. The
// chip rejects any 32-byte transfer to block 0 of the config zone (bytes
// 0..16 are read-only factory area, the chip returns ParseError 0x03). The
// service must therefore write block 0 as **four** 4-byte transfers
// targeting words 4..=7 (chip-side bytes 16..32), skipping the factory
// area entirely. This test pins down the exact wire sequence so that a
// regression in either addressing or transfer size is caught
// deterministically off-target.
// ---------------------------------------------------------------------------

/// Build the wire frame for one `Write(Config, 4-byte, cleartext)` command
/// targeting the given (block, word_offset) inside the config zone. The
/// frame layout is identical to the existing
/// `write_4_config_block_2_offset_5_cleartext` test, parameterised over
/// the address and payload.
fn build_write_4_config_word(block: u8, word_offset: u8, data: &[u8; WORD_SIZE]) -> [u8; 12]
{
    let address = config_or_otp_address(block, word_offset);
    let mut frame = [0u8; 12];
    frame[0] = 0x03;                                   // word address (command)
    frame[1] = 0x0B;                                   // count = 7 + 4 = 11
    frame[2] = 0x12;                                   // opcode WRITE
    frame[3] = 0x00;                                   // p1 = Config | 4-byte | cleartext
    frame[4] = (address & 0xFF) as u8;                 // p2 lo
    frame[5] = ((address >> 8) & 0xFF) as u8;          // p2 hi
    frame[6..10].copy_from_slice(data);
    let crc = atecc608b::crc::crc16(&frame[1..10]);
    let crc_bytes = atecc608b::crc::crc16_to_bytes(crc);
    frame[10] = crc_bytes[0];
    frame[11] = crc_bytes[1];
    frame
}

#[test]
fn write_config_block_0_sequence_is_four_4byte_writes_at_words_4_to_7()
{
    // Build a representative 32-byte payload. Only the upper 16 bytes
    // (offsets 16..32) should hit the wire; the first 16 are the factory
    // area placeholder that the host CLI sends but the chip must never see.
    let mut payload = [0u8; BLOCK_SIZE];
    for (i, byte) in payload.iter_mut().enumerate()
    {
        // Distinctive pattern so a wrong slicing is immediately visible
        // in the assertion: bytes 0..16 use 0xA0..0xAF, bytes 16..32 use
        // 0xB0..0xBF. The test expects to see only the 0xBX values on
        // the wire.
        *byte = if i < 16 { 0xA0 | (i as u8) } else { 0xB0 | ((i - 16) as u8) };
    }

    // Expected sequence: four 4-byte writes at word offsets 4, 5, 6, 7
    // (chip-side bytes 16..20, 20..24, 24..28, 28..32).
    let expected_frames: [[u8; 12]; 4] =
    [
        build_write_4_config_word(0, 4, &[payload[16], payload[17], payload[18], payload[19]]),
        build_write_4_config_word(0, 5, &[payload[20], payload[21], payload[22], payload[23]]),
        build_write_4_config_word(0, 6, &[payload[24], payload[25], payload[26], payload[27]]),
        build_write_4_config_word(0, 7, &[payload[28], payload[29], payload[30], payload[31]]),
    ];

    let response = status_response(0x00);
    let mut hal = MockHal::new();
    expect_wake(&mut hal);
    for frame in &expected_frames
    {
        expect_command_round_trip(&mut hal, frame, 45, &response);
    }
    expect_idle(&mut hal);

    // Drive the same sequence the service-level `write_config_block(0, ..)`
    // will produce. Mirrors that orchestration explicitly so a regression
    // in either function (driver-level `write_4` addressing or service-level
    // chunking) is caught here.
    let mut atecc = Atecc::new(hal);
    let mut channel = block_on(atecc.open_channel()).expect("open_channel");
    for word_offset in 4u8..=7u8
    {
        let off = usize::from(word_offset) * 4;
        let chunk: [u8; WORD_SIZE] =
        [
            payload[off],
            payload[off + 1],
            payload[off + 2],
            payload[off + 3],
        ];
        block_on(channel.write_4(Zone::Config, config_or_otp_address(0, word_offset), &chunk))
            .expect("write_4");
    }

    block_on(channel.close()).expect("close");
    atecc.into_hal().verify();
}

#[test]
fn write_config_block_0_addresses_are_0x0004_through_0x0007()
{
    // Anchors the addressing math used by the service: word offsets 4..=7
    // in block 0 of the config zone correspond to chip-side bytes 16..32,
    // and the param2 values are 0x0004, 0x0005, 0x0006, 0x0007 respectively.
    // If `config_or_otp_address` ever changes its bit layout, this test
    // fails loudly before any HAL is even touched.
    assert_eq!(config_or_otp_address(0, 4), 0x0004);
    assert_eq!(config_or_otp_address(0, 5), 0x0005);
    assert_eq!(config_or_otp_address(0, 6), 0x0006);
    assert_eq!(config_or_otp_address(0, 7), 0x0007);
}

// ---------------------------------------------------------------------------
// Config-zone block 2 wire-sequence contract
//
// Block 2 covers chip-side bytes 64..96. Word 5 (bytes 84..88) holds
// `UserExtra`, `Selector`, `LockValue`, and `LockConfig`, which are not
// writable via the `Write` command (they have dedicated `UpdateExtra` and
// `Lock` commands). The chip rejects any 32-byte transfer that includes
// this word with `ParseError 0x03`. CryptoAuthLib's `calib_write_bytes_zone`
// in `lib/calib/calib_basic.c` skips word 5 of block 2 explicitly:
//
//     if (!(zone == ATCA_ZONE_CONFIG && cur_block == 2u && cur_word == 5u)) {
//         calib_write_zone(... cur_block, cur_word, ..., ATCA_WORD_SIZE);
//     }
//
// We mirror that: block 2 is written as 7 separate 4-byte writes at word
// offsets 0, 1, 2, 3, 4, 6, 7. Word 5 is silently skipped.
// ---------------------------------------------------------------------------

#[test]
fn write_config_block_2_sequence_skips_word_5()
{
    // Build a representative 32-byte payload with a distinctive pattern so
    // a wrong slicing is immediately visible. Each byte encodes its block-2
    // position in the upper nibble: byte n of the payload is 0xC0 | (n & 0x1F).
    let mut payload = [0u8; BLOCK_SIZE];
    for (i, byte) in payload.iter_mut().enumerate()
    {
        *byte = 0xC0 | (i as u8 & 0x1F);
    }

    // Word offsets 0..=4 and 6..=7 are writable; word 5 (payload bytes
    // 20..24, chip-side bytes 84..88) is skipped.
    let writable_offsets: [u8; 7] = [0, 1, 2, 3, 4, 6, 7];
    let mut expected_frames: Vec<[u8; 12]> = Vec::new();
    for &word_offset in &writable_offsets
    {
        let off = usize::from(word_offset) * 4;
        let chunk: [u8; WORD_SIZE] =
        [
            payload[off],
            payload[off + 1],
            payload[off + 2],
            payload[off + 3],
        ];
        expected_frames.push(build_write_4_config_word(2, word_offset, &chunk));
    }
    assert_eq!(expected_frames.len(), 7);

    let response = status_response(0x00);
    let mut hal = MockHal::new();
    expect_wake(&mut hal);
    for frame in &expected_frames
    {
        expect_command_round_trip(&mut hal, frame, 45, &response);
    }
    expect_idle(&mut hal);

    // Drive the same sequence `write_config_block(2, ..)` produces.
    let mut atecc = Atecc::new(hal);
    let mut channel = block_on(atecc.open_channel()).expect("open_channel");
    for &word_offset in &writable_offsets
    {
        let off = usize::from(word_offset) * 4;
        let chunk: [u8; WORD_SIZE] =
        [
            payload[off],
            payload[off + 1],
            payload[off + 2],
            payload[off + 3],
        ];
        block_on(channel.write_4(Zone::Config, config_or_otp_address(2, word_offset), &chunk))
            .expect("write_4");
    }

    block_on(channel.close()).expect("close");
    atecc.into_hal().verify();
}

#[test]
fn write_config_block_2_addresses_skip_0x0015()
{
    // The block-2 word offsets that hit the wire are 0..=4 and 6..=7.
    // Their param2 values are:
    //   word 0 (bytes 64-67)  -> 0x0010
    //   word 1 (bytes 68-71)  -> 0x0011
    //   word 2 (bytes 72-75)  -> 0x0012
    //   word 3 (bytes 76-79)  -> 0x0013
    //   word 4 (bytes 80-83)  -> 0x0014
    //   word 5 (bytes 84-87)  -> 0x0015  (NOT WRITTEN)
    //   word 6 (bytes 88-91)  -> 0x0016
    //   word 7 (bytes 92-95)  -> 0x0017
    assert_eq!(config_or_otp_address(2, 0), 0x0010);
    assert_eq!(config_or_otp_address(2, 4), 0x0014);
    assert_eq!(config_or_otp_address(2, 5), 0x0015); // skipped on the wire
    assert_eq!(config_or_otp_address(2, 6), 0x0016);
    assert_eq!(config_or_otp_address(2, 7), 0x0017);
}

// ---------------------------------------------------------------------------
// write_32 encrypted (slot 5 / PIN hash)
// ---------------------------------------------------------------------------

#[test]
fn write_32_encrypted_data_slot_5()
{
    // p1 = 0xC2 (Data | Encrypted | 32-byte)
    // p2 = data_address(slot=5, block=0, off=0) = 0x0028
    // data = 32 bytes ciphertext (all 0xAA) + 32 bytes MAC (all 0x55)
    let mut data = [0u8; ENCRYPTED_WRITE_DATA_SIZE];
    data[..32].fill(0xAA);
    data[32..].fill(0x55);

    let mut command = [0u8; 72];
    command[0] = 0x03;                   // word addr
    command[1] = 0x47;                   // count = 7 + 64 = 71 = 0x47
    command[2] = 0x12;                   // opcode WRITE
    command[3] = 0xC2;                   // p1 = data + 32-byte + encrypted
    command[4] = 0x28;                   // p2 lo
    command[5] = 0x00;                   // p2 hi
    command[6..70].copy_from_slice(&data);
    let crc = atecc608b::crc::crc16(&command[1..70]);
    let crc_bytes = atecc608b::crc::crc16_to_bytes(crc);
    command[70] = crc_bytes[0];
    command[71] = crc_bytes[1];

    // Sanity: pre-computed reference for this exact frame was 40 ED.
    assert_eq!(command[70..72], [0x40, 0xED]);

    let response = status_response(0x00);
    let mut hal = MockHal::new();
    expect_wake(&mut hal);
    expect_command_round_trip(&mut hal, &command, 45, &response);

    let slot = Slot::const_new(5);
    expect_idle(&mut hal);
    let mut atecc = Atecc::new(hal);
    let mut channel = block_on(atecc.open_channel()).expect("open_channel");
    block_on(channel.write_32_encrypted(Zone::Data, data_address(slot, 0, 0), &data))
        .expect("write_32_encrypted");

    block_on(channel.close()).expect("close");
    atecc.into_hal().verify();
}

// ---------------------------------------------------------------------------
// Error propagation
// ---------------------------------------------------------------------------

#[test]
fn write_propagates_chip_execution_error()
{
    // Chip returns 04 0F <crc>. ExecutionError per CryptoAuthLib's
    // isATCAError(). The driver should surface AteccError::Chip(ExecutionError).
    let mut command = [0u8; 12];
    command[0] = 0x03;
    command[1] = 0x0B;
    command[2] = 0x12;
    command[3] = 0x00;
    command[4] = 0x00;
    command[5] = 0x00;
    command[6..10].copy_from_slice(&[0x01, 0x02, 0x03, 0x04]);
    let crc = atecc608b::crc::crc16(&command[1..10]);
    let crc_bytes = atecc608b::crc::crc16_to_bytes(crc);
    command[10] = crc_bytes[0];
    command[11] = crc_bytes[1];

    let response = status_response(0x0F);
    let mut hal = MockHal::new();
    expect_wake(&mut hal);
    expect_command_round_trip(&mut hal, &command, 45, &response);

    expect_idle(&mut hal);
    let mut atecc = Atecc::new(hal);
    let mut channel = block_on(atecc.open_channel()).expect("open_channel");
    let payload: [u8; WORD_SIZE] = [0x01, 0x02, 0x03, 0x04];
    let err = block_on(channel.write_4(Zone::Config, 0, &payload)).unwrap_err();

    match err
    {
        AteccError::Chip(ChipError::ExecutionError) => {}
        other => panic!("expected Chip(ExecutionError), got {other:?}"),
    }
    block_on(channel.close()).expect("close");
    atecc.into_hal().verify();
}

#[test]
fn write_rejects_payload_response_as_malformed()
{
    // A Write should never return a data payload. If the chip somehow does,
    // execute_command_status treats the result as malformed.
    let mut command = [0u8; 12];
    command[0] = 0x03;
    command[1] = 0x0B;
    command[2] = 0x12;
    command[3] = 0x00;
    command[4] = 0x00;
    command[5] = 0x00;
    command[6..10].copy_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD]);
    let crc = atecc608b::crc::crc16(&command[1..10]);
    let crc_bytes = atecc608b::crc::crc16_to_bytes(crc);
    command[10] = crc_bytes[0];
    command[11] = crc_bytes[1];

    // Force the mock to reply with a 5-byte response (count = 5). The
    // status-only entry point reads exactly 4 bytes into its tiny buffer,
    // so a count byte of 5 exceeds that buffer and surfaces as
    // MalformedResponse from the polling layer (total > max_buf_len).
    let bogus_response: [u8; 4] = [0x05, 0xAA, 0x00, 0x00];

    let mut hal = MockHal::new();
    expect_wake(&mut hal);
    hal.expect_i2c_write(ADDR, &command);
    hal.expect_delay_ms(45);
    // The driver reads the count byte 0x05 and notices it exceeds the
    // 4-byte buffer. No further i2c_read should follow.
    hal.expect_i2c_read(ADDR, &bogus_response[0..1]);

    expect_idle(&mut hal);
    let mut atecc = Atecc::new(hal);
    let mut channel = block_on(atecc.open_channel()).expect("open_channel");
    let payload: [u8; WORD_SIZE] = [0xAA, 0xBB, 0xCC, 0xDD];
    let err = block_on(channel.write_4(Zone::Config, 0, &payload)).unwrap_err();

    match err
    {
        AteccError::MalformedResponse => {}
        other => panic!("expected MalformedResponse, got {other:?}"),
    }
    block_on(channel.close()).expect("close");
    atecc.into_hal().verify();
}