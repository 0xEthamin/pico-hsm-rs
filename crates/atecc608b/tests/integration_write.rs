//! Integration tests for the Write command and its higher-level helpers.
//!
//! Every wire byte sequence in this file was produced by running the same
//! CRC-16 algorithm as `crates/atecc608b/src/crc.rs` in Python over the
//! expected frame layout.

mod common;

use common::{block_on, MockHal};

use atecc608b::Atecc;
use atecc608b::command::read_write::{
    config_or_otp_address,
    data_address,
    Zone,
    BLOCK_SIZE,
    ENCRYPTED_WRITE_DATA_SIZE,
    WORD_SIZE,
};
use atecc608b::{AteccError, ChipError, Slot};

/// Wake response bytes from a healthy chip.
const WAKE_RESPONSE: [u8; 4] = [0x04, 0x11, 0x33, 0x43];

/// I2C 7-bit address used throughout these tests (chip default).
const ADDR: u8 = 0x60;

/// Setup the mock to expect one wake sequence.
fn expect_wake(hal: &mut MockHal)
{
    hal.expect_pulse_sda_low(60);
    hal.expect_delay_us(1500);
    hal.expect_i2c_read(ADDR, &WAKE_RESPONSE);
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

    let mut atecc = Atecc::new(hal);
    let payload = [0xCA, 0xFE, 0xBA, 0xBE];
    block_on(atecc.write_4(Zone::Config, config_or_otp_address(2, 5), &payload))
        .expect("write_4");

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
    let mut atecc = Atecc::new(hal);
    block_on(atecc.write_slot_word(slot, 0, 0, &payload)).expect("write_slot_word");

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
    let mut atecc = Atecc::new(hal);
    block_on(atecc.write_slot_block(slot, 0, &data)).expect("write_slot_block");

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

    let mut atecc = Atecc::new(hal);
    block_on(atecc.write_32(Zone::Data, data_address(slot, 0, 0), &data))
        .expect("write_32");

    atecc.into_hal().verify();
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
    let mut atecc = Atecc::new(hal);
    block_on(atecc.write_32_encrypted(Zone::Data, data_address(slot, 0, 0), &data))
        .expect("write_32_encrypted");

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

    let mut atecc = Atecc::new(hal);
    let payload: [u8; WORD_SIZE] = [0x01, 0x02, 0x03, 0x04];
    let err = block_on(atecc.write_4(Zone::Config, 0, &payload)).unwrap_err();

    match err
    {
        AteccError::Chip(ChipError::ExecutionError) => {}
        other => panic!("expected Chip(ExecutionError), got {other:?}"),
    }
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

    let mut atecc = Atecc::new(hal);
    let payload: [u8; WORD_SIZE] = [0xAA, 0xBB, 0xCC, 0xDD];
    let err = block_on(atecc.write_4(Zone::Config, 0, &payload)).unwrap_err();

    match err
    {
        AteccError::MalformedResponse => {}
        other => panic!("expected MalformedResponse, got {other:?}"),
    }
    atecc.into_hal().verify();
}