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

//! Integration tests for the Nonce command.
//!
//! Every wire byte sequence in this file was produced by running the same
//! CRC-16 algorithm as `crates/atecc608b/src/crc.rs` in Python over the
//! expected frame layout.

mod common;

use common::{block_on, MockHal};

use atecc608b::command::nonce::{NonceTarget, NONCE_NUMIN_SIZE, NONCE_NUMOUT_SIZE, NONCE_PASSTHROUGH_SIZE};
use atecc608b::{Atecc, AteccError, ChipError};
use atecc608b::opcodes::{WAKE_DELAY_US, WAKE_LOW_DURATION_US};

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

/// Build a 35-byte payload response: count(1) + 32 bytes + crc(2).
fn response_frame_32(payload: &[u8; 32]) -> [u8; 35]
{
    let mut out = [0u8; 35];
    out[0] = 35;
    out[1..33].copy_from_slice(payload);
    let crc = atecc608b::crc::crc16(&out[..33]);
    let crc_bytes = atecc608b::crc::crc16_to_bytes(crc);
    out[33] = crc_bytes[0];
    out[34] = crc_bytes[1];
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
// nonce_random (mode 0)
// ---------------------------------------------------------------------------

#[test]
fn nonce_random_returns_chip_num_out()
{
    // p1 = 0x00 (mode 0, random)
    // p2 = 0x0000
    // data = NumIn = 20 bytes 00..13
    // Reference frame body: 1B 16 00 00 00 <num_in> 53 B5
    let mut num_in = [0u8; NONCE_NUMIN_SIZE];
    for (i, byte) in num_in.iter_mut().enumerate()
    {
        *byte = i as u8;
    }

    let mut command = [0u8; 28];
    command[0] = 0x03;                   // word addr
    command[1] = 0x1B;                   // count = 7 + 20 = 27 = 0x1B
    command[2] = 0x16;                   // opcode NONCE
    command[3] = 0x00;                   // p1 = mode 0
    command[4] = 0x00;                   // p2 lo
    command[5] = 0x00;                   // p2 hi
    command[6..26].copy_from_slice(&num_in);
    let crc = atecc608b::crc::crc16(&command[1..26]);
    let crc_bytes = atecc608b::crc::crc16_to_bytes(crc);
    command[26] = crc_bytes[0];
    command[27] = crc_bytes[1];

    // Sanity: precomputed reference was 53 B5.
    assert_eq!(command[26..28], [0x53, 0xB5]);

    // Chip-returned NumOut is 32 bytes 0x80..0x9F.
    let mut num_out = [0u8; NONCE_NUMOUT_SIZE];
    for (i, byte) in num_out.iter_mut().enumerate()
    {
        *byte = 0x80 + i as u8;
    }
    let response = response_frame_32(&num_out);

    let mut hal = MockHal::new();
    expect_wake(&mut hal);
    expect_command_round_trip(&mut hal, &command, 20, &response);

    expect_idle(&mut hal);
    let mut atecc = Atecc::new(hal);
    let mut channel = block_on(atecc.open_channel()).expect("open_channel");
    let result = block_on(channel.nonce_random(&num_in)).expect("nonce_random");

    assert_eq!(result, num_out);
    block_on(channel.close()).expect("close");
    atecc.into_hal().verify();
}

// ---------------------------------------------------------------------------
// nonce_passthrough (mode 3)
// ---------------------------------------------------------------------------

#[test]
fn nonce_passthrough_tempkey_loads_value_verbatim()
{
    // p1 = 0x03 (mode 3, target TempKey)
    // p2 = 0x0000
    // data = 32 bytes 0x20..0x3F (a deterministic stand-in for a digest)
    // Reference frame body: 27 16 03 00 00 <value> 8B E0
    let mut value = [0u8; NONCE_PASSTHROUGH_SIZE];
    for (i, byte) in value.iter_mut().enumerate()
    {
        *byte = 0x20 + i as u8;
    }

    let mut command = [0u8; 40];
    command[0] = 0x03;                   // word addr
    command[1] = 0x27;                   // count = 7 + 32 = 39 = 0x27
    command[2] = 0x16;                   // opcode NONCE
    command[3] = 0x03;                   // p1 = mode 3, target TempKey
    command[4] = 0x00;                   // p2 lo
    command[5] = 0x00;                   // p2 hi
    command[6..38].copy_from_slice(&value);
    let crc = atecc608b::crc::crc16(&command[1..38]);
    let crc_bytes = atecc608b::crc::crc16_to_bytes(crc);
    command[38] = crc_bytes[0];
    command[39] = crc_bytes[1];

    // Sanity: precomputed reference was 8B E0.
    assert_eq!(command[38..40], [0x8B, 0xE0]);

    let response = status_response(0x00);

    let mut hal = MockHal::new();
    expect_wake(&mut hal);
    expect_command_round_trip(&mut hal, &command, 20, &response);

    expect_idle(&mut hal);
    let mut atecc = Atecc::new(hal);
    let mut channel = block_on(atecc.open_channel()).expect("open_channel");
    block_on(channel.nonce_passthrough(NonceTarget::TempKey, &value))
        .expect("nonce_passthrough TempKey");

    block_on(channel.close()).expect("close");
    atecc.into_hal().verify();
}

#[test]
fn nonce_passthrough_msgdigbuf_sets_target_bit()
{
    // p1 = 0x43 (mode 3, target MsgDigBuf via bit 6)
    // p2 = 0x0000
    // data = 32 bytes 0xAA
    // Reference frame body: 27 16 43 00 00 <value> F7 45
    let value = [0xAAu8; NONCE_PASSTHROUGH_SIZE];

    let mut command = [0u8; 40];
    command[0] = 0x03;
    command[1] = 0x27;
    command[2] = 0x16;
    command[3] = 0x43;                   // mode 3 | target MsgDigBuf
    command[4] = 0x00;
    command[5] = 0x00;
    command[6..38].copy_from_slice(&value);
    let crc = atecc608b::crc::crc16(&command[1..38]);
    let crc_bytes = atecc608b::crc::crc16_to_bytes(crc);
    command[38] = crc_bytes[0];
    command[39] = crc_bytes[1];

    // Sanity: precomputed reference was F7 45.
    assert_eq!(command[38..40], [0xF7, 0x45]);

    let response = status_response(0x00);

    let mut hal = MockHal::new();
    expect_wake(&mut hal);
    expect_command_round_trip(&mut hal, &command, 20, &response);

    expect_idle(&mut hal);
    let mut atecc = Atecc::new(hal);
    let mut channel = block_on(atecc.open_channel()).expect("open_channel");
    block_on(channel.nonce_passthrough(NonceTarget::MsgDigBuf, &value))
        .expect("nonce_passthrough MsgDigBuf");

    block_on(channel.close()).expect("close");
    atecc.into_hal().verify();
}

// ---------------------------------------------------------------------------
// Error propagation
// ---------------------------------------------------------------------------

#[test]
fn nonce_passthrough_propagates_chip_parse_error()
{
    // Chip returns 04 03 <crc>. ParseError per CryptoAuthLib's isATCAError().
    let value = [0x11u8; NONCE_PASSTHROUGH_SIZE];

    let mut command = [0u8; 40];
    command[0] = 0x03;
    command[1] = 0x27;
    command[2] = 0x16;
    command[3] = 0x03;
    command[4] = 0x00;
    command[5] = 0x00;
    command[6..38].copy_from_slice(&value);
    let crc = atecc608b::crc::crc16(&command[1..38]);
    let crc_bytes = atecc608b::crc::crc16_to_bytes(crc);
    command[38] = crc_bytes[0];
    command[39] = crc_bytes[1];

    let response = status_response(0x03);

    let mut hal = MockHal::new();
    expect_wake(&mut hal);
    expect_command_round_trip(&mut hal, &command, 20, &response);

    expect_idle(&mut hal);
    let mut atecc = Atecc::new(hal);
    let mut channel = block_on(atecc.open_channel()).expect("open_channel");
    let err = block_on(channel.nonce_passthrough(NonceTarget::TempKey, &value)).unwrap_err();

    match err
    {
        AteccError::Chip(ChipError::ParseError) => {}
        other => panic!("expected Chip(ParseError), got {other:?}"),
    }
    block_on(channel.close()).expect("close");
    atecc.into_hal().verify();
}

#[test]
fn nonce_random_then_passthrough_share_one_wake()
{
    // Two Nonce commands in a row should produce a single wake sequence at
    // the start: the chip stays awake between commands. This mirrors the
    // real usage in Sign workflows where Nonce-passthrough precedes Sign
    // without any sleep in between.
    let num_in = [0xCCu8; NONCE_NUMIN_SIZE];

    // First command: nonce_random. We don't care about the exact CRC here,
    // compute it dynamically.
    let mut cmd1 = [0u8; 28];
    cmd1[0] = 0x03;
    cmd1[1] = 0x1B;
    cmd1[2] = 0x16;
    cmd1[3] = 0x00;
    cmd1[4] = 0x00;
    cmd1[5] = 0x00;
    cmd1[6..26].copy_from_slice(&num_in);
    let c1 = atecc608b::crc::crc16(&cmd1[1..26]);
    let c1b = atecc608b::crc::crc16_to_bytes(c1);
    cmd1[26] = c1b[0];
    cmd1[27] = c1b[1];

    let num_out = [0x55u8; NONCE_NUMOUT_SIZE];
    let resp1 = response_frame_32(&num_out);

    // Second command: nonce_passthrough TempKey, value = 32 bytes 0x00.
    let value = [0x00u8; NONCE_PASSTHROUGH_SIZE];
    let mut cmd2 = [0u8; 40];
    cmd2[0] = 0x03;
    cmd2[1] = 0x27;
    cmd2[2] = 0x16;
    cmd2[3] = 0x03;
    cmd2[4] = 0x00;
    cmd2[5] = 0x00;
    cmd2[6..38].copy_from_slice(&value);
    let c2 = atecc608b::crc::crc16(&cmd2[1..38]);
    let c2b = atecc608b::crc::crc16_to_bytes(c2);
    cmd2[38] = c2b[0];
    cmd2[39] = c2b[1];

    let resp2 = status_response(0x00);

    let mut hal = MockHal::new();
    expect_wake(&mut hal);
    expect_command_round_trip(&mut hal, &cmd1, 20, &resp1);
    // Crucially: NO second wake here.
    expect_command_round_trip(&mut hal, &cmd2, 20, &resp2);

    expect_idle(&mut hal);
    let mut atecc = Atecc::new(hal);
    let mut channel = block_on(atecc.open_channel()).expect("open_channel");
    let returned_num_out = block_on(channel.nonce_random(&num_in)).expect("nonce_random");
    assert_eq!(returned_num_out, num_out);
    block_on(channel.nonce_passthrough(NonceTarget::TempKey, &value))
        .expect("nonce_passthrough");

    block_on(channel.close()).expect("close");
    atecc.into_hal().verify();
}