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

//! Integration tests for the `PrivWrite` command.

mod common;

use common::{block_on, MockHal};

use atecc608b::command::privwrite::PRIVWRITE_CLEARTEXT_SIZE;
use atecc608b::{Atecc, AteccError, ChipError, Slot};
use atecc608b::opcodes::{WAKE_DELAY_US, WAKE_LOW_DURATION_US};

const WAKE_RESPONSE: [u8; 4] = [0x04, 0x11, 0x33, 0x43];
const ADDR: u8 = 0x60;

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

#[test]
fn privwrite_cleartext_slot_0_zero_key()
{
    // Frame: 0x2B 0x46 0x00 0x00 0x00 + 4 pad + 32 zero priv + CRC
    // Total body = 7 + 36 = 43 bytes
    let priv_key = [0u8; 32];
    let mut command = [0u8; 44];
    command[0] = 0x03;                               // word addr
    command[1] = 0x2B;                               // count = 43 = 0x2B
    command[2] = 0x46;                               // OP_PRIVWRITE
    command[3] = 0x00;                               // mode = cleartext
    command[4] = 0x00;                               // p2 lo (slot 0)
    command[5] = 0x00;                               // p2 hi
    // 4 pad + 32 priv key (all zero)
    let crc = atecc608b::crc::crc16(&command[1..42]);
    let crc_bytes = atecc608b::crc::crc16_to_bytes(crc);
    command[42] = crc_bytes[0];
    command[43] = crc_bytes[1];
    // Sanity: precomputed reference was CC 80.
    assert_eq!(command[42..44], [0xCC, 0x80]);

    let response = status_response(0x00);

    let mut hal = MockHal::new();
    expect_wake(&mut hal);
    expect_command_round_trip(&mut hal, &command, 50, &response);

    expect_idle(&mut hal);
    let mut atecc = Atecc::new(hal);
    let mut channel = block_on(atecc.open_channel()).expect("open_channel");
    block_on(channel.privwrite_cleartext(Slot::const_new(0), &priv_key))
        .expect("privwrite_cleartext");
    block_on(channel.close()).expect("close");
    atecc.into_hal().verify();
}

#[test]
fn privwrite_cleartext_propagates_chip_execution_error()
{
    // After data zone lock, the chip rejects cleartext PrivWrite with
    // ExecutionError (status 0x0F). Verify the error path.
    let priv_key = [0xAAu8; 32];
    let mut command = [0u8; 44];
    command[0] = 0x03;
    command[1] = 0x2B;
    command[2] = 0x46;
    command[3] = 0x00;
    command[4] = 0x00;
    command[5] = 0x00;
    command[6..10].copy_from_slice(&[0u8; 4]);
    command[10..42].copy_from_slice(&priv_key);
    let crc = atecc608b::crc::crc16(&command[1..42]);
    let crc_bytes = atecc608b::crc::crc16_to_bytes(crc);
    command[42] = crc_bytes[0];
    command[43] = crc_bytes[1];

    let response = status_response(0x0F);

    let mut hal = MockHal::new();
    expect_wake(&mut hal);
    expect_command_round_trip(&mut hal, &command, 50, &response);

    expect_idle(&mut hal);
    let mut atecc = Atecc::new(hal);
    let mut channel = block_on(atecc.open_channel()).expect("open_channel");
    let err = block_on(channel.privwrite_cleartext(Slot::const_new(0), &priv_key)).unwrap_err();

    match err
    {
        AteccError::Chip(ChipError::ExecutionError) => {}
        other => panic!("expected Chip(ExecutionError), got {other:?}"),
    }
    block_on(channel.close()).expect("close");
    atecc.into_hal().verify();
}

#[test]
fn privwrite_cleartext_payload_size_constant()
{
    assert_eq!(PRIVWRITE_CLEARTEXT_SIZE, 36);
}