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

//! Integration tests for the `Counter` command.

mod common;

use common::{block_on, MockHal};

use atecc608b::command::counter::CounterId;
use atecc608b::Atecc;
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

fn response_frame_u32(value: u32) -> [u8; 7]
{
    let mut out = [0u8; 7];
    out[0] = 7;
    out[1..5].copy_from_slice(&value.to_le_bytes());
    let crc = atecc608b::crc::crc16(&out[..5]);
    let crc_bytes = atecc608b::crc::crc16_to_bytes(crc);
    out[5] = crc_bytes[0];
    out[6] = crc_bytes[1];
    out
}

fn expect_command_round_trip
(
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
fn counter_read_counter0_returns_value()
{
    // Reference frame body: 07 24 00 00 00 0C FD
    const COMMAND: [u8; 8] = [0x03, 0x07, 0x24, 0x00, 0x00, 0x00, 0x0C, 0xFD];

    let response = response_frame_u32(5);

    let mut hal = MockHal::new();
    expect_wake(&mut hal);
    expect_command_round_trip(&mut hal, &COMMAND, 25, &response);
    expect_idle(&mut hal);

    let mut atecc = Atecc::new(hal);
    let mut channel = block_on(atecc.open_channel()).expect("open_channel");
    let value = block_on(channel.counter_read(CounterId::Counter0)).expect("counter_read");
    block_on(channel.close()).expect("close");

    assert_eq!(value, 5);
    atecc.into_hal().verify();
}

#[test]
fn counter_increment_counter0_returns_new_value()
{
    // Reference frame body: 07 24 01 00 00 0F 77
    const COMMAND: [u8; 8] = [0x03, 0x07, 0x24, 0x01, 0x00, 0x00, 0x0F, 0x77];

    let response = response_frame_u32(6);

    let mut hal = MockHal::new();
    expect_wake(&mut hal);
    expect_command_round_trip(&mut hal, &COMMAND, 25, &response);
    expect_idle(&mut hal);

    let mut atecc = Atecc::new(hal);
    let mut channel = block_on(atecc.open_channel()).expect("open_channel");
    let value = block_on(channel.counter_increment(CounterId::Counter0))
        .expect("counter_increment");
    block_on(channel.close()).expect("close");

    assert_eq!(value, 6);
    atecc.into_hal().verify();
}

#[test]
fn counter_read_counter1_uses_param2_one()
{
    // Reference frame body: 07 24 00 01 00 05 7D
    const COMMAND: [u8; 8] = [0x03, 0x07, 0x24, 0x00, 0x01, 0x00, 0x05, 0x7D];

    let response = response_frame_u32(123_456);

    let mut hal = MockHal::new();
    expect_wake(&mut hal);
    expect_command_round_trip(&mut hal, &COMMAND, 25, &response);
    expect_idle(&mut hal);

    let mut atecc = Atecc::new(hal);
    let mut channel = block_on(atecc.open_channel()).expect("open_channel");
    let value = block_on(channel.counter_read(CounterId::Counter1)).expect("counter_read");
    block_on(channel.close()).expect("close");

    assert_eq!(value, 123_456);
    atecc.into_hal().verify();
}

#[test]
fn counter_value_is_little_endian()
{
    // Send back 0x00 0x01 0x00 0x00 = 256 in LE.
    const COMMAND: [u8; 8] = [0x03, 0x07, 0x24, 0x00, 0x00, 0x00, 0x0C, 0xFD];

    let mut response = [0u8; 7];
    response[0] = 7;
    response[1] = 0x00;
    response[2] = 0x01;
    response[3] = 0x00;
    response[4] = 0x00;
    let crc = atecc608b::crc::crc16(&response[..5]);
    let crc_bytes = atecc608b::crc::crc16_to_bytes(crc);
    response[5] = crc_bytes[0];
    response[6] = crc_bytes[1];

    let mut hal = MockHal::new();
    expect_wake(&mut hal);
    expect_command_round_trip(&mut hal, &COMMAND, 25, &response);
    expect_idle(&mut hal);

    let mut atecc = Atecc::new(hal);
    let mut channel = block_on(atecc.open_channel()).expect("open_channel");
    let value = block_on(channel.counter_read(CounterId::Counter0)).expect("counter_read");
    block_on(channel.close()).expect("close");

    assert_eq!(value, 256);
    atecc.into_hal().verify();
}
