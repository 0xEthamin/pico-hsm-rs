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

//! Integration tests for the `GenDig` command.

mod common;

use atecc608b::opcodes::{WAKE_DELAY_US, WAKE_LOW_DURATION_US};
use common::{block_on, MockHal};

use atecc608b::command::gendig::GenDigZone;
use atecc608b::Atecc;

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
fn gendig_data_slot_8_uses_zone_data()
{
    // Reference frame body: 07 15 02 08 00 33 E8
    const COMMAND: [u8; 8] = [0x03, 0x07, 0x15, 0x02, 0x08, 0x00, 0x33, 0xE8];
    let response = status_response(0x00);

    let mut hal = MockHal::new();
    expect_wake(&mut hal);
    expect_command_round_trip(&mut hal, &COMMAND, 25, &response);

    expect_idle(&mut hal);
    let mut atecc = Atecc::new(hal);
    let mut channel = block_on(atecc.open_channel()).expect("open_channel");
    block_on(channel.gendig(GenDigZone::Data, 0x0008)).expect("gendig");
    block_on(channel.close()).expect("close");
    atecc.into_hal().verify();
}

#[test]
fn gendig_config_block_0()
{
    // Reference frame body: 07 15 00 00 00 33 8D
    const COMMAND: [u8; 8] = [0x03, 0x07, 0x15, 0x00, 0x00, 0x00, 0x33, 0x8D];
    let response = status_response(0x00);

    let mut hal = MockHal::new();
    expect_wake(&mut hal);
    expect_command_round_trip(&mut hal, &COMMAND, 25, &response);

    expect_idle(&mut hal);
    let mut atecc = Atecc::new(hal);
    let mut channel = block_on(atecc.open_channel()).expect("open_channel");
    block_on(channel.gendig(GenDigZone::Config, 0x0000)).expect("gendig");
    block_on(channel.close()).expect("close");
    atecc.into_hal().verify();
}

#[test]
fn gendig_data_slot_0()
{
    // Reference frame body: 07 15 02 00 00 30 08
    const COMMAND: [u8; 8] = [0x03, 0x07, 0x15, 0x02, 0x00, 0x00, 0x30, 0x08];
    let response = status_response(0x00);

    let mut hal = MockHal::new();
    expect_wake(&mut hal);
    expect_command_round_trip(&mut hal, &COMMAND, 25, &response);

    expect_idle(&mut hal);
    let mut atecc = Atecc::new(hal);
    let mut channel = block_on(atecc.open_channel()).expect("open_channel");
    block_on(channel.gendig(GenDigZone::Data, 0x0000)).expect("gendig");
    block_on(channel.close()).expect("close");
    atecc.into_hal().verify();
}