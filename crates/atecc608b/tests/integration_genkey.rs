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

//! Integration tests for the `GenKey` command.

mod common;

use common::{block_on, MockHal};

use atecc608b::command::genkey::PUBLIC_KEY_SIZE;
use atecc608b::{Atecc, Slot};
use atecc608b::opcodes::{WAKE_DELAY_US, WAKE_LOW_DURATION_US};

const WAKE_RESPONSE: [u8; 4] = [0x04, 0x11, 0x33, 0x43];
const ADDR: u8 = 0x60;

fn expect_wake(hal: &mut MockHal)
{
    hal.expect_pulse_sda_low(WAKE_LOW_DURATION_US);
    hal.expect_delay_us(WAKE_DELAY_US);
    hal.expect_i2c_read(ADDR, &WAKE_RESPONSE);
}

fn response_frame_64(payload: &[u8; PUBLIC_KEY_SIZE]) -> [u8; 67]
{
    let mut out = [0u8; 67];
    out[0] = 67;
    out[1..65].copy_from_slice(payload);
    let crc = atecc608b::crc::crc16(&out[..65]);
    let crc_bytes = atecc608b::crc::crc16_to_bytes(crc);
    out[65] = crc_bytes[0];
    out[66] = crc_bytes[1];
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
fn genkey_create_slot_0_returns_pubkey()
{
    // Reference frame body: 07 40 04 00 00 83 87
    const COMMAND: [u8; 8] = [0x03, 0x07, 0x40, 0x04, 0x00, 0x00, 0x83, 0x87];

    let mut pubkey = [0u8; PUBLIC_KEY_SIZE];
    for (i, byte) in pubkey.iter_mut().enumerate()
    {
        *byte = i as u8;
    }
    let response = response_frame_64(&pubkey);

    let mut hal = MockHal::new();
    expect_wake(&mut hal);
    expect_command_round_trip(&mut hal, &COMMAND, 215, &response);

    let mut atecc = Atecc::new(hal);
    let result = block_on(atecc.genkey_create(Slot::const_new(0))).expect("genkey_create");

    assert_eq!(result, pubkey);
    atecc.into_hal().verify();
}

#[test]
fn genkey_public_slot_0_uses_mode_zero()
{
    // Reference frame body: 07 40 00 00 00 00 05
    const COMMAND: [u8; 8] = [0x03, 0x07, 0x40, 0x00, 0x00, 0x00, 0x00, 0x05];

    let pubkey = [0x42u8; PUBLIC_KEY_SIZE];
    let response = response_frame_64(&pubkey);

    let mut hal = MockHal::new();
    expect_wake(&mut hal);
    expect_command_round_trip(&mut hal, &COMMAND, 215, &response);

    let mut atecc = Atecc::new(hal);
    let result = block_on(atecc.genkey_public(Slot::const_new(0))).expect("genkey_public");

    assert_eq!(result, pubkey);
    atecc.into_hal().verify();
}

#[test]
fn genkey_create_slot_1_changes_param2()
{
    // Reference frame body: 07 40 00 01 00 09 85
    const COMMAND: [u8; 8] = [0x03, 0x07, 0x40, 0x00, 0x01, 0x00, 0x09, 0x85];

    let pubkey = [0xAAu8; PUBLIC_KEY_SIZE];
    let response = response_frame_64(&pubkey);

    let mut hal = MockHal::new();
    expect_wake(&mut hal);
    expect_command_round_trip(&mut hal, &COMMAND, 215, &response);

    let mut atecc = Atecc::new(hal);
    let result = block_on(atecc.genkey_public(Slot::const_new(1))).expect("genkey_public slot 1");

    assert_eq!(result, pubkey);
    atecc.into_hal().verify();
}