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

//! Integration tests for the `Verify` command.

mod common;

use common::{block_on, MockHal};

use atecc608b::command::genkey::PUBLIC_KEY_SIZE;
use atecc608b::command::sign::SIGNATURE_SIZE;
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

/// Build a 136-byte `Verify External P256` command (word addr + 135 body).
fn build_verify_command(
    signature: &[u8; SIGNATURE_SIZE],
    public_key: &[u8; PUBLIC_KEY_SIZE],
) -> [u8; 136]
{
    let mut cmd = [0u8; 136];
    cmd[0] = 0x03;                       // word addr
    cmd[1] = 0x87;                       // count = 7 + 128 = 135 = 0x87
    cmd[2] = 0x45;                       // OP_VERIFY
    cmd[3] = 0x02;                       // p1 = External
    cmd[4] = 0x04;                       // p2 lo = P256 key id
    cmd[5] = 0x00;                       // p2 hi
    cmd[6..70].copy_from_slice(signature);
    cmd[70..134].copy_from_slice(public_key);
    let crc = atecc608b::crc::crc16(&cmd[1..134]);
    let crc_bytes = atecc608b::crc::crc16_to_bytes(crc);
    cmd[134] = crc_bytes[0];
    cmd[135] = crc_bytes[1];
    cmd
}

#[test]
fn verify_external_success_returns_true()
{
    let signature = [0x11u8; SIGNATURE_SIZE];
    let public_key = [0x22u8; PUBLIC_KEY_SIZE];

    let command = build_verify_command(&signature, &public_key);
    // Sanity vs precomputed CRC.
    assert_eq!(command[134..136], [0xB6, 0x87]);

    let response = status_response(0x00);

    let mut hal = MockHal::new();
    expect_wake(&mut hal);
    expect_command_round_trip(&mut hal, &command, 295, &response);

    expect_idle(&mut hal);
    let mut atecc = Atecc::new(hal);
    let mut channel = block_on(atecc.open_channel()).expect("open_channel");
    let ok = block_on(channel.verify_external(&signature, &public_key))
        .expect("verify_external");

    assert!(ok);
    block_on(channel.close()).expect("close");
    atecc.into_hal().verify();
}

#[test]
fn verify_external_miscompare_returns_false()
{
    // Chip returns status 0x01 = CheckMacOrVerifyFailed, which the driver
    // maps to Ok(false) rather than propagating as an error.
    let signature = [0x33u8; SIGNATURE_SIZE];
    let public_key = [0x44u8; PUBLIC_KEY_SIZE];

    let command = build_verify_command(&signature, &public_key);
    let response = status_response(0x01);

    let mut hal = MockHal::new();
    expect_wake(&mut hal);
    expect_command_round_trip(&mut hal, &command, 295, &response);

    expect_idle(&mut hal);
    let mut atecc = Atecc::new(hal);
    let mut channel = block_on(atecc.open_channel()).expect("open_channel");
    let ok = block_on(channel.verify_external(&signature, &public_key))
        .expect("verify_external");

    assert!(!ok);
    block_on(channel.close()).expect("close");
    atecc.into_hal().verify();
}