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

//! Integration tests for the `Sign` command.

mod common;

use common::{block_on, MockHal};

use atecc608b::command::sign::SIGNATURE_SIZE;
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

fn expect_idle(hal: &mut MockHal)
{
    hal.expect_i2c_write(ADDR, &[0x02]);
}

fn response_frame_64(payload: &[u8; SIGNATURE_SIZE]) -> [u8; 67]
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
fn sign_external_slot_0_returns_64_byte_signature()
{
    // Reference frame body: 07 41 A0 00 00 7B 85
    //
    // - p1 = 0xA0 = SIGN_MODE_EXTERNAL (0x80) | SIGN_MODE_SOURCE_MSGDIGBUF (0x20)
    //   The 608's `Sign(external)` requires both bits: external mode (digest
    //   provided by host, not generated internally) AND source=MsgDigBuf
    //   (read the 32-byte digest from the Message Digest Buffer rather than
    //   from TempKey). Sending 0x80 alone leaves source=TempKey, which on
    //   the 608 makes the chip mix extra context bytes into what it actually
    //   signs — the resulting signature does NOT verify off-chip against the
    //   raw digest.
    // - p2 = 0x0000 (slot 0).
    // - CRC = 0x857B for body [0x07, 0x41, 0xA0, 0x00, 0x00].
    const COMMAND: [u8; 8] = [0x03, 0x07, 0x41, 0xA0, 0x00, 0x00, 0x7B, 0x85];

    // Synthetic signature R || S = 0x40..0x7F.
    let mut sig = [0u8; SIGNATURE_SIZE];
    for (i, byte) in sig.iter_mut().enumerate()
    {
        *byte = 0x40 + i as u8;
    }
    let response = response_frame_64(&sig);

    let mut hal = MockHal::new();
    expect_wake(&mut hal);
    expect_command_round_trip(&mut hal, &COMMAND, 220, &response);

    expect_idle(&mut hal);
    let mut atecc = Atecc::new(hal);
    let mut channel = block_on(atecc.open_channel()).expect("open_channel");
    let result = block_on(channel.sign_external(Slot::const_new(0))).expect("sign_external");

    assert_eq!(result, sig);
    block_on(channel.close()).expect("close");
    atecc.into_hal().verify();
}