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

//! Integration test exercising the full Info command pipeline.
//!
//! Verifies that:
//! 1. Opening a channel performs the wake sequence.
//! 2. The Info command frame is serialized exactly as the chip expects.
//! 3. The chip's revision response is parsed correctly.
//! 4. Multiple commands can be issued within a single channel without
//!    re-waking.
//! 5. Closing the channel sends the idle token, and the next channel
//!    triggers a fresh wake.

mod common;

use common::{block_on, MockHal};

use atecc608b::Atecc;
use atecc608b::opcodes::{WAKE_DELAY_US, WAKE_LOW_DURATION_US};

/// Full byte stream of a wake response from a healthy ATECC608B.
const WAKE_RESPONSE: [u8; 4] = [0x04, 0x11, 0x33, 0x43];

/// Wire bytes the driver should send for an Info(Revision) command. The
/// first byte is the command word address (0x03). The next 7 bytes are the
/// command frame itself (count, opcode, p1, p2_lo, p2_hi, crc_lo, crc_hi).
const INFO_COMMAND_WIRE: [u8; 8] = [0x03, 0x07, 0x30, 0x00, 0x00, 0x00, 0x03, 0x5D];

/// Wire bytes the chip returns for Info(Revision) on an M0 silicon variant.
/// Layout: count(0x07) + reserved(0x00, 0x00) + family(0x60) + variant(0x02)
/// + crc(0x80, 0x38).
const INFO_RESPONSE_M0: [u8; 7] = [0x07, 0x00, 0x00, 0x60, 0x02, 0x80, 0x38];

/// Setup the mock to expect exactly one wake sequence.
fn expect_wake(hal: &mut MockHal)
{
    hal.expect_pulse_sda_low(WAKE_LOW_DURATION_US);
    hal.expect_delay_us(WAKE_DELAY_US);
    hal.expect_i2c_read(0x60, &WAKE_RESPONSE);
}

/// Setup the mock to expect exactly one idle write (the channel close).
fn expect_idle(hal: &mut MockHal)
{
    hal.expect_i2c_write(0x60, &[0x02]);
}

/// Setup the mock to expect one full Info(Revision) round-trip including the
/// command write, execution delay, count-byte read, and payload read.
fn expect_info_revision_m0(hal: &mut MockHal)
{
    // 1. Send command frame.
    hal.expect_i2c_write(0x60, &INFO_COMMAND_WIRE);
    // 2. Wait nominal execution time (Info is 5 ms on M0).
    hal.expect_delay_ms(5);
    // 3. Read count byte.
    hal.expect_i2c_read(0x60, &INFO_RESPONSE_M0[0..1]);
    // 4. Read the remaining 6 bytes (payload + CRC).
    hal.expect_i2c_read(0x60, &INFO_RESPONSE_M0[1..7]);
}

#[test]
fn info_revision_full_pipeline()
{
    let mut hal = MockHal::new();
    expect_wake(&mut hal);
    expect_info_revision_m0(&mut hal);
    expect_idle(&mut hal);

    let mut atecc = Atecc::new(hal);
    let mut channel = block_on(atecc.open_channel()).expect("open_channel");
    let revision = block_on(channel.info_revision()).expect("info_revision");
    block_on(channel.close()).expect("close");

    assert_eq!(revision, [0x00, 0x00, 0x60, 0x02]);
    atecc.into_hal().verify();
}

#[test]
fn two_commands_in_one_channel_share_a_single_wake()
{
    let mut hal = MockHal::new();
    // One wake, then two Info commands back-to-back, then one idle close.
    expect_wake(&mut hal);
    expect_info_revision_m0(&mut hal);
    expect_info_revision_m0(&mut hal);
    expect_idle(&mut hal);

    let mut atecc = Atecc::new(hal);
    let mut channel = block_on(atecc.open_channel()).expect("open_channel");
    let _ = block_on(channel.info_revision()).expect("first info_revision");
    let revision2 = block_on(channel.info_revision()).expect("second info_revision");
    block_on(channel.close()).expect("close");

    assert_eq!(revision2, [0x00, 0x00, 0x60, 0x02]);
    atecc.into_hal().verify();
}

#[test]
fn closing_then_reopening_triggers_fresh_wake()
{
    let mut hal = MockHal::new();
    // First channel: wake, Info, idle.
    expect_wake(&mut hal);
    expect_info_revision_m0(&mut hal);
    expect_idle(&mut hal);
    // Second channel: fresh wake, Info, idle.
    expect_wake(&mut hal);
    expect_info_revision_m0(&mut hal);
    expect_idle(&mut hal);

    let mut atecc = Atecc::new(hal);

    let mut channel = block_on(atecc.open_channel()).expect("open_channel 1");
    let _ = block_on(channel.info_revision()).expect("info_revision 1");
    block_on(channel.close()).expect("close 1");

    let mut channel = block_on(atecc.open_channel()).expect("open_channel 2");
    let _ = block_on(channel.info_revision()).expect("info_revision 2");
    block_on(channel.close()).expect("close 2");

    atecc.into_hal().verify();
}

#[test]
fn polling_handles_chip_busy_then_ready()
{
    // The chip NACKs the first 3 reads of the count byte, then responds.
    // The driver should retry with a 2 ms delay between each attempt.
    let mut hal = MockHal::new();
    expect_wake(&mut hal);

    // 1. Command write.
    hal.expect_i2c_write(0x60, &INFO_COMMAND_WIRE);
    // 2. Nominal delay.
    hal.expect_delay_ms(5);
    // 3. Three NACK + delay cycles. The driver reads a single count byte
    //    each time.
    hal.expect_i2c_read_nack(0x60, 1);
    hal.expect_delay_ms(2);
    hal.expect_i2c_read_nack(0x60, 1);
    hal.expect_delay_ms(2);
    hal.expect_i2c_read_nack(0x60, 1);
    hal.expect_delay_ms(2);
    // 4. Fourth attempt succeeds. Count byte first, then the payload.
    hal.expect_i2c_read(0x60, &INFO_RESPONSE_M0[0..1]);
    hal.expect_i2c_read(0x60, &INFO_RESPONSE_M0[1..7]);
    // 5. Close.
    expect_idle(&mut hal);

    let mut atecc = Atecc::new(hal);
    let mut channel = block_on(atecc.open_channel()).expect("open_channel");
    let revision = block_on(channel.info_revision()).expect("info_revision under polling");
    block_on(channel.close()).expect("close");
    assert_eq!(revision, [0x00, 0x00, 0x60, 0x02]);
    atecc.into_hal().verify();
}
