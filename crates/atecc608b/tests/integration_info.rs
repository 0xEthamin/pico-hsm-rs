//! Integration test exercising the full Info command pipeline.
//!
//! Verifies that:
//! 1. The driver performs the wake sequence on the first call.
//! 2. The Info command frame is serialized exactly as the chip expects.
//! 3. The chip's revision response is parsed correctly.
//! 4. Calling info_revision a second time skips the wake (already awake).
//! 5. After explicit idle(), a subsequent call wakes the chip again.

mod common;

use common::{block_on, MockHal};

use atecc608b::Atecc;

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
    hal.expect_pulse_sda_low(60);
    hal.expect_delay_us(1500);
    hal.expect_i2c_read(0x60, &WAKE_RESPONSE);
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

    let mut atecc = Atecc::new(hal);
    let revision = block_on(atecc.info_revision()).expect("info_revision");

    assert_eq!(revision, [0x00, 0x00, 0x60, 0x02]);
    atecc.into_hal().verify();
}

#[test]
fn second_call_skips_wake()
{
    let mut hal = MockHal::new();
    // First call: wake then Info.
    expect_wake(&mut hal);
    expect_info_revision_m0(&mut hal);
    // Second call: NO wake, just Info.
    expect_info_revision_m0(&mut hal);

    let mut atecc = Atecc::new(hal);
    let _ = block_on(atecc.info_revision()).expect("first info_revision");
    let revision2 = block_on(atecc.info_revision()).expect("second info_revision");

    assert_eq!(revision2, [0x00, 0x00, 0x60, 0x02]);
    atecc.into_hal().verify();
}

#[test]
fn idle_forces_rewake()
{
    let mut hal = MockHal::new();
    expect_wake(&mut hal);
    expect_info_revision_m0(&mut hal);
    // Idle is just a single-byte I2C write of the idle word address (0x02).
    hal.expect_i2c_write(0x60, &[0x02]);
    // Next call should wake again.
    expect_wake(&mut hal);
    expect_info_revision_m0(&mut hal);

    let mut atecc = Atecc::new(hal);
    let _ = block_on(atecc.info_revision()).expect("first info_revision");
    block_on(atecc.idle()).expect("idle");
    let _ = block_on(atecc.info_revision()).expect("second info_revision");

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
    let mut atecc = Atecc::new(hal);
    let revision = block_on(atecc.info_revision()).expect("info_revision under polling");
    assert_eq!(revision, [0x00, 0x00, 0x60, 0x02]);
    atecc.into_hal().verify();
}
