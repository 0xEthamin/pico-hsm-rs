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
    // Reference frame body: 07 41 80 00 00 28 05
    // p1 = 0x80 (SIGN_MODE_EXTERNAL), p2 = 0x0000 (slot 0)
    const COMMAND: [u8; 8] = [0x03, 0x07, 0x41, 0x80, 0x00, 0x00, 0x28, 0x05];

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

    let mut atecc = Atecc::new(hal);
    let result = block_on(atecc.sign_external(Slot::const_new(0))).expect("sign_external");

    assert_eq!(result, sig);
    atecc.into_hal().verify();
}