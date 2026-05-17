//! Integration tests for the `CheckMac` command.

mod common;

use common::{block_on, MockHal};

use atecc608b::command::checkmac::{
    CHECKMAC_CHALLENGE_SIZE,
    CHECKMAC_CLIENT_RESPONSE_SIZE,
    CHECKMAC_DATA_SIZE,
    CHECKMAC_OTHER_DATA_SIZE,
};
use atecc608b::{Atecc, Slot};

const WAKE_RESPONSE: [u8; 4] = [0x04, 0x11, 0x33, 0x43];
const ADDR: u8 = 0x60;

fn expect_wake(hal: &mut MockHal)
{
    hal.expect_pulse_sda_low(60);
    hal.expect_delay_us(1500);
    hal.expect_i2c_read(ADDR, &WAKE_RESPONSE);
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

/// Build the 85-byte CheckMac command (word_addr + 7 header + 77 data).
fn build_checkmac_command(
    slot: u8,
    challenge: &[u8; CHECKMAC_CHALLENGE_SIZE],
    client_resp: &[u8; CHECKMAC_CLIENT_RESPONSE_SIZE],
    other_data: &[u8; CHECKMAC_OTHER_DATA_SIZE],
) -> [u8; 85]
{
    let mut cmd = [0u8; 85];
    cmd[0] = 0x03;
    cmd[1] = (7 + CHECKMAC_DATA_SIZE) as u8; // 84 = 0x54
    cmd[2] = 0x28;                            // OP_CHECKMAC
    cmd[3] = 0x00;                            // mode = challenge from input
    cmd[4] = slot;
    cmd[5] = 0x00;
    cmd[6..38].copy_from_slice(challenge);
    cmd[38..70].copy_from_slice(client_resp);
    cmd[70..83].copy_from_slice(other_data);
    let crc = atecc608b::crc::crc16(&cmd[1..83]);
    let crc_bytes = atecc608b::crc::crc16_to_bytes(crc);
    cmd[83] = crc_bytes[0];
    cmd[84] = crc_bytes[1];
    cmd
}

#[test]
fn checkmac_match_returns_true()
{
    let mut challenge = [0u8; CHECKMAC_CHALLENGE_SIZE];
    for (i, byte) in challenge.iter_mut().enumerate()
    {
        *byte = i as u8;
    }
    let mut client_resp = [0u8; CHECKMAC_CLIENT_RESPONSE_SIZE];
    for (i, byte) in client_resp.iter_mut().enumerate()
    {
        *byte = (i as u8) ^ 0xFF;
    }
    let other_data = [0u8; CHECKMAC_OTHER_DATA_SIZE];

    let command = build_checkmac_command(5, &challenge, &client_resp, &other_data);
    // Sanity vs precomputed CRC for this exact payload (challenge 00..1F,
    // client_resp 00^FF..1F^FF, other_data all zero, slot 5).
    assert_eq!(command[83..85], [0x33, 0x0E]);

    let response = status_response(0x00);

    let mut hal = MockHal::new();
    expect_wake(&mut hal);
    expect_command_round_trip(&mut hal, &command, 40, &response);

    let mut atecc = Atecc::new(hal);
    let ok = block_on(atecc.checkmac(Slot::const_new(5), &challenge, &client_resp, &other_data))
        .expect("checkmac");
    assert!(ok);
    atecc.into_hal().verify();
}

#[test]
fn checkmac_miscompare_returns_false()
{
    let challenge = [0u8; CHECKMAC_CHALLENGE_SIZE];
    let client_resp = [0u8; CHECKMAC_CLIENT_RESPONSE_SIZE];
    let other_data = [0u8; CHECKMAC_OTHER_DATA_SIZE];

    let command = build_checkmac_command(5, &challenge, &client_resp, &other_data);
    // Sanity vs precomputed CRC for all-zero data, slot 5.
    assert_eq!(command[83..85], [0xBA, 0x95]);

    let response = status_response(0x01);

    let mut hal = MockHal::new();
    expect_wake(&mut hal);
    expect_command_round_trip(&mut hal, &command, 40, &response);

    let mut atecc = Atecc::new(hal);
    let ok = block_on(atecc.checkmac(Slot::const_new(5), &challenge, &client_resp, &other_data))
        .expect("checkmac");
    assert!(!ok);
    atecc.into_hal().verify();
}