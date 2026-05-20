//! End-to-end protocol tests that mimic what the firmware and host do.

use hsm_usb_protocol::{
    commands::{self, CommandOpcode, DIGEST_LEN, PIN_LEN, PUK_LEN},
    responses::ResponseStatus,
    Frame,
    HID_REPORT_SIZE,
};

#[test]
fn host_builds_sign_request_and_token_parses_it()
{
    // Host side: build a Sign command targeting slot 0 with a known digest.
    let mut digest = [0u8; DIGEST_LEN];
    for (i, byte) in digest.iter_mut().enumerate()
    {
        *byte = i as u8;
    }
    let mut payload = [0u8; 1 + DIGEST_LEN];
    payload[0] = 0; // slot 0
    payload[1..].copy_from_slice(&digest);

    let report = Frame::to_report(CommandOpcode::Sign.as_u8(), &payload).unwrap();
    assert_eq!(report.len(), HID_REPORT_SIZE);

    // Token side: parse the wire bytes back.
    let frame = Frame::parse(&report).unwrap();
    let opcode = CommandOpcode::try_from(frame.opcode).unwrap();
    assert_eq!(opcode, CommandOpcode::Sign);

    let (parsed_slot, parsed_digest) = commands::parse_sign(frame.payload).unwrap();
    assert_eq!(parsed_slot, 0);
    assert_eq!(parsed_digest, digest);
}

#[test]
fn token_returns_pubkey_response_and_host_parses_it()
{
    // Token side: build an Ok response with a 64-byte pubkey payload.
    let mut pubkey = [0u8; 64];
    for (i, byte) in pubkey.iter_mut().enumerate()
    {
        *byte = 0x40 + i as u8;
    }
    let report = Frame::to_report(ResponseStatus::Ok.as_u8(), &pubkey).unwrap();

    // Host side: parse.
    let frame = Frame::parse(&report).unwrap();
    let status = ResponseStatus::try_from(frame.opcode).unwrap();
    assert_eq!(status, ResponseStatus::Ok);
    assert_eq!(frame.payload, &pubkey);
}

#[test]
fn token_returns_wrong_pin_with_tries_remaining()
{
    // Tries remaining = 3, encoded in the single-byte payload.
    let report = Frame::to_report(ResponseStatus::WrongPin.as_u8(), &[3]).unwrap();
    let frame = Frame::parse(&report).unwrap();
    assert_eq!(ResponseStatus::try_from(frame.opcode).unwrap(), ResponseStatus::WrongPin);
    assert_eq!(frame.payload, &[3]);
}

#[test]
fn unblock_pin_round_trip()
{
    let puk = *b"12345678";
    let new_pin = *b"4242";
    let io_key: [u8; 32] = core::array::from_fn(|i| 0xA0u8.wrapping_add(i as u8));
    let mut payload = [0u8; PUK_LEN + PIN_LEN + 32];
    payload[..PUK_LEN].copy_from_slice(&puk);
    payload[PUK_LEN..PUK_LEN + PIN_LEN].copy_from_slice(&new_pin);
    payload[PUK_LEN + PIN_LEN..].copy_from_slice(&io_key);

    let report = Frame::to_report(CommandOpcode::UnblockPin.as_u8(), &payload).unwrap();
    let frame = Frame::parse(&report).unwrap();
    assert_eq!(CommandOpcode::try_from(frame.opcode).unwrap(), CommandOpcode::UnblockPin);
    let (parsed_puk, parsed_pin, parsed_io_key) =
        commands::parse_unblock_pin(frame.payload).unwrap();
    assert_eq!(parsed_puk, puk);
    assert_eq!(parsed_pin, new_pin);
    assert_eq!(parsed_io_key, io_key);
}

#[test]
fn empty_payload_command_uses_zero_length_payload()
{
    let report = Frame::to_report(CommandOpcode::Info.as_u8(), &[]).unwrap();
    // The two len bytes must be 0.
    assert_eq!(report[1], 0);
    assert_eq!(report[2], 0);
    let frame = Frame::parse(&report).unwrap();
    assert_eq!(frame.payload.len(), 0);
    assert_eq!(CommandOpcode::try_from(frame.opcode).unwrap(), CommandOpcode::Info);
}