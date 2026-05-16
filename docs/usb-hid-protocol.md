# USB-HID protocol

The mini-HSM exposes a vendor-defined HID interface with fixed-size 64-byte
reports in each direction. Both Linux/macOS (libusb/hidraw) and Windows
(Hidclass.sys) support this without a kernel driver.

## VID / PID

| Field | Value     |
|-------|-----------|
| VID   | `0xCAFE`  |
| PID   | `0x1312`  |

These are not officially assigned by the USB-IF. They follow community
convention for hobby / open-source devices. If the project graduates beyond
the hackathon, I would consider applying for a free PID from [pid.codes](https://pid.codes/).

## Report layout

Every report (host->token and token->host) is exactly 64 bytes:

```
Byte 0    : Opcode or status code
Bytes 1-2 : Payload length, little-endian u16
Bytes 3-N : Payload
Bytes …   : Zero-padding until 64
```

## Command opcodes

See [`crates/hsm-usb-protocol/src/commands.rs`](../crates/hsm-usb-protocol/src/commands.rs)
for the source of truth. Highlights:

| Code  | Name                  | Payload (host->token)              | Notes                                                                  |
|-------|-----------------------|-----------------------------------|------------------------------------------------------------------------|
| 0x01  | Info                  | (none)                            |                                                                        |
| 0x02  | GetPubkey             | `slot:u8`                         |                                                                        |
| 0x03  | Sign                  | `slot:u8, digest:[u8;32]`         | Requires active PIN session and touch.                                 |
| 0x04  | GenKey                | `slot:u8`                         | Requires active PIN session.                                           |
| 0x05  | ReadConfigZone        | (none)                            | Returns 128 bytes.                                                     |
| 0x06  | ReadConfigSlot        | `slot:u8`                         | Returns 4 bytes (SlotConfig + KeyConfig).                              |
| 0x07  | VerifyPin             | `pin:[u8;4]`                      | Opens a 30 s session.                                                  |
| 0x08  | SetPin                | `old:[u8;4], new:[u8;4]`          | Requires active session.                                               |
| 0x09  | UnblockPin            | `puk:[u8;8], new_pin:[u8;4]`      |                                                                        |
| 0x0A  | GetPinStatus          | (none)                            | Returns retry counters and blocked / bricked state.                    |
| 0x10  | WriteConfigZone       | `config:[u8;88]`                  | Writable part of the config zone.                                      |
| 0xF0  | LockConfigZone        | `magic:[u8;4], expected_crc:u16`  | **Irreversible.**                                                      |
| 0xF1  | LockDataZone          | `magic:[u8;4]`                    | **Irreversible.**                                                      |
| 0xF2  | LockSlot              | `magic:[u8;4], slot:u8`           | **Irreversible.**                                                      |

## Status codes

See [`crates/hsm-usb-protocol/src/responses.rs`](../crates/hsm-usb-protocol/src/responses.rs).
