# USB-HID protocol

The mini-HSM exposes a vendor-defined HID interface with fixed-size
64-byte reports in each direction. Linux, macOS, and Windows all support
this without a kernel driver.

## VID and PID

| Field | Value     |
|-------|-----------|
| VID   | `0xCAFE`  |
| PID   | `0x1312`  |

These values are not officially assigned by the USB-IF. They follow the
community convention for open-source and hobby devices. If the project
graduates beyond the hackathon, applying for a free PID at
[pid.codes](https://pid.codes/) is the next step.

## Report layout

Every report, in either direction, is exactly 64 bytes:

```
Byte 0    : Opcode (host -> token) or status code (token -> host)
Bytes 1-2 : Payload length, little-endian u16
Bytes 3-N : Payload
Bytes ... : Zero padding up to byte 63
```

The canonical encoder and decoder live in
`crates/hsm-usb-protocol/src/frame.rs`, with round-trip property tests.

## Command opcodes

These match the `CommandOpcode` enum in
`crates/hsm-usb-protocol/src/commands.rs`. That file is the source of
truth for opcode values, payload formats, and parsing logic.

| Code   | Name             | Payload (host -> token)                                       | Notes                                                                          |
|--------|------------------|---------------------------------------------------------------|--------------------------------------------------------------------------------|
| `0x01` | Info             | empty                                                         | Returns firmware version, chip serial, provisioning state.                     |
| `0x02` | GetPubkey        | `slot: u8`                                                    | Returns the 64-byte public key.                                                |
| `0x03` | Sign             | `slot: u8, digest: [u8; 32]`                                  | Requires an active PIN session **and** a touch. Returns 64-byte signature R\|\|S. |
| `0x04` | GenKey           | `slot: u8`                                                    | Requires an active PIN session. Generates a fresh P-256 key in the slot. The old key is overwritten. |
| `0x05` | ReadConfigZone   | `block: u8` (0..=3)                                           | Returns 32 bytes of the configuration zone. Host issues 4 times to get all 128 bytes. |
| `0x06` | ReadConfigSlot   | `slot: u8`                                                    | Returns 4 bytes (SlotConfig + KeyConfig).                                      |
| `0x07` | VerifyPin        | `pin: [u8; 4]` (ASCII digits)                                 | Opens a 30 s PIN session. Wrong PIN increments Counter0 by 1.                  |
| `0x08` | SetPin           | `old: [u8; 4], new: [u8; 4], io_key: [u8; 32]`                | Re-verifies `old` on the chip via CheckMac (consumes one Counter0 attempt, refreshed on success). No prior PIN session is required: this call both authenticates and opens / refreshes the session. |
| `0x09` | UnblockPin       | `puk: [u8; 8], new_pin: [u8; 4], io_key: [u8; 32]`            | Resets the PIN. Wrong PUK increments Counter1 by 1.                            |
| `0x0A` | GetPinStatus     | empty                                                         | Returns retry counters for PIN and PUK, and the "blocked" and "bricked" flags. |
| `0x0B` | SetPuk           | `old_puk: [u8; 8], new_puk: [u8; 8], io_key: [u8; 32]`        | Requires an active PIN session. Re-verifies `old_puk` on the chip via CheckMac (consumes one Counter1 attempt, refreshed on success). |
| `0x0D` | EmergencyReset   | `magic: [u8; 4] = BA DC 0F FE, io_key: [u8; 32]`              | **Last-chance recovery.** Only succeeds when both PIN and PUK batches are exhausted. Otherwise returns `EmergencyResetNotPermitted` with the actual tries remaining. Destroys user ECC keys, resets PIN to `0000`, generates fresh PUK (returned). No PIN required. |
| `0x10` | WriteConfigZone  | `block: u8, data: [u8; 32]`                                   | Writes one 32-byte block of the configuration zone. Host issues 4 times. Reversible only while the config zone is unlocked. |
| `0x11` | ProvisionSlot    | `slot: u8, value: [u8; 32]`                                   | Writes a 32-byte cleartext value into a data slot. Only accepted for slots 5 (PIN hash), 6 (PUK hash), and 8 (IO key). Only legal while the data zone is unlocked. |
| `0x12` | ProvisionInitialPin | empty                                                      | Writes `SHA-256("0000" \|\| pin_salt)` into slot 5. The salt is derived on-chip from the chip serial; the host does not need to compute it. Only legal while the data zone is unlocked. |
| `0x13` | ProvisionInitialPuk | empty                                                      | Generates a random 8-digit PUK from the chip RNG, writes `SHA-256(puk \|\| puk_salt)` into slot 6, and returns the PUK in the response payload. **One-time** read of the PUK. |
| `0x14` | ProvisionIoKey   | empty                                                         | Generates 32 random bytes via the chip RNG, writes them into slot 8, and returns the value in the response payload. **One-time** read of the IO key. The host must persist it. |
| `0xF0` | LockConfigZone   | `magic: [u8; 4], expected_crc: [u8; 2]`                       | **Irreversible.** Firmware verifies the chip's current configuration CRC equals `expected_crc` before issuing `Lock(config)`. |
| `0xF1` | LockDataZone     | `magic: [u8; 4], expected_crc: [u8; 2]`                       | **Irreversible.** Verifies a CRC of the current data zone state.               |
| `0xF2` | LockSlot         | `magic: [u8; 4], slot: u8`                                    | **Irreversible.** Permanently freezes one slot. Requires `KeyConfig.Lockable=1` on that slot. |

For the project's mini-HSM configuration, the expected CRC for
`LockConfigZone` is **`0xCB23`** (see `docs/config-zone-layout.md`).

The "magic" word on Lock commands is a fixed 4-byte sentinel checked by
the firmware before issuing the chip's `Lock` command. It is a final
sanity guard against bit-flips in the USB report or a host CLI that
forgot to pass the confirmation flag. The current values are:
- `LockConfigZone` magic: `0xDE 0xAD 0xBE 0xEF`
- `LockDataZone` magic: `0xCA 0xFE 0xBA 0xBE`
- `LockSlot` magic: `0xCA 0xFE 0xBA 0xBE`

## Status codes (token to host)

These match the `ResponseStatus` enum in
`crates/hsm-usb-protocol/src/responses.rs`.

| Code   | Name                     | Meaning                                                                  |
|--------|--------------------------|--------------------------------------------------------------------------|
| `0x00` | Ok                       | Operation succeeded. Payload contains the command-specific response.     |
| `0x01` | InvalidCommand           | The opcode byte was not recognized.                                      |
| `0x02` | InvalidPayload           | Payload size or shape was wrong for this command.                        |
| `0x03` | InvalidSlot              | Slot index was out of range.                                             |
| `0x04` | AteccCommunicationError  | I2C or wake error talking to the ATECC.                                  |
| `0x05` | AteccChipError           | The chip returned an error status. First byte of payload is the chip code. |
| `0x06` | TouchTimeout             | The user did not press the button within 30 s.                           |
| `0x07` | NotProvisioned           | The token has not been provisioned yet.                                  |
| `0x08` | LockMagicMismatch        | Magic word for a Lock command did not match.                             |
| `0x09` | LockCrcMismatch          | CRC of the expected configuration did not match what is on the chip.     |
| `0x0A` | Busy                     | Another operation is in progress.                                        |
| `0x0B` | WrongPin                 | PIN was wrong. Payload first byte is "tries remaining in this batch".    |
| `0x0C` | PinRequired              | A PIN session is required before this operation.                         |
| `0x0D` | PinBlocked               | PIN slot is hardware-blocked. Only `UnblockPin` can recover.             |
| `0x0E` | WrongPuk                 | PUK was wrong. Payload first byte is "PUK tries remaining in this batch". |
| `0x0F` | Bricked                  | PUK retries exhausted (Counter1 saturated). PUK feature unavailable. Signing remains possible if the user knows the PIN. |
| `0x10` | EmergencyResetNotPermitted | `EmergencyReset` was attempted while the user still has PIN or PUK attempts. Payload: `[pin_tries_remaining, puk_tries_remaining]`. |

## Reserved opcode space

The following opcodes are reserved for forthcoming commands. They are
not yet implemented. The host CLI rejects them: the firmware returns
`InvalidCommand` (`0x01`).

| Code   | Reserved name | Intended payload                                                | Status                                                                  |
|--------|---------------|-----------------------------------------------------------------|-------------------------------------------------------------------------|
| `0x0B` | SetPuk        | `old: [u8; 8], new: [u8; 8], io_key: [u8; 32]`                  | Implemented.                                                            |
| `0x0D` | EmergencyReset | `magic: [u8; 4] = BA DC 0F FE, io_key: [u8; 32]`               | Implemented. Last-chance recovery for "PIN + PUK both lost AND both batches exhausted". Firmware refuses with `EmergencyResetNotPermitted` if either batch still has attempts. User loses ECC private keys. |

The opcode space below `0xF0` is for routine commands; `0xF0` and above
are reserved for the small family of permanent / irreversible commands.

## Sample exchanges

### Successful Sign

Host -> token:
```
03 21 00 02 <32-byte digest> <23 zero bytes of padding>
```
(opcode `Sign`, payload length 0x0021 = 33 bytes = `slot=2 ||
digest[32]`)

Token sequence:
- Verify PIN session is active. If not, respond `0C PinRequired`.
- Enter `WaitingForTouch` state. Yellow LED on.
- Wait up to 30 s for the button press. On timeout, respond `06
  TouchTimeout`.
- On press, enter `Signing` state. Issue `Nonce(passthrough, digest)`
  then `Sign(slot)` on the chip.
- Return the 64-byte signature.

Token -> host:
```
00 40 00 <64-byte signature R||S> <padding>
```

### Wrong PIN

Host -> token: `07 04 00 39 39 39 39 <padding>`
(VerifyPin with PIN "9999")

Chip CheckMac fails, Counter0 increments. Firmware computes tries
remaining in this batch.

Token -> host: `0B 01 00 <tries_remaining> <padding>`

### Lock confirmation flow (configuration zone)

Host -> token:
```
F0 06 00 DE AD BE EF 23 CB <padding>
```
(`LockConfigZone` with magic `DE AD BE EF` and `expected_crc = 0xCB23`
encoded little-endian as `23 CB`.)

The firmware:
1. Validates the magic word. If wrong, respond `08 LockMagicMismatch`.
2. Reads the current configuration zone from the chip.
3. Computes its CRC over bytes 16-127.
4. Compares with the supplied `expected_crc`. If different, respond `09
   LockCrcMismatch`.
5. Issues the chip's `Lock(config)` command.
6. Respond `Ok`.