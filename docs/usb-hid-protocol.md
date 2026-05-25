# USB-HID protocol

The mini-HSM exposes a vendor-defined HID interface with fixed-size
128-byte reports in each direction. Linux, macOS, and Windows all support
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

Every report, in either direction, is exactly 128 bytes:

```
Byte 0    : Opcode (host -> token) or status code (token -> host)
Bytes 1-2 : Payload length, little-endian u16
Bytes 3-N : Payload
Bytes ... : Zero padding up to byte 127
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
| `0x0C` | CloseSession     | empty                                                         | Terminates the current PIN session immediately. Idempotent: closing an already-closed session succeeds. No chip interaction. |
| `0x0D` | EmergencyReset   | `magic: [u8; 4] = BA DC 0F FE, io_key: [u8; 32]`              | **Last-chance recovery.** Only succeeds when both PIN and PUK batches are exhausted. Otherwise returns `EmergencyResetNotPermitted` with the actual tries remaining. Destroys user ECC keys, resets PIN to `0000`, generates fresh PUK (returned). No PIN required. |
| `0x0E` | ReadSlotBlock    | `slot: u8, block: u8`                                         | Reads one 32-byte block of a data slot. The chip enforces slot policy (private ECC slots refuse). No PIN required. Mostly for bring-up diagnostics and reading the IO key before lock. |
| `0x0F` | ReadSlotWord     | `slot: u8, block: u8, offset_words: u8`                       | Same as `ReadSlotBlock` but returns a 4-byte word. `offset_words` is in 0..=7.                |
| `0x10` | WriteConfigZone  | `block: u8, data: [u8; 32]`                                   | Writes one 32-byte block of the configuration zone. Host issues 4 times. Reversible only while the config zone is unlocked. |
| `0x11` | ProvisionSlot    | `slot: u8, value: [u8; 32]`                                   | Writes a 32-byte cleartext value into a data slot. Only accepted for slots 5 (PIN hash), 6 (PUK hash), and 8 (IO key). Only legal while the data zone is unlocked. |
| `0x12` | ProvisionInitialPin | empty                                                      | Writes `SHA-256("0000" \|\| pin_salt)` into slot 5. The salt is derived on-chip from the chip serial; the host does not need to compute it. Only legal while the data zone is unlocked. |
| `0x13` | ProvisionInitialPuk | empty                                                      | Generates a random 8-digit PUK from the chip RNG, writes `SHA-256(puk \|\| puk_salt)` into slot 6, and returns the PUK in the response payload. **One-time** read of the PUK. |
| `0x14` | ProvisionIoKey   | empty                                                         | Generates 32 random bytes via the chip RNG, writes them into slot 8, and returns the value in the response payload. **One-time** read of the IO key. The host must persist it. |
| `0x15` | ReadCounter      | `id: u8` (0 or 1)                                             | Reads the current value of `Counter0` (PIN attempts, `id=0`) or `Counter1` (PUK attempts, `id=1`). Returns the 8-byte raw counter encoding. The CLI decodes it via the algorithm in `tools/config-generator/src/counter_encoding.rs`. |
| `0xF0` | LockConfigZone   | `magic: [u8; 4], crc: [u8; 2]`                                | **Irreversible.** Host reads the current configuration zone, computes the CRC-16 over the full 128 bytes, and passes it here. The chip recomputes the same CRC and refuses the command if it has drifted. |
| `0xF1` | LockDataZone     | `magic: [u8; 4]`                                              | **Irreversible.** No CRC: secret-bearing slots (`IsSecret=1`) cannot be read back to compute one. The double-confirmation in the host CLI and the magic-word check are the only guards. |
| `0xF2` | LockSlot         | `magic: [u8; 4], slot: u8`                                    | **Irreversible.** Permanently freezes one slot. Requires `KeyConfig.Lockable=1` on that slot. |

The CRC passed with `LockConfigZone` is computed by the host CLI from
a fresh `ReadConfigZone` of the chip, over the full 128 bytes (factory
area included). It is not a constant: bytes 0..16 of the configuration
zone vary per chip. See `tools/hsm-host/src/main.rs::cmd_lock_config_dangerous`.

The "magic" word on Lock commands is a fixed 4-byte sentinel checked by
the firmware before issuing the chip's `Lock` command. It is a final
sanity guard against bit-flips in the USB report or a host CLI that
forgot to pass the confirmation flag. The current values are:
- `LockConfigZone` magic: `0xDE 0xAD 0xBE 0xEF`
- `LockDataZone` magic:   `0xCA 0xFE 0xBA 0xBE`
- `LockSlot` magic:       `0xF0 0x0D 0xCA 0xFE`

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

## Opcode ranges

The opcode space is organised in three contiguous blocks. The current
allocation:

- `0x01..=0x0F` — **Runtime operations.** Read-only inspection, signing,
  PIN/PUK session management, and last-chance recovery. Safe to call at
  any point after the chip has been provisioned and both zones locked.
- `0x10..=0x1F` — **Provisioning operations.** Only effective while the
  relevant zone is unlocked. Sequenced once at the chip's first boot
  and never again in normal operation. The firmware accepts them at
  any time; the chip is the actual gate (it returns an error after lock).
- `0xF0..=0xFF` — **Destructive / irreversible operations** (zone and
  slot locks). Protected by per-opcode magic words and, on the host
  side, by interactive double-confirmation prompts.

Unassigned opcodes inside each range are available for future use. The
firmware returns `InvalidCommand` (`0x01`) for any unknown opcode.

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

Host CLI sequence before sending the command:
1. Issue four `ReadConfigZone(block)` calls and concatenate the
   128 bytes returned.
2. Compute the CRC-16/ATECC over those 128 bytes. For example, if the
   value comes out to `0xC92D`, encode it little-endian as `2D C9`.
3. Print the CRC in a double-confirmation prompt and wait for the user
   to type the magic phrase.

Host -> token:
```
F0 06 00 DE AD BE EF 2D C9 <padding>
```
(`LockConfigZone` with magic `DE AD BE EF` and `crc = 0xC92D` encoded
little-endian as `2D C9`.)

The firmware:
1. Validates the magic word. If wrong, respond `08 LockMagicMismatch`.
2. Forwards the supplied CRC to the chip in the `Lock(config)` command.
3. The chip recomputes the CRC of its own current configuration and
   refuses if it disagrees. The firmware surfaces this as `09
   LockCrcMismatch` for the host.
4. On success, respond `Ok`.