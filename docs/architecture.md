# Architecture

This document captures the design of the mini-HSM project. It is the
contract between the layers. If implementation drifts away from this
document, update the document first, then the code.

## Goals

- A USB dongle that signs door-unlock challenges only after verifying a PIN
  and observing a physical touch.
- The private key never leaves the ATECC608B chip.
- The PIN is verified hardware-side by the chip (`CheckMac` against a
  dedicated slot), with hardware-enforced retry limits.
- User-facing keys are user-replaceable. Only the deliberate use of the
  `Lock` commands or `Lock(slot=N)` on a slot with `Lockable=1` is
  irreversible.

## Layered breakdown

```
------------------------------------------------------------------------
|  L6 - Application / state machine                                    |
|       (`crates/hsm-firmware-logic/src/state_machine.rs`)             |
|  L5 - USB-HID protocol (`crates/hsm-usb-protocol`)                   |
|  L4 - Crypto service (`crates/hsm-crypto-service`)                   |
|  L3 - ATECC608B high-level commands (`crates/atecc608b/src/command`) |
|  L2 - ATECC608B packet layer (`crates/atecc608b/src/{crc,packet}`)   |
|  L1 - HAL trait + RP2040 impl (`atecc608b/src/hal.rs` +              |
|                                 `hsm-firmware/src/hal_rp2040.rs`)    |
|  L0 - Embassy runtime + embassy-rp peripherals                       |
------------------------------------------------------------------------
```

A layer may only depend on the one directly below it, through that lower
layer's trait. The crate split enforces it physically: `atecc608b` has no
notion of USB, `hsm-crypto-service` has no notion of GPIO. The result is
that every layer can be exercised on a laptop with `cargo test`, with a
mock implementation of the layer beneath.

The crate `hsm-firmware-logic` exists so the parts of the application
that are pure logic (state machine, debouncer, LED and button
abstractions) can be tested on the host without pulling in `embassy-rp`.
The `hsm-firmware` binary depends on `hsm-firmware-logic` and supplies
the hardware-facing trait implementations.

## Slot allocation

The chip has 16 slots. The mini-HSM uses them as follows. The canonical
reference is `docs/config-zone-layout.md`.

| Slot  | Role                                | Type           | Replaceable by user?              |
|-------|-------------------------------------|----------------|-----------------------------------|
| 0     | Primary identity, GenKey-only       | ECC P-256      | Yes via GenKey (no import).       |
| 1     | Secondary identity, GenKey-only     | ECC P-256      | Yes via GenKey (no import).       |
| 2-4   | User key, GenKey or encrypted import| ECC P-256      | Yes via GenKey or PrivWrite.      |
| 5     | PIN hash                            | 32 bytes data  | Yes via SetPin (encrypted post-lock). |
| 6     | PUK hash                            | 32 bytes data  | Yes via SetPuk (encrypted post-lock). |
| 7     | User key, GenKey or encrypted import| ECC P-256      | Yes via GenKey or PrivWrite.      |
| 8     | I/O Protection master key           | 32 bytes data  | No. Written once, immutable post-lock. |
| 9-15  | Reserves for V2                     | ECC P-256      | Yes, configured like slots 2-4.   |

Slots 0 and 1 have `KeyConfig.Lockable = 0`, so they cannot be
individually frozen. They are always regeneratable. Slots 2-4, 7, and
9-15 have `Lockable = 1`. This means an operator can permanently freeze
the key currently in one of these slots via `Lock(mode=slot, slot=N)`,
which is useful if a particular slot is reserved later for an attestation
key or a secure-boot signature.

The PIN slot (5) and PUK slot (6) are configured with
`WriteConfig=Always_then_Encrypt`. The initial PIN and PUK hashes are
written in cleartext during provisioning (before the data zone is locked),
and any later update goes through an encrypted write keyed by slot 8.

## Security model

| Threat                                       | Mitigation                                                                                              |
|----------------------------------------------|---------------------------------------------------------------------------------------------------------|
| Stolen token, attacker tries to sign         | Hardware-enforced PIN via `ReqAuth=1` on slot 0-4, 7, 9-15. Slot 5 blocks after 5 wrong PIN tries.      |
| Stolen token plus observed PIN               | Touch-to-sign: physical button needed for every signature.                                              |
| Attacker desolders chip and probes I2C       | Private key never leaves the chip. `IsSecret=1` on every secret-bearing slot.                           |
| Attacker dumps RP2040 flash                  | I/O master key derived from chip serial plus firmware-side pepper. Useless without the physical chip.   |
| Attacker brute-forces PIN over USB           | Counter0 caps PIN attempts at 5 per cycle, slot self-disables. Refresh of the batch only via PUK.       |
| Repeated PUK guessing                        | Counter1 caps PUK attempts at 10 per cycle. Chip remains usable for signing, only PUK becomes unavailable. |
| Stuck in unrecoverable state after PIN+PUK   | `FactoryReset` regenerates slots 0-4 and 7, resets PIN to default. Counters are not reset (cannot be).  |

The PUK-related risk window is bounded by the 21-bit Counter1: the chip
supports about 2 million ticks. Each PUK reset cycle consumes 10 ticks
(in the worst case of 9 wrong attempts plus the successful one). That
gives roughly 200 000 reset cycles over the chip's lifetime, well beyond
any realistic usage pattern. If the user does exhaust Counter1, the PUK
feature becomes unavailable but the chip continues to work for signing.

## State machine

The token's behavior is driven by an event-driven state machine in
`crates/hsm-firmware-logic/src/state_machine.rs`. Its states are:

```
                  -------------------
                  |     Booting     | (yellow LED blinks)
                  -------------------
                           | init OK
                           v
                  -------------------
                  |       Idle      | (green LED solid)
                  -------------------
                    |       | VerifyPin(ok)
                    |       v
                    |     ----------------------
                    |     |   Authenticated    |  (green slow pulse)
                    |     |   30 s session     |
                    |     ----------------------
                    |       | timeout  | Sign command
                    |       |          v
                    |       |       -------------------
                    |       |       | WaitingForTouch | (yellow LED solid)
                    |       |       -------------------
                    |       |         | touch       | 30 s timeout
                    |       |         v             v
                    |       |       -----------  TouchTimeout -> Idle
                    |       |       | Signing |
                    |       |       -----------
                    ----------------------
                             back to Idle
```

The same state machine handles re-`VerifyPin` while already
`Authenticated` (it extends the session timer), `Sign` commands without
an active PIN session (rejected with `PinRequired`), and a fast Error
recovery path that returns to Idle after about 5 seconds.

## What is intentionally out of scope

- Attestation certificates. Slot 10 is left in the polyvalent "ECC + V2
  reserve" configuration so it can be repurposed later.
- Secure firmware updates. The device is flashed via the Pico BOOTSEL
  button. Acceptable for a hackathon device, deferred for a product
  iteration.
- Tamper response. The dongle has no tamper detection.
- PIN session backed by hardware nonce. The 30 s session is enforced by
  the firmware. A hardware-backed approach (e.g. TempKey lifecycle)
  could be considered if a higher trust level is needed.
