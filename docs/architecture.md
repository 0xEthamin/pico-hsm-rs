# Architecture

This document captures the design decisions made before any line of firmware
code was written. It is the contract between the layers. If you have to
deviate from it during implementation, change *this* file first, then the
code.

## Goals

- A USB dongle that signs door-unlock challenges only after verifying a PIN
  and observing a physical touch.
- The private key never leaves the ATECC608B chip.
- The PIN is verified hardware-side by the chip (`CheckMac` against a
  dedicated slot), with hardware-enforced retry limits.
- Everything user-facing is reversible *except* the deliberate use of the
  `Lock` commands.

## Layered breakdown

```
------------------------------------------------------------------------
|  L6 - Application / state machine                                    |
|       (`crates/hsm-firmware/src/state_machine.rs`)                   |
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
layer's trait. This is what makes the whole stack testable on a laptop with
`cargo test`: every layer can be exercised against a mock of the one beneath.

## Slot allocation

See [`crates/hsm-crypto-service/src/slots.rs`](../crates/hsm-crypto-service/src/slots.rs)
for the canonical mapping. Summary:

- Slot 0     - primary P-256 identity, PIN-gated.
- Slots 1-4  - P-256 reserve, PIN-gated.
- Slot 5     - PIN hash (`SHA-256(PIN || salt)`).
- Slot 6     - PUK hash (`SHA-256(PUK || salt2)`).
- Slot 7     - reserved.
- Slot 8     - I/O protection master key.
- Slots 9-15 - reserved.

## Security model

| Threat                                  | Mitigation                                                  |
|-----------------------------------------|-------------------------------------------------------------|
| Stolen token, attacker tries to sign    | Hardware-enforced PIN (`ReqAuth`) on slot 0 + 5 PIN tries.  |
| Stolen token + observed PIN             | Touch-to-sign: physical button needed for every signature.  |
| Attacker desolders chip and probes I2C  | Private key never leaves the chip; `IsSecret=1` slot.       |
| Attacker dumps RP2040 flash             | I/O master key is derived from chip serial + firmware-side pepper. Useless without the physical chip. |
| Attacker brute-forces PIN over USB      | Counter0 caps at 5 tries hardware-side, slot self-disables. |
| Repeated PUK guessing                   | Counter1 caps at 10 PUK tries; chip bricked beyond that.    |

## State machine

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
                    |     |   Authenticated    |  (green + slow pulse)
                    |     |   30 s session     |
                    |     ----------------------
                    |       | timeout  | Sign cmd
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

## What is intentionally out of scope

- Attestation certificates.
- Multi-user enrollment workflow (slots 1-4 reserved, no UI yet).
- Secure firmware updates (the device is flashed via the Pico's BOOTSEL
  button. This is acceptable for a hackathon device).
- Tamper response (the dongle has no tamper detection).
