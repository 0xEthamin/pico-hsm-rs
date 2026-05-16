# mini-hsm

Open-source mini HSM (Hardware Security Module) in the form of a USB dongle,
built around the Raspberry Pi Pico (RP2040) and the Microchip ATECC608B secure
element. Used to authenticate the opening of a connected door lock through a
PIN + touch-to-sign challenge/response protocol.

Developed for the Maker Days 2026 hackathon by Garage Isep.

## Quick links

- [Architecture overview](docs/architecture.md)
- [Config zone layout](docs/config-zone-layout.md)
- [USB-HID protocol](docs/usb-hid-protocol.md)
- [Bring-up procedure](docs/bring-up-procedure.md)

## Repository layout

```
mini-hsm/
|-- crates/
|   |-- atecc608b/          # Pure no_std driver for the ATECC608B, generic over a HAL trait.
|   |-- hsm-crypto-service/ # Business logic: slot conventions, sign workflow, PIN verification.
|   |-- hsm-usb-protocol/   # HID command/response encoding, shared between firmware and host.
|   |__ hsm-firmware/       # The firmware binary for RP2040: glues everything together.
|-- tools/
|   |-- hsm-host/           # CLI utility on the host PC to talk to the token over USB-HID.
|   |__ config-generator/   # Produces the 128-byte ATECC608B config blob.
|__ docs/
```

## How to build

```bash
# Host-side unit tests for the no_std crates (no hardware required):
cargo test -p atecc608b -p hsm-crypto-service -p hsm-usb-protocol

# Firmware (cross-compiled for thumbv6m-none-eabi):
cargo build -p hsm-firmware --release

# Host CLI:
cargo build -p hsm-host --release
```

## Security model in one paragraph

The token holds an ECDSA P-256 private key, generated on-chip and never
extractable. Every signature requires both a valid PIN (verified hardware-side
through a CheckMac on a dedicated slot) and a physical touch on the device's
button. The PIN is rate-limited by the chip's monotonic counter. After five
failures, only the PUK (set during provisioning) can unblock it.
