# mini-hsm

Open-source mini HSM (Hardware Security Module) in the form of a USB
dongle, built around the Raspberry Pi Pico (RP2040) and the Microchip
ATECC608B secure element. Used to authenticate the opening of a
connected door lock through a PIN plus touch-to-sign challenge/response
protocol.

Developed for the Maker Days 2026 hackathon by Garage Isep.

## Quick links

- [Architecture overview](docs/architecture.md)
- [Configuration zone layout](docs/config-zone-layout.md)
- [USB-HID protocol](docs/usb-hid-protocol.md)
- [Bring-up procedure](docs/bring-up-procedure.md)

## Repository layout

```
mini-hsm/
|-- crates/
|   |-- atecc608b/          # no_std driver for the ATECC608B, generic over a HAL trait.
|   |-- hsm-crypto-service/ # Business logic: slot conventions, sign workflow, PIN/PUK verification.
|   |-- hsm-usb-protocol/   # HID command/response encoding, shared between firmware and host CLI.
|   |-- hsm-firmware-logic/ # Host-testable parts of the firmware (state machine, button debouncer).
|   |-- hsm-firmware/       # The firmware binary for RP2040. Links the other crates together.
|-- tools/
|   |-- hsm-host/           # CLI utility on the host PC to talk to the token over USB-HID.
|   |-- config-generator/   # Produces the 128-byte ATECC608B configuration zone blob.
|-- docs/
```

## How to build

```bash
# Host-side unit and integration tests for the no_std crates (no hardware required):
cargo test

# Firmware (cross-compiled for thumbv6m-none-eabi via the workspace alias):
cargo firmware-build

# Host CLI:
cargo build -p hsm-host --release
```

The workspace has `default-members` set so a bare `cargo` command does
not try to compile the firmware crate for the host target. Use the
`firmware-build` / `firmware-check` / `firmware-run` aliases (defined in
`.cargo/config.toml`) to operate on the firmware.

## Security model in one paragraph

The token holds an ECDSA P-256 private key, generated on-chip and never
extractable. Every signature requires both a valid PIN (verified
hardware-side through a CheckMac on a dedicated slot) and a physical
touch on the device's button. The PIN is rate-limited by the chip's
monotonic counter. After five failures, only the PUK (set during
provisioning) can unblock it. The PUK in turn is rate-limited; if it
gets exhausted, the chip remains usable for signing as long as the user
remembers their PIN, but PIN recovery becomes unavailable. Slots 0 and
1 are configured for `GenKey`-only access, so the user can rotate the
identity key at any time but cannot import an external one.

## Provisioning state

The chip is shipped blank by Microchip (the `-SSHDA` variant). Before
the dongle can be used, an operator must:

1. Generate the configuration blob via `cargo run -p config-generator`.
2. Write it to the chip via `hsm-host write-config`.
3. Lock the configuration zone via `hsm-host lock-config-DANGEROUS
   --expected-crc 0xCB23`. **This is irreversible.**
4. Provision the I/O master key in slot 8, the PIN hash in slot 5, the
   PUK hash in slot 6, and generate the primary identity key with
   `GenKey(slot=0)`.
5. Optionally, lock the data zone for permanent hardening, or defer that
   step indefinitely.

See [`docs/bring-up-procedure.md`](docs/bring-up-procedure.md) for the
full step-by-step walk-through.

## License

This entire workspace (including the firmware, the host tools, and the ATECC608B driver) is open-source and licensed under the **GNU General Public License v3.0 or later** ([GPL-3.0-or-later](LICENSE)). 

This strong copyleft license ensures that any modifications, improvements, or products built upon this project remain open-source and freely available to the community.

### Commercial Licensing

If you wish to integrate this project—whether it's the HSM firmware logic, the architecture, or the driver—into a proprietary, closed-source commercial product (and therefore cannot comply with the GPLv3 requirement to open-source your entire product), please contact me to discuss a **Commercial License**. 

Contact: `perso@simontuloup.fr`