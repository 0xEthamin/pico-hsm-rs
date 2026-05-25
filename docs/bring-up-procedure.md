# Bring-up procedure

This is the prescribed order in which to take a fresh ATECC608B-SSHDA-T
from sealed bag to working dongle. Every phase has an exit criterion. Do
not advance until it is met.

**No `Lock` command is ever issued automatically.** Every irreversible
step requires explicit operator action with a confirmation argument.

## Phase 0: bench safety

Have at least **two** spare ATECC608B-SSHDA-T chips on hand. Phase 4 may
brick one or two while you iterate on the configuration zone. The
sacrificial chip used for the first config-lock is gone forever once you
issue `LockConfigZone`. Be sure the configuration is correct before that
moment.

## Phase 1: communication (any chip)

1. Solder the chip, the 2.2 kOhm I2C pull-up resistors, and connect it
   to a Pico H. SDA on GP4, SCL on GP5.
2. Flash `hsm-firmware` (currently the blinky scaffold).
3. Replace the blinky with the bring-up sketch: wake then Info then
   `Read(Config, block=0)`. The sketch logs over `defmt-rtt`.
4. Read the defmt log via `probe-rs attach`.

**Exit criterion:**
- The chip replies to the wake pulse with `04 11 33 43`.
- `Info(Revision)` returns `00 00 60 02` (M0) or `00 00 60 03` (M1) or
  `00 00 60 04` (M2). For an SSHDA-T, M0 is expected.
- `Read(Config, block=0)` returns 32 bytes where byte 12 is `0xEE`. The
  9-byte chip serial is `bytes[0..4] || bytes[8..12] || 0xEE`.

This phase **never writes** to the chip. It remains in pristine, fully
re-provisionable state.

## Phase 2: read configuration zone (still pristine)

Run `hsm-host read-config`. The 128 bytes should match the factory
default for an ATECC608B-SSHDA. Note byte 16 (`I2C_Address`) and byte 87
(`LockConfig`). The latter must be `0x55` (unlocked).

This phase also reads no slot data, only the configuration zone.

## Phase 3: write configuration zone (same chip)

1. Generate the mini-HSM configuration blob:
   ```
   cargo run -p config-generator -- --output config_zone.bin --annotate
   ```
   Inspect `config_zone.txt` and confirm the slot table matches
   `docs/config-zone-layout.md`. Confirm the CRC-16 reported by the
   generator is `0xC92D`.
2. Send the writable portion to the chip:
   ```
   hsm-host write-config --path config_zone.bin
   ```
   The host CLI splits the writable portion into four 32-byte blocks and
   issues four `WriteConfigZone` HID commands (one per block).
3. Read back:
   ```
   hsm-host read-config
   ```
   Bytes 16-127 must match `config_zone.bin` bytes 16-127. Bytes 0-15
   are the read-only factory area and are returned with the chip's
   actual factory values.

Iterate freely as long as the configuration zone is unlocked. Cleartext
writes to slots 5 and 6 (PIN, PUK hashes) and to slot 8 (I/O master key)
are not yet allowed at this stage because the data zone is also unlocked
but the `Write` command needs the config zone locked first for any
non-config write to take effect on slots with `IsSecret=1`. So this
phase only writes configuration, not slot data.

## Phase 4: lock configuration zone (sacrificial chip)

This step is irreversible.

1. Switch to a **different** chip from Phase 1-3. This second chip will
   be the one we lock. The first chip can stay pristine as a backup.
2. Repeat phases 1, 2, and 3 on this second chip.
3. Compute and confirm the CRC of the writable portion:
   ```
   cargo run -p config-generator -- --crc-only
   ```
   Expected output: `0xC92D`.
4. With deliberate intent, invoke:
   ```
   hsm-host lock-config-DANGEROUS --expected-crc 0xC92D
   ```
   The CLI prompts twice for confirmation. Read each prompt fully before
   responding. The firmware verifies that the configuration zone on the
   chip CRCs to `0xC92D` before issuing the chip's `Lock(config)`
   command. If the CRC does not match, the firmware refuses.

**Exit criterion:** the chip's `LockConfig` byte (offset 87) reads
`0x00`. `Info(State)` reports the configuration zone as locked.
`GenKey(slot=0)` now succeeds (it was failing before the lock because
`Lock(config)` is a prerequisite for ECC key derivation).

## Phase 5: provision slot data (same chip, data zone still unlocked)

In order:

1. Read the chip serial via `Read(Config, block=0)` and derive the I/O
   Protection master key as `SHA-256(chip_serial || firmware_pepper)`.
2. Write the I/O master key into slot 8 in cleartext via `Write(Data,
   slot=8)`. The slot's `WriteConfig=Always` allows it because the data
   zone is still unlocked.
3. Compute the initial PIN hash: `SHA-256("0000" || pin_salt)` with
   `pin_salt = b"mini-hsm-pin-salt-v1"`.
4. Write the PIN hash into slot 5 in cleartext via `Write(Data,
   slot=5)`. The slot's `WriteConfig=Always_then_Encrypt` allows
   cleartext writes pre-lock.
5. Generate a random 8-digit PUK and compute
   `SHA-256(puk || puk_salt)` with `puk_salt = b"mini-hsm-puk-salt-v1"`.
6. Write the PUK hash into slot 6 in cleartext.
7. Display the chosen PUK to the operator via the host CLI. The PUK is
   not retained anywhere else; the operator records it in a password
   manager. Losing the PUK means losing the ability to reset a forgotten
   PIN. The chip remains usable for signing as long as the user remembers
   their PIN.
8. Issue `GenKey(slot=0)` to materialize the primary identity key
   pair. Record the resulting public key alongside this chip's serial.

## Phase 6: end-to-end smoke test (same chip)

- `hsm-host verify-pin --pin 0000` should succeed (PIN session opens).
- `hsm-host sign --slot 0 --challenge $(openssl rand -hex 32)` should
  light up the yellow LED, wait for a touch on the button, then return a
  64-byte signature `R || S`.
- Verify the signature off-chip with the `p256` crate (or `openssl
  ecdsa_verify`) using the public key recorded in Phase 5. The
  verification must succeed.
- Repeat with PIN `1234` to confirm `SetPin` works (change the PIN, then
  re-verify with the new PIN).

## Phase 7: lock data zone (optional, deferred to demo day)

Until this step is run, slots 5, 6, and 8 can still be re-provisioned by
re-running Phase 5. **Do not run `Lock(data)` during development.**

When the project is ready for permanent deployment:

```
hsm-host lock-data-DANGEROUS
```

The CLI prompts for confirmation. After this:
- Slot 8 (I/O master key) becomes immutable.
- Slots 5 and 6 (PIN, PUK hashes) can only be updated through encrypted
  writes via slot 8, which the firmware handles internally for `SetPin`,
  `SetPuk`, `UnblockPin`, and `FactoryReset`.

It is recommended to defer this phase until the firmware is feature-frozen
to retain the option of re-provisioning during late changes.

## Phase 8: optional individual slot locks

If a particular slot (for example, an attestation key in slot 10) needs
to be permanently frozen, issue `Lock(mode=slot, slot=N)` once the slot
has the desired contents. The slot's `KeyConfig.Lockable` must be 1 for
this to work. Slots 0 and 1 have `Lockable=0` deliberately, to keep
identity key rotation available for the life of the device.
