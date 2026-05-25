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
3. As a final sanity check, run `hsm-host read-config` and bit-compare
   bytes 16-127 against the writable portion of `config_zone.bin`. They
   must match exactly.
4. With deliberate intent, invoke:
   ```
   hsm-host lock-config-DANGEROUS
   ```
   The CLI reads the chip's current configuration zone, computes the
   CRC-16 over the full 128 bytes (factory area included), and prints
   the result inside the double-confirmation prompt. Read the prompt
   fully, verify the displayed CRC against your expectations, then type
   the confirmation phrase. The firmware passes the CRC to the chip's
   `Lock(config)` command, which recomputes it one last time and refuses
   if the data has drifted between the read and the lock.

**Exit criterion:** the chip's `LockConfig` byte (offset 87) reads
`0x00`. `Info(State)` reports the configuration zone as locked.
`GenKey(slot=0)` now succeeds (it was failing before the lock because
`Lock(config)` is a prerequisite for ECC key derivation).

## Phase 5: provision slot data (same chip, data zone still unlocked)

The host CLI orchestrates this phase as one command. Running it
end-to-end is the recommended path. The individual building blocks are
also exposed as opcodes for diagnostics.

### Recommended path: `provision-token`

```
hsm-host provision-token --secrets-file ./secrets-<chip-serial>.json
```

This issues, in order:

1. `ProvisionInitialPin`. The firmware computes
   `SHA-256("0000" || pin_salt)` on the chip's hash engine and writes
   the result into slot 5 (cleartext, allowed because the data zone is
   still unlocked).
2. `ProvisionInitialPuk`. The firmware draws 8 ASCII digits from the
   chip's RNG to make a PUK, computes `SHA-256(puk || puk_salt)` on the
   chip, writes the hash into slot 6, and returns the cleartext PUK in
   the response. **This is the only opportunity** to read the PUK.
3. `ProvisionIoKey`. The firmware draws 32 random bytes from the chip's
   RNG, writes them into slot 8 with `IsSecret=1`, and returns the
   cleartext value in the response. **This is the only opportunity** to
   read the I/O master key.
4. `GenKey(slot=0)` to materialise the primary identity key pair.

The CLI then writes a JSON secrets file containing the PUK, the I/O
master key, the chip serial, and the slot-0 public key. **Read this
file once and back it up to a password manager.** Losing the I/O
master key locks you out of every encrypted operation (`SetPin`,
`SetPuk`, `UnblockPin`, `EmergencyReset`). Losing the PUK locks you
out of `UnblockPin` if the PIN is forgotten.

### Notes on the secrets

The I/O master key is **pure random output from the chip's RNG**, not
derived from the chip serial or any host-side input. The firmware
holds no recoverable secret of its own, and the host CLI cannot
regenerate the I/O key after this phase. If you do not record what
`provision-token` returns, the only path forward is to throw the chip
away.

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

The CLI prompts for a typed confirmation. No CRC is asked for: the
secret-bearing slots (`IsSecret=1`) cannot be read back to compute one,
so the magic-word check in the firmware and the interactive prompt are
the only safety. After this:

- Slot 8 (I/O master key) becomes immutable.
- Slots 5 and 6 (PIN, PUK hashes) can only be updated through encrypted
  writes via slot 8, which the firmware handles internally for `SetPin`,
  `SetPuk`, `UnblockPin`, and `EmergencyReset`.

It is recommended to defer this phase until the firmware is feature-frozen
to retain the option of re-provisioning during late changes.

## Phase 8: optional individual slot locks

If a particular slot (for example, an attestation key in slot 10) needs
to be permanently frozen, issue `Lock(mode=slot, slot=N)` once the slot
has the desired contents. The slot's `KeyConfig.Lockable` must be 1 for
this to work. Slots 0 and 1 have `Lockable=0` deliberately, to keep
identity key rotation available for the life of the device.
