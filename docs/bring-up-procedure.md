# Bring-up procedure

This is the prescribed order in which to bring a fresh ATECC608B-SSHDA up to
"working dongle". Every step has an exit criterion. Do not advance until it
is met. **No `Lock` command is ever issued automatically.**

## Phase 0 - Bench safety

Have at least **two** spare ATECC608B-SSHDA chips on hand. Phase 4 may brick
one or two of them while we iterate on the config zone.

## Phase 1 - Communication (any chip)

1. Solder the chip, the 2.2 kOhm pull-ups, and connect it to a Pico H.
2. Flash `hsm-firmware` (currently = blinky).
3. Replace the blinky with the test sketch (TBD): wake + Info.
4. Read the defmt log via `probe-rs attach`.

**Exit criterion:** the chip replies to wake with `04 11 33 43` and `Info`
returns revision `00 00 60 02` (or `60 03`).

This phase **never writes** to the chip. The chip remains in pristine state.

## Phase 2 - Read config zone (same chip, still pristine)

Run `hsm-host read-config`. The 128-byte dump should match the factory
default for ATECC608B-SSHDA.

## Phase 3 - Write config zone (same chip)

1. Generate the desired blob: `cargo run -p config-generator -- --output config.bin`.
2. `hsm-host write-config --path config.bin`.
3. `hsm-host read-config` again. The writable bytes must now match `config.bin`.

Iterate freely: as long as the config zone is unlocked, you can rewrite it.

## Phase 4 - Lock config zone (sacrificial chip)

Once the config is satisfactory:

1. Switch to a **different** chip (this one will be irrevocably altered).
2. Repeat phases 1 through 3 on it.
3. Compute the CRC-16 of the config you intend to lock:
   `cargo run -p config-generator -- --crc-only --path config.bin`.
4. Manually invoke
   `hsm-host lock-config-DANGEROUS --expected-crc <crc>`.
5. The CLI prompts for confirmation twice. Read the prompts. Then accept.

**Exit criterion:** `GenKey(slot=0)` now works (it fails before
`lock(config)`).

## Phase 5 - Provision keys, slots 5 / 6 / 8

In order, on the chip from Phase 4:

1. Write the I/O master key into slot 8 (in cleartext, since the slot is
   `Write=Always` before data zone lock).
2. Write the PIN hash into slot 5 (encrypted with the I/O key).
3. Write the PUK hash into slot 6 (encrypted with the I/O key).
4. `GenKey(slot=0)` to materialize the primary identity.
5. Record the resulting public key.

## Phase 6 - End-to-end smoke test (same chip)

- `hsm-host verify-pin --pin 0000` should succeed.
- `hsm-host sign --slot 0 --challenge $(openssl rand -hex 32)` should
  emit the yellow LED, wait for a touch, then return a 64-byte signature.
- Verify it off-chip with `openssl ec_verify` or the `p256` crate using the
  public key from phase 5.

## Phase 7 - Lock data zone (optional, deferred to demo day)

Until this step is done, slots 5 and 6 can still be re-provisioned by
re-running phase 5. **Lock(data) should not be executed during development.**

When it is finally executed, run `hsm-host lock-data-DANGEROUS` and read the
two confirmation prompts. After this, slot 8 / 5 / 6 are immutable.
