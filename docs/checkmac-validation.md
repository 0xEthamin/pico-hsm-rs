# Validating the host-side CheckMac formula

## Why this document exists

The PIN and PUK verification flow of this project relies on a 32-byte
"client response" computed on the host that the ATECC chip must
reproduce byte-for-byte during a `CheckMac` command. If the host's
formula differs from the chip's by a single bit, every `verify_pin`
call will fail with a generic `CheckMacOrVerifyFailed` error and there
is **no way to introspect the chip-side computation** to find out
which byte is wrong.

The formula lives in `crates/hsm-crypto-service/src/pin.rs`,
function `checkmac_response`. It was written from a reading of the
ATECC608B summary datasheet and CryptoAuthLib's source. The reading
is plausibly correct but has never been validated end-to-end.

This document describes two validation procedures. Either one is
sufficient. The first is faster but requires a Linux host with a real
C toolchain. The second is slower but works with the chip alone.


## Approach A: compile CryptoAuthLib in C and compare digests

This is the highest-confidence approach, because it compares our pure
Rust function against the same code base the ATECC firmware was
specified against.

### Prerequisites

- A Linux host with `gcc`, `make`, and `cmake`.
- Network access to fetch the CryptoAuthLib source from
  <https://github.com/MicrochipTech/cryptoauthlib>.

### Steps

1. Clone CryptoAuthLib and build it as a host library (`CMakeLists.txt`
   ships a `linux-kit` build that exposes the crypto helpers without
   needing a chip):

   ```sh
   git clone --depth=1 https://github.com/MicrochipTech/cryptoauthlib
   cd cryptoauthlib
   mkdir build && cd build
   cmake -DATCA_BUILD_SHARED_LIBS=ON -DATCA_HAL_KIT_HID=OFF ..
   make -j$(nproc) cryptoauth
   ```

2. Write a small C program (`tools/checkmac-oracle/main.c`, not in
   this repo) that calls
   `atcah_check_mac` from `lib/host/atca_host.c` with a fixed input
   and prints the 32-byte output as hex:

   ```c
   #include <stdio.h>
   #include <string.h>
   #include "host/atca_host.h"

   int main(void) {
       struct atca_check_mac_in_out p = {0};
       uint8_t slot_value[32];   memset(slot_value, 0xAA, 32);
       uint8_t challenge[32];    memset(challenge, 0xBB, 32);
       uint8_t other_data[13];   memset(other_data, 0xCC, 13);
       uint8_t sn[9];            memset(sn, 0xDD, 9);
       uint8_t client_resp[32];

       p.mode         = 0;       // CheckMac mode 0
       p.key_id       = 5;       // PIN slot
       p.client_chal  = challenge;
       p.client_resp  = client_resp;
       p.other_data   = other_data;
       p.otp          = NULL;    // not used
       p.sn           = sn;
       p.slot_key     = slot_value;
       p.target_key   = NULL;

       atcah_check_mac(&p);

       for (int i = 0; i < 32; i++) printf("%02x", client_resp[i]);
       printf("\n");
       return 0;
   }
   ```

3. Compile and run:

   ```sh
   gcc main.c -L cryptoauthlib/build/lib -l cryptoauth -o oracle
   LD_LIBRARY_PATH=cryptoauthlib/build/lib ./oracle
   ```

4. Compare the printed digest against the Rust function:

   ```sh
   cd mini-hsm
   cat > /tmp/oracle_compare.rs << 'EOF'
   use hsm_crypto_service::pin::checkmac_response;
   fn main() {
       let slot_value = [0xAAu8; 32];
       let challenge  = [0xBBu8; 32];
       let other_data = [0xCCu8; 13];
       let sn         = [0xDDu8; 9];
       let r = checkmac_response(&slot_value, &challenge, &other_data, &sn);
       for b in r { print!("{:02x}", b); }
       println!();
   }
   EOF
   # add this as an example or a quick #[test] and run it
   cargo test -p hsm-crypto-service checkmac_oracle -- --nocapture
   ```

   Both digests must match byte-for-byte. If they do not, the discrepancy
   tells us which part of the formula in `checkmac_response` is off.

### Triage when digests differ

The most common discrepancy is the layout of the serial bytes mixed
into the hash. As of CryptoAuthLib `lib/calib/calib_command.c`, the
ATECC pulls `SN[8]` (one byte at chip address 9, i.e. `chip_serial[8]`
in the 9-byte serial) and `SN[0..2]` (the two low bytes of the serial,
i.e. `chip_serial[0..2]`). Our `checkmac_response` mirrors this with
`chip_serial[8..9]` and `chip_serial[0..2]`. Off-by-one indices on
these slices produce a completely different digest. Walk through the
slice operations in `checkmac_response` against the C source line by
line.


## Approach B: validate on the chip itself, no C toolchain

Slower but requires only the chip on a breadboard and the firmware
already in this project. The idea is to write a known 32-byte value
into slot 5 **in cleartext** while the data zone is still unlocked,
then run a `CheckMac` against it using the host formula. If the
formula is correct, the CheckMac call returns success; if not, it
returns failure.

This works only because writes to an unlocked data zone are
unauthenticated (no encryption, no MAC).

### Prerequisites

- A provisioned chip with the config zone locked but the data zone
  still unlocked. The `tools/config-generator` output written via
  `WriteConfig` brings us to this state.
- The firmware built with a temporary debug subcommand that performs
  the test described below.

### Steps

1. Pick a known 32-byte value, e.g. all `0x11`. Write it as cleartext
   into slot 5 via `Atecc::write_32(Zone::Data, data_address(slot5, 0, 0), &value)`.
   This call works only while the data zone is unlocked.

2. Read it back via `Atecc::read_32(Zone::Data, ...)` and verify the
   chip stored it correctly.

3. Compute the expected `client_resp` on the host:
   - `slot_value = [0x11; 32]`
   - `challenge = <random 32 bytes>` (or fixed, doesn't matter)
   - `other_data = checkmac_other_data(5, &chip_serial)`
   - `client_resp = checkmac_response(&slot_value, &challenge, &other_data, &chip_serial)`

4. Call `Atecc::checkmac(slot5, &challenge, &client_resp, &other_data).await`.

5. Outcome:
   - `Ok(true)` -> the formula is correct. Proceed to lock the data
     zone and finish provisioning.
   - `Ok(false)` -> the formula is wrong. Inspect the serial byte
     layout in `checkmac_response`.
   - `Err(_)` -> a chip or transport error unrelated to the formula.

### Important constraints

- **Do not lock the data zone until validation passes.** Once locked,
  slot 5 can only be written via the encrypted-write flow, which
  itself depends on the IO key being present and correctly written.
  Iterating on the CheckMac formula after a data lock is impractical.

- **Counter0 is incremented by each `CheckMac` call** even during
  testing. Allow several attempts in the slot's LimitedUse budget.
  With our default of 5, three or four iterations on the formula is
  the practical limit before the counter blocks further verifies.
  If that happens, `unblock_pin` via the PUK still works because the
  PUK uses Counter1, but iterating becomes painful. A way out is to
  write a relaxed `SlotConfig` for slot 5 during the validation phase
  (`LimitedUse=0`) and rewrite the production config after validation.


## Recommended path for this project

Use **Approach A** if you have a Linux dev box at hand. The round
trip is short (15 minutes once the C build is set up) and it
generalises: the oracle program can later validate the encrypted
write MAC formula too, by calling `atcah_write_auth_mac` and
comparing against `encrypted_write::write_mac`.

Fall back to **Approach B** only if the C toolchain is unavailable.
It is sufficient on its own but slower and more sensitive to chip
state.

If neither path validates the formula, the project is not safe to
ship: PIN verification cannot work without a correct `client_resp`,
and there is no fail-open mode that would let the chip be unlocked
without it.
