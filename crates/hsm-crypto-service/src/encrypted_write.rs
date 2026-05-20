// Copyright (c) 2026 Tuloup Simon
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

//! Host-side cryptography for the ATECC's encrypted write flow.
//!
//! The chip can write a 32-byte slot only after the host has set up a
//! shared "session key" in `TempKey` via `Nonce` + `GenDig`. The host must
//! then encrypt the new value and produce a MAC that the chip can verify.
//!
//! The full sequence is:
//!
//! 1. Host generates a random 32-byte input and sends it as
//!    `Nonce(passthrough)`. The chip's `TempKey` is now equal to that input.
//! 2. Host issues `GenDig(zone=Data, key_id=io_slot)`. The chip updates
//!    `TempKey` to
//!    `SHA-256(io_key || opcode || param1 || param2 || sn[8] || sn[0..2]
//!     || zeros(25) || TempKey_prev)`.
//! 3. The host can recompute the same `TempKey` because it knows the
//!    `io_key` (passed in at provisioning) and all the other inputs.
//! 4. To write `plaintext` (32 bytes) into `target_slot`, the host sends
//!    `Write` with `data = ciphertext || mac` where:
//!    - `ciphertext[i] = plaintext[i] XOR TempKey[i]`
//!    - `mac = SHA-256(io_key || opcode_write || param1 || param2
//!       || sn[8] || sn[0..2] || zeros(25) || TempKey || plaintext)`
//!
//! The chip recomputes the MAC, validates it, decrypts, and stores.
//!
//! This module exposes the pure host-side helpers. The orchestration
//! against the live chip lives in [`crate::service::CryptoService`].

use atecc608b::command::read_write::data_address;
use atecc608b::Slot;
use sha2::{Digest, Sha256};

/// Length of an ATECC chip serial number in bytes (as read from the
/// config zone).
pub const CHIP_SERIAL_LEN: usize = 9;

/// Length of a slot value (32 bytes).
pub const SLOT_VALUE_LEN: usize = 32;

/// ATECC opcode for `GenDig`.
pub const OP_GENDIG: u8 = 0x15;

/// ATECC opcode for `Write`.
pub const OP_WRITE: u8 = 0x12;

/// Zone byte encoding `Data` in the `GenDig` and Write commands.
pub const ZONE_DATA: u8 = 0x02;

/// Compute the `TempKey` value that the chip ends up with after a
/// `Nonce(passthrough, nonce_input)` followed by
/// `GenDig(zone=Data, key_id=io_slot)`.
///
/// `io_key` is the 32-byte value stored in the I/O Protection slot
/// (slot 8 by convention in this project).
///
/// `nonce_input` is the 32-byte passthrough nonce that was loaded into
/// `TempKey` before the `GenDig`.
///
/// `io_slot` is the slot index of the I/O Protection Key (e.g. 8).
///
/// `chip_serial` is the 9-byte serial number of the chip.
#[must_use]
pub fn derive_session_key
(
    io_key: &[u8; SLOT_VALUE_LEN],
    nonce_input: &[u8; SLOT_VALUE_LEN],
    io_slot: u8,
    chip_serial: &[u8; CHIP_SERIAL_LEN],
) -> [u8; SLOT_VALUE_LEN]
{
    // GenDig parameters that the chip mixes in.
    let param1 = ZONE_DATA;
    let param2_lo = io_slot;
    let param2_hi: u8 = 0x00;

    let mut hasher = Sha256::new();
    // 32 bytes: the slot value (the key itself).
    hasher.update(io_key);
    // Opcode (1 byte), param1 (1), param2 (2 little-endian).
    hasher.update([OP_GENDIG, param1, param2_lo, param2_hi]);
    // SN[8] (1 byte) then SN[0..2] (2 bytes). On the ATECC608B, SN[8] is
    // chip_serial[8]. The byte at index 8 in the 9-byte serial we
    // cache from the config zone. Indices 0..2 are then SN[0] and SN[1].
    // Cross-checked against CryptoAuthLib `atcah_gen_dig`
    // (lib/host/atca_host.c) which reads `param->sn[8]` then
    // `param->sn[0]` then `param->sn[1]`.
    hasher.update(&chip_serial[8..9]);
    hasher.update(&chip_serial[0..2]);
    // 25 zero bytes per the GenDig formula.
    hasher.update([0u8; 25]);
    // Previous TempKey (the nonce input).
    hasher.update(nonce_input);

    let mut out = [0u8; SLOT_VALUE_LEN];
    out.copy_from_slice(hasher.finalize().as_slice());
    out
}

/// XOR-encrypt a 32-byte plaintext with the session key.
///
/// The chip will XOR with the same `TempKey` to recover the plaintext.
#[must_use]
pub fn encrypt_payload
(
    plaintext: &[u8; SLOT_VALUE_LEN],
    session_key: &[u8; SLOT_VALUE_LEN],
) -> [u8; SLOT_VALUE_LEN]
{
    let mut ciphertext = [0u8; SLOT_VALUE_LEN];
    // XOR pad: ciphertext[i] = plaintext[i] ^ session_key[i] for all i.
    for ((dst, p), s) in ciphertext
        .iter_mut()
        .zip(plaintext.iter())
        .zip(session_key.iter())
    {
        *dst = p ^ s;
    }
    ciphertext
}

/// Compute the MAC that the chip expects to find appended to the
/// ciphertext in an encrypted write.
///
/// `session_key` is the value of `TempKey` *after* `Nonce + GenDig`,
/// reproduced on the host side via [`derive_session_key`]. The `io_key`
/// itself does not appear directly in this MAC: it has already been
/// absorbed into the `session_key`, which is the actual block-1 input of
/// the SHA-256 here (see `CryptoAuthLib` `atcah_write_auth_mac`).
///
/// `target_slot` is the slot being written (e.g. slot 5 for the PIN hash).
/// `target_block` is which 32-byte block within the slot (always 0 for
/// our single-block slots).
///
/// The slot/block address bytes are derived via
/// [`atecc608b::command::read_write::data_address`] so this module never
/// duplicates the chip's address-byte layout: a single source of truth
/// lives in the driver.
#[must_use]
pub fn write_mac
(
    session_key: &[u8; SLOT_VALUE_LEN],
    plaintext: &[u8; SLOT_VALUE_LEN],
    target_slot: Slot,
    target_block: u8,
    chip_serial: &[u8; CHIP_SERIAL_LEN],
) -> [u8; SLOT_VALUE_LEN]
{
    // Reconstruct the Write command parameters. The chip uses these
    // when computing its own copy of the MAC. The Write parameters used
    // for encrypted 32-byte writes set both the "32 byte" and
    // "encrypted" flags in param1.
    let param1 = ZONE_DATA | 0x80 | 0x40;
    // param2 is the same little-endian u16 the driver puts on the wire:
    // see `data_address` for the slot/block/offset bit layout.
    let address = data_address(target_slot, target_block, 0);
    let param2_lo = (address & 0xFF) as u8;
    let param2_hi = (address >> 8) as u8;

    let mut hasher = Sha256::new();
    // CryptoAuthLib `atcah_write_auth_mac` (lib/host/atca_host.c).
    hasher.update(session_key);
    hasher.update([OP_WRITE, param1, param2_lo, param2_hi]);
    hasher.update(&chip_serial[8..9]);
    hasher.update(&chip_serial[0..2]);
    hasher.update([0u8; 25]);
    hasher.update(plaintext);

    let mut out = [0u8; SLOT_VALUE_LEN];
    out.copy_from_slice(hasher.finalize().as_slice());
    out
}

/// Assemble the 64-byte payload (`ciphertext || mac`) that the driver
/// expects in [`atecc608b::Atecc::write_32_encrypted`].
#[must_use]
pub fn build_encrypted_write_payload
(
    ciphertext: &[u8; SLOT_VALUE_LEN],
    mac: &[u8; SLOT_VALUE_LEN],
) -> [u8; 64]
{
    let mut out = [0u8; 64];
    out[0..32].copy_from_slice(ciphertext);
    out[32..64].copy_from_slice(mac);
    out
}

#[cfg(test)]
mod tests
{
    use super::*;

    #[test]
    fn session_key_is_deterministic()
    {
        let io_key = [0x11u8; SLOT_VALUE_LEN];
        let nonce = [0x22u8; SLOT_VALUE_LEN];
        let serial = [0x33u8; CHIP_SERIAL_LEN];
        let k1 = derive_session_key(&io_key, &nonce, 8, &serial);
        let k2 = derive_session_key(&io_key, &nonce, 8, &serial);
        assert_eq!(k1, k2);
    }

    #[test]
    fn session_key_changes_with_each_input()
    {
        let io_key = [0x11u8; SLOT_VALUE_LEN];
        let nonce = [0x22u8; SLOT_VALUE_LEN];
        let serial = [0x33u8; CHIP_SERIAL_LEN];
        let base = derive_session_key(&io_key, &nonce, 8, &serial);

        let mut io_key2 = io_key;
        io_key2[0] ^= 0xFF;
        assert_ne!(derive_session_key(&io_key2, &nonce, 8, &serial), base);

        let mut nonce2 = nonce;
        nonce2[0] ^= 0xFF;
        assert_ne!(derive_session_key(&io_key, &nonce2, 8, &serial), base);

        assert_ne!(derive_session_key(&io_key, &nonce, 9, &serial), base);

        let mut serial2 = serial;
        serial2[0] ^= 0xFF;
        assert_ne!(derive_session_key(&io_key, &nonce, 8, &serial2), base);
    }

    #[test]
    fn encrypt_is_xor_and_self_inverse()
    {
        let plaintext = [0xAAu8; SLOT_VALUE_LEN];
        let key = [0x55u8; SLOT_VALUE_LEN];
        let ciphertext = encrypt_payload(&plaintext, &key);
        // 0xAA XOR 0x55 == 0xFF
        assert!(ciphertext.iter().all(|&b| b == 0xFF));
        // XOR is self-inverse: applying the same key recovers the
        // plaintext.
        let recovered = encrypt_payload(&ciphertext, &key);
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn write_mac_is_deterministic()
    {
        let session = [0x22u8; SLOT_VALUE_LEN];
        let plaintext = [0x33u8; SLOT_VALUE_LEN];
        let serial = [0x44u8; CHIP_SERIAL_LEN];
        let slot = Slot::new(5).unwrap();
        let m1 = write_mac(&session, &plaintext, slot, 0, &serial);
        let m2 = write_mac(&session, &plaintext, slot, 0, &serial);
        assert_eq!(m1, m2);
    }

    #[test]
    fn write_mac_changes_with_target_slot()
    {
        let session = [0x22u8; SLOT_VALUE_LEN];
        let plaintext = [0x33u8; SLOT_VALUE_LEN];
        let serial = [0x44u8; CHIP_SERIAL_LEN];
        let slot_5 = Slot::new(5).unwrap();
        let slot_6 = Slot::new(6).unwrap();
        let m_slot_5 = write_mac(&session, &plaintext, slot_5, 0, &serial);
        let m_slot_6 = write_mac(&session, &plaintext, slot_6, 0, &serial);
        assert_ne!(m_slot_5, m_slot_6);
    }

    #[test]
    fn build_payload_concatenates_correctly()
    {
        let c = [0xAAu8; SLOT_VALUE_LEN];
        let m = [0xBBu8; SLOT_VALUE_LEN];
        let payload = build_encrypted_write_payload(&c, &m);
        assert!(payload[0..32].iter().all(|&b| b == 0xAA));
        assert!(payload[32..64].iter().all(|&b| b == 0xBB));
    }
}