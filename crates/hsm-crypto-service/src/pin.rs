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

//! PIN / PUK hashing and `CheckMac` MAC computation.
//!
//! The project stores `SHA-256(PIN || pin_salt)` in slot 5 and
//! `SHA-256(PUK || puk_salt)` in slot 6. The salts are derived from the
//! chip's unique serial number at provisioning so that two physically
//! distinct tokens never share a hash even when the user picks the same
//! PIN, without paying the cost of storing an explicit salt elsewhere.
//!
//! The `CheckMac` verification on slot 5 / 6 mirrors what the chip itself
//! computes. The byte layout below is taken **verbatim** from
//! `CryptoAuthLib`'s `atcah_check_mac` (`lib/host/atca_host.c`), which is
//! the authoritative reference, and validated against it by
//! [`tests::checkmac_response_matches_cryptoauthlib_oracle`].
//!
//! ```text
//! msg[0..32]   = slot_value         (32)
//! msg[32..64]  = challenge          (32)
//! msg[64..68]  = other_data[0..4]   ( 4)  OpCode, Mode, Param2 LE
//! msg[68..76]  = OTP[0..8] or zero  ( 8)
//! msg[76..79]  = other_data[4..7]   ( 3)
//! msg[79]      = serial[8]          ( 1)  SN[8]
//! msg[80..84]  = other_data[7..11]  ( 4)
//! msg[84..86]  = serial[0..2]       ( 2)  SN[0..2]
//! msg[86..88]  = other_data[11..13] ( 2)
//! ```
//!
//! Total = 88 bytes (`ATCA_MSG_SIZE_MAC`).
//!
//! Notable surprises vs. the Microchip ASF documentation table:
//! - SN[4..8] and SN[2..4] do **not** participate in the hash.
//! - `other_data` is consumed in three discontinuous chunks: `[0..4]`,
//!   `[4..7]`, `[7..11]`, `[11..13]`. All 13 bytes contribute.
//!
//! We pass OTP as zeros: PIN verification in this project is not coupled
//! to the OTP zone.

use sha2::{Digest, Sha256};

/// Length of a SHA-256 digest.
pub(crate) const HASH_LEN: usize = 32;

/// PIN length in bytes (4 ASCII digits).
pub(crate) const PIN_LEN: usize = 4;

/// PUK length in bytes (8 ASCII digits).
pub(crate) const PUK_LEN: usize = 8;

/// Domain separation tag for the PIN salt.
const PIN_SALT_DOMAIN: &[u8] = b"mini-hsm-pin-salt-v1";

/// Domain separation tag for the PUK salt.
const PUK_SALT_DOMAIN: &[u8] = b"mini-hsm-puk-salt-v1";

/// Errors returned when a PIN or PUK does not match the expected format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum FormatError
{
    /// One of the bytes was not an ASCII digit `'0'..='9'`.
    NonDigit
    {
        /// Position of the offending byte.
        position: usize,
    },
    /// A numeric argument fell outside its accepted range (e.g. a
    /// config-zone block index greater than 3).
    OutOfRange,
}

/// Validate that every byte of `code` is an ASCII digit `'0'..='9'`.
///
/// # Errors
/// Returns [`FormatError::NonDigit`] at the position of the first non-digit
/// byte.
pub(crate) fn validate_digits(code: &[u8]) -> Result<(), FormatError>
{
    for (position, byte) in code.iter().enumerate()
    {
        if !byte.is_ascii_digit()
        {
            return Err(FormatError::NonDigit { position });
        }
    }
    Ok(())
}

/// Compute the PIN salt deterministically from the chip serial number.
///
/// The serial is the 9-byte ATECC unique ID read from the config zone.
#[must_use]
pub(crate) fn pin_salt(chip_serial: &[u8; 9]) -> [u8; HASH_LEN]
{
    let mut hasher = Sha256::new();
    hasher.update(PIN_SALT_DOMAIN);
    hasher.update(chip_serial);
    let mut out = [0u8; HASH_LEN];
    out.copy_from_slice(hasher.finalize().as_slice());
    out
}

/// Compute the PUK salt deterministically from the chip serial number.
#[must_use]
pub(crate) fn puk_salt(chip_serial: &[u8; 9]) -> [u8; HASH_LEN]
{
    let mut hasher = Sha256::new();
    hasher.update(PUK_SALT_DOMAIN);
    hasher.update(chip_serial);
    let mut out = [0u8; HASH_LEN];
    out.copy_from_slice(hasher.finalize().as_slice());
    out
}

/// Compute `SHA-256(pin || pin_salt)`. This is the value stored in slot 5.
#[must_use]
pub(crate) fn pin_hash(pin: [u8; PIN_LEN], salt: &[u8; HASH_LEN]) -> [u8; HASH_LEN]
{
    let mut hasher = Sha256::new();
    hasher.update(pin);
    hasher.update(salt);
    let mut out = [0u8; HASH_LEN];
    out.copy_from_slice(hasher.finalize().as_slice());
    out
}

/// Compute `SHA-256(puk || puk_salt)`. This is the value stored in slot 6.
#[must_use]
pub(crate) fn puk_hash(puk: [u8; PUK_LEN], salt: &[u8; HASH_LEN]) -> [u8; HASH_LEN]
{
    let mut hasher = Sha256::new();
    hasher.update(puk);
    hasher.update(salt);
    let mut out = [0u8; HASH_LEN];
    out.copy_from_slice(hasher.finalize().as_slice());
    out
}

/// Compute the host-side `CheckMac` response for slot 5 or 6.
///
/// The MAC layout matches `CryptoAuthLib`'s `atcah_check_mac` exactly
/// (`lib/host/atca_host.c`):
///
/// ```text
/// msg[0..32]   = slot_value         (32)
/// msg[32..64]  = challenge          (32)
/// msg[64..68]  = other_data[0..4]   ( 4)
/// msg[68..76]  = OTP[0..8] (zero)   ( 8)
/// msg[76..79]  = other_data[4..7]   ( 3)
/// msg[79]      = serial[8]          ( 1)
/// msg[80..84]  = other_data[7..11]  ( 4)
/// msg[84..86]  = serial[0..2]       ( 2)
/// msg[86..88]  = other_data[11..13] ( 2)
/// ```
///
/// All 13 bytes of `other_data` are consumed, in three discontinuous
/// chunks. Only serial bytes 0, 1, and 8 contribute to the hash; the
/// remaining serial bytes (2..8) are absent from the formula by design.
///
/// `chip_serial` must therefore have valid values at indices 0, 1, 8;
/// the others are ignored.
#[must_use]
pub(crate) fn checkmac_response
(
    slot_value: &[u8; HASH_LEN],
    challenge: &[u8; HASH_LEN],
    other_data: &[u8; 13],
    chip_serial: &[u8; 9],
) -> [u8; HASH_LEN]
{
    let mut hasher = Sha256::new();
    hasher.update(slot_value);
    hasher.update(challenge);
    hasher.update(&other_data[0..4]);
    hasher.update([0u8; 8]);
    hasher.update(&other_data[4..7]);
    hasher.update(&chip_serial[8..9]);
    hasher.update(&other_data[7..11]);
    hasher.update(&chip_serial[0..2]);
    hasher.update(&other_data[11..13]);
    let mut out = [0u8; HASH_LEN];
    out.copy_from_slice(hasher.finalize().as_slice());
    out
}

/// Build the `other_data` block for a `CheckMac` call against `key_id` on
/// this project's slots, with zero OTP coupling.
///
/// `other_data` is 13 bytes long. Bytes 0..4 carry the opcode, mode, and
/// `key_id` that the chip substitutes into the hash at message offsets
/// 84..88. Bytes 4..7 are reserved for OTP coupling, which we never use
/// (kept at zero). Bytes 7..13 are six free-form bytes that the chip
/// hashes verbatim at message offsets 80..84 and 88..96. Their actual
/// values are not constrained by the protocol: any sequence works as long
/// as both the host (in [`checkmac_response`]) and the chip-side computation
/// receive the same bytes. We seed them from `chip_serial` to bind a
/// successful `CheckMac` to a specific chip, defeating a replay of a
/// pre-computed response against a different physical chip with the
/// same slot value.
#[must_use]
pub(crate) fn checkmac_other_data(key_id: u8, chip_serial: &[u8; 9]) -> [u8; 13]
{
    let mut data = [0u8; 13];
    // Bytes 0..4: command shape that the chip rebuilds for verification.
    data[0] = 0x28; // OP_CHECKMAC
    data[1] = 0x00; // CHECKMAC_MODE_CHALLENGE
    data[2] = key_id;
    data[3] = 0x00;
    // Bytes 4..7: OTP coupling area. We do not use OTP, leave at zero.
    // Bytes 7..13: free-form bytes hashed verbatim by the chip. Seeded
    // from the chip serial so that the same slot value on a different
    // physical chip cannot replay a previously captured response.
    data[7] = chip_serial[0];
    data[8] = chip_serial[0];
    data[9] = chip_serial[1];
    data[10] = chip_serial[2];
    data[11] = chip_serial[3];
    data[12] = 0x00;
    data
}

#[cfg(test)]
mod tests
{
    use super::*;

    #[test]
    fn validate_digits_accepts_ascii_digits()
    {
        assert!(validate_digits(b"0000").is_ok());
        assert!(validate_digits(b"1234").is_ok());
        assert!(validate_digits(b"99999999").is_ok());
    }

    #[test]
    fn validate_digits_rejects_non_digit()
    {
        assert_eq!(
            validate_digits(b"12A4"),
            Err(FormatError::NonDigit { position: 2 })
        );
        assert_eq!(
            validate_digits(b" 234"),
            Err(FormatError::NonDigit { position: 0 })
        );
    }

    #[test]
    fn pin_salt_is_deterministic()
    {
        let serial = [0u8; 9];
        assert_eq!(pin_salt(&serial), pin_salt(&serial));
    }

    #[test]
    fn pin_salt_changes_with_serial()
    {
        let s1 = [1u8; 9];
        let s2 = [2u8; 9];
        assert_ne!(pin_salt(&s1), pin_salt(&s2));
    }

    #[test]
    fn pin_salt_and_puk_salt_differ()
    {
        let serial = [0xAB; 9];
        assert_ne!(pin_salt(&serial), puk_salt(&serial));
    }

    #[test]
    fn pin_hash_is_deterministic()
    {
        let pin = *b"0000";
        let salt = [0u8; HASH_LEN];
        assert_eq!(pin_hash(pin, &salt), pin_hash(pin, &salt));
    }

    #[test]
    fn pin_hash_changes_with_pin()
    {
        let salt = [0u8; HASH_LEN];
        assert_ne!(pin_hash(*b"0000", &salt), pin_hash(*b"1234", &salt));
    }

    #[test]
    fn pin_hash_changes_with_salt()
    {
        let pin = *b"0000";
        let salt1 = [0u8; HASH_LEN];
        let salt2 = [1u8; HASH_LEN];
        assert_ne!(pin_hash(pin, &salt1), pin_hash(pin, &salt2));
    }

    #[test]
    fn checkmac_response_is_deterministic()
    {
        let slot_value = [0xAAu8; HASH_LEN];
        let challenge = [0xBBu8; HASH_LEN];
        let other_data = [0xCCu8; 13];
        let serial = [0xDDu8; 9];
        let r1 = checkmac_response(&slot_value, &challenge, &other_data, &serial);
        let r2 = checkmac_response(&slot_value, &challenge, &other_data, &serial);
        assert_eq!(r1, r2);
    }

    /// `CryptoAuthLib` oracle match - vector 1 (uniform).
    ///
    /// Tests the host-side `CheckMac` formula against the digest produced
    /// by Microchip's `CryptoAuthLib` for an identical input.
    ///
    /// This vector uses uniform bytes per region. It catches gross
    /// formula errors (wrong total length, wrong segment sizes, OTP not
    /// zero) but cannot catch swaps of equal-sized slices that happen to
    /// hold the same byte. Vectors v2 and v3 cover that case.
    ///
    /// Inputs:
    ///   `slot_value` = [0xAA; 32]
    ///   challenge  = [0xBB; 32]
    ///   `other_data` = [0xCC; 13]
    ///   sn         = [0xDD;  9]
    #[test]
    fn checkmac_response_matches_cryptoauthlib_oracle_v1_uniform()
    {
        let slot_value = [0xAAu8; HASH_LEN];
        let challenge = [0xBBu8; HASH_LEN];
        let other_data = [0xCCu8; 13];
        let serial = [0xDDu8; 9];
        let got = checkmac_response(&slot_value, &challenge, &other_data, &serial);
        let expected: [u8; HASH_LEN] = [
            0xe6, 0x70, 0x6b, 0xdf, 0x1f, 0x6b, 0x55, 0x3f,
            0xce, 0x61, 0xbb, 0x4c, 0xfe, 0x90, 0xa9, 0x2e,
            0x19, 0x9e, 0x80, 0x04, 0x04, 0x87, 0x88, 0x34,
            0xe5, 0xcc, 0x3c, 0x73, 0xde, 0xba, 0x24, 0xe9,
        ];
        assert_eq!(got, expected, "host CheckMac formula diverges from CryptoAuthLib (v1)");
    }

    /// `CryptoAuthLib` oracle match - vector 2 (linear).
    ///
    /// Every byte across `slot_value`, challenge, `other_data`, and serial
    /// is distinct. Any swap of two slices in the formula's byte
    /// layout would change the digest with overwhelming probability,
    /// so this vector is the most powerful regression guard among the
    /// three.
    ///
    /// Inputs:
    ///   `slot_value`[i] = i             for i in 0..32   (0x00 .. 0x1F)
    ///   challenge[i]  = i + 32        for i in 0..32   (0x20 .. 0x3F)
    ///   `other_data`[i] = 0x80 + i      for i in 0..13   (0x80 .. 0x8C)
    ///   serial[i]     = 0xE0 + i      for i in 0..9    (0xE0 .. 0xE8)
    #[test]
    fn checkmac_response_matches_cryptoauthlib_oracle_v2_linear()
    {
        let slot_value: [u8; HASH_LEN] = core::array::from_fn(|i| u8::try_from(i).unwrap());
        let challenge: [u8; HASH_LEN]  = core::array::from_fn(|i| u8::try_from(i + 32).unwrap());
        let other_data: [u8; 13]       = core::array::from_fn(|i| 0x80 + u8::try_from(i).unwrap());
        let serial: [u8; 9]            = core::array::from_fn(|i| 0xE0 + u8::try_from(i).unwrap());

        let got = checkmac_response(&slot_value, &challenge, &other_data, &serial);
        let expected: [u8; HASH_LEN] = [
            0x06, 0x78, 0x0a, 0x56, 0x55, 0x68, 0x0c, 0x31,
            0x23, 0x89, 0x3d, 0xd3, 0x9b, 0x7f, 0x3f, 0x71,
            0xfa, 0x8d, 0x37, 0x81, 0x98, 0x34, 0xfd, 0xf5,
            0xf2, 0xe7, 0xf1, 0x1e, 0x26, 0xed, 0xad, 0xa8,
        ];
        assert_eq!(got, expected, "host CheckMac formula diverges from CryptoAuthLib (v2)");
    }

    /// `CryptoAuthLib` oracle match - vector 3 (realistic).
    ///
    /// Inputs are shaped like what the firmware will actually see at
    /// runtime: a PIN-hash-looking `slot_value`, an entropy-looking
    /// challenge, an `other_data` filled with the `CheckMac` opcode/mode/
    /// `key_id` pattern (0x28 / 0x00 / 0x05 0x00 followed by zeros), and
    /// a serial styled after a typical ATECC608 serial number.
    #[test]
    fn checkmac_response_matches_cryptoauthlib_oracle_v3_realistic()
    {
        let slot_value: [u8; HASH_LEN] = [
            0x9b, 0x87, 0x1d, 0x4f, 0x3c, 0x2c, 0xa9, 0x2f,
            0x14, 0xbd, 0xc3, 0xa6, 0xa6, 0x36, 0xa6, 0xa0,
            0x4d, 0xaf, 0xfb, 0xc0, 0xff, 0x7c, 0xc2, 0x55,
            0x68, 0xea, 0xf4, 0x36, 0x55, 0xb6, 0xa3, 0xe9,
        ];
        let challenge: [u8; HASH_LEN] = [
            0x10, 0xd6, 0xf5, 0xc8, 0xb2, 0xa8, 0x60, 0xc5,
            0x9a, 0xf7, 0xe7, 0x40, 0x4c, 0x21, 0x4a, 0x10,
            0x6f, 0x07, 0xa7, 0x9d, 0x67, 0xeb, 0xfc, 0xee,
            0xa6, 0xaf, 0xc9, 0x65, 0x88, 0x4f, 0x40, 0x12,
        ];
        let other_data: [u8; 13] = [
            0x28, 0x00, 0x05, 0x00,
            0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00,
        ];
        let serial: [u8; 9] = [
            0x01, 0x23, 0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6, 0xee,
        ];

        let got = checkmac_response(&slot_value, &challenge, &other_data, &serial);
        let expected: [u8; HASH_LEN] = [
            0xd8, 0xab, 0x16, 0xa7, 0x5d, 0xc3, 0xbc, 0x16,
            0xca, 0xd1, 0xd9, 0x55, 0x4d, 0x24, 0xbb, 0x95,
            0x47, 0x6f, 0x55, 0x90, 0x5e, 0x91, 0xb8, 0x1d,
            0x86, 0x60, 0x4c, 0x32, 0x77, 0x18, 0x4d, 0x1f,
        ];
        assert_eq!(got, expected, "host CheckMac formula diverges from CryptoAuthLib (v3)");
    }

    #[test]
    fn checkmac_response_changes_with_each_input()
    {
        let slot_value = [0xAAu8; HASH_LEN];
        let challenge = [0xBBu8; HASH_LEN];
        let other_data = [0xCCu8; 13];
        let serial = [0xDDu8; 9];
        let base = checkmac_response(&slot_value, &challenge, &other_data, &serial);

        let mut v = slot_value;
        v[0] ^= 0xFF;
        assert_ne!(checkmac_response(&v, &challenge, &other_data, &serial), base);

        let mut c = challenge;
        c[0] ^= 0xFF;
        assert_ne!(checkmac_response(&slot_value, &c, &other_data, &serial), base);

        // All 13 bytes of other_data are consumed by the formula in
        // three chunks: [0..4], [4..7], [7..11], [11..13]. Mutating any
        // byte must flip the digest.
        let mut o = other_data;
        o[0] ^= 0xFF;
        assert_ne!(checkmac_response(&slot_value, &challenge, &o, &serial), base);

        // Only serial[0], [1], and [8] participate in the hash. Pick
        // one that is in the formula to assert it matters.
        let mut s = serial;
        s[8] ^= 0xFF;
        assert_ne!(checkmac_response(&slot_value, &challenge, &other_data, &s), base);
    }

    #[test]
    fn checkmac_response_uses_every_other_data_byte()
    {
        // The CheckMac formula consumes all 13 bytes of other_data,
        // split into [0..4], [4..7], [7..11], [11..13]. Document this
        // by mutating each byte in turn and asserting the digest flips.
        let slot_value = [0xAAu8; HASH_LEN];
        let challenge = [0xBBu8; HASH_LEN];
        let other_data = [0xCCu8; 13];
        let serial = [0xDDu8; 9];
        let base = checkmac_response(&slot_value, &challenge, &other_data, &serial);

        for index in 0..13
        {
            let mut o = other_data;
            o[index] ^= 0xFF;
            assert_ne!(
                checkmac_response(&slot_value, &challenge, &o, &serial),
                base,
                "other_data byte {index} should affect the MAC",
            );
        }
    }

    #[test]
    fn checkmac_response_only_uses_serial_bytes_0_1_8()
    {
        // The CheckMac formula consumes serial[8] (1 byte) and
        // serial[0..2] (2 bytes). Bytes 2..8 do NOT participate in the
        // hash. Document this so any regression that mistakenly mixes
        // in additional serial bytes gets caught here.
        let slot_value = [0xAAu8; HASH_LEN];
        let challenge = [0xBBu8; HASH_LEN];
        let other_data = [0xCCu8; 13];
        let serial = [0xDDu8; 9];
        let base = checkmac_response(&slot_value, &challenge, &other_data, &serial);

        // Bytes 2..=7 are ignored.
        for ignored_index in 2..=7
        {
            let mut s = serial;
            s[ignored_index] ^= 0xFF;
            assert_eq!(
                checkmac_response(&slot_value, &challenge, &other_data, &s),
                base,
                "serial byte {ignored_index} should NOT affect the MAC",
            );
        }

        // Bytes 0, 1, 8 are consumed.
        for used_index in [0, 1, 8]
        {
            let mut s = serial;
            s[used_index] ^= 0xFF;
            assert_ne!(
                checkmac_response(&slot_value, &challenge, &other_data, &s),
                base,
                "serial byte {used_index} should affect the MAC",
            );
        }
    }

    #[test]
    fn checkmac_other_data_populates_known_bytes()
    {
        let serial = [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x00];
        let data = checkmac_other_data(5, &serial);
        assert_eq!(data[0], 0x28);  // opcode
        assert_eq!(data[1], 0x00);  // mode
        assert_eq!(data[2], 5);     // key id lo
        assert_eq!(data[3], 0x00);  // key id hi
    }
}