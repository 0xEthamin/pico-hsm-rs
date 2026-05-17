//! PIN / PUK hashing and CheckMac MAC computation.
//!
//! The project stores `SHA-256(PIN || pin_salt)` in slot 5 and
//! `SHA-256(PUK || puk_salt)` in slot 6. The salts are derived from the
//! chip's unique serial number at provisioning so that two physically
//! distinct tokens never share a hash even when the user picks the same
//! PIN, without paying the cost of storing an explicit salt elsewhere.
//!
//! The CheckMac verification on slot 5 / 6 uses the chip-side formula
//!
//! ```text
//! SHA256( slot_value || challenge || other_data[0..4] || zeroes(8) ||
//!         other_data[4..7] || serial[2..3] || other_data[7..13] ||
//!         serial[4..7] )
//! ```
//!
//! which the host must replicate exactly so that the chip's MAC and the
//! host's `client_resp` match when the user's PIN is correct. See
//! CryptoAuthLib `lib/calib/calib_checkmac.c` and the CheckMac section of
//! the ATECC608B summary datasheet for the canonical byte layout.

use sha2::{Digest, Sha256};

/// Length of a SHA-256 digest.
pub const HASH_LEN: usize = 32;

/// PIN length in bytes (4 ASCII digits).
pub const PIN_LEN: usize = 4;

/// PUK length in bytes (8 ASCII digits).
pub const PUK_LEN: usize = 8;

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
}

/// Validate that every byte of `code` is an ASCII digit `'0'..='9'`.
///
/// # Errors
/// Returns [`FormatError::NonDigit`] at the position of the first non-digit
/// byte.
pub fn validate_digits(code: &[u8]) -> Result<(), FormatError>
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
pub fn pin_salt(chip_serial: &[u8; 9]) -> [u8; HASH_LEN]
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
pub fn puk_salt(chip_serial: &[u8; 9]) -> [u8; HASH_LEN]
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
pub fn pin_hash(pin: &[u8; PIN_LEN], salt: &[u8; HASH_LEN]) -> [u8; HASH_LEN]
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
pub fn puk_hash(puk: &[u8; PUK_LEN], salt: &[u8; HASH_LEN]) -> [u8; HASH_LEN]
{
    let mut hasher = Sha256::new();
    hasher.update(puk);
    hasher.update(salt);
    let mut out = [0u8; HASH_LEN];
    out.copy_from_slice(hasher.finalize().as_slice());
    out
}

/// Compute the host-side CheckMac response for slot 5 or 6.
///
/// The MAC layout matches the ATECC608B documentation for CheckMac mode 0:
///
/// ```text
/// SHA-256(
///     key_in_slot  [32]
///  || challenge    [32]
///  || other_data[0..4]
///  || zero_pad[0..8]
///  || other_data[4..7]
///  || serial[2..3]
///  || other_data[7..13]
///  || serial[4..7]
/// )
/// ```
///
/// `other_data` is laid out as
/// `[opcode, mode, key_id_lo, key_id_hi, otp[0], otp[1], otp[2], sn[8],
///   sn[0], sn[1], sn[2], sn[3], sn[4]]`. When OTP is not in use, the OTP
/// bytes are zero. `sn[*]` are the relevant serial bytes.
///
/// For PIN verification in this project, `other_data` is filled with the
/// expected opcode/mode/key_id of the CheckMac command and zeros for the
/// OTP bytes (we do not couple OTP to PIN).
#[must_use]
pub fn checkmac_response(
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
    hasher.update(&[0u8; 8]);
    hasher.update(&other_data[4..7]);
    hasher.update(&chip_serial[2..3]);
    hasher.update(&other_data[7..13]);
    hasher.update(&chip_serial[4..7]);
    let mut out = [0u8; HASH_LEN];
    out.copy_from_slice(hasher.finalize().as_slice());
    out
}

/// Build the `other_data` block for a CheckMac call against `key_id` on
/// this project's slots, with zero OTP coupling.
///
/// `chip_serial[0..2]` are the SN[0..2] bytes (the so-called "SN8" plus
/// the two low bytes), which the chip mixes in at the expected offsets.
#[must_use]
pub fn checkmac_other_data(key_id: u8, chip_serial: &[u8; 9]) -> [u8; 13]
{
    let mut data = [0u8; 13];
    // CheckMac opcode and mode bytes that the chip itself substitutes.
    data[0] = 0x28; // OP_CHECKMAC
    data[1] = 0x00; // CHECKMAC_MODE_CHALLENGE
    data[2] = key_id;
    data[3] = 0x00;
    // OTP bytes 8..11 are zero (we do not use OTP).
    // SN[8] = chip_serial[0] (low byte of the SN word at offset 8).
    data[7] = chip_serial[0];
    // SN[0..2] = chip_serial[0..2].
    data[8] = chip_serial[0];
    data[9] = chip_serial[1];
    // SN[2..3] gets pulled separately by the chip via the layout above.
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
        assert_eq!(pin_hash(&pin, &salt), pin_hash(&pin, &salt));
    }

    #[test]
    fn pin_hash_changes_with_pin()
    {
        let salt = [0u8; HASH_LEN];
        assert_ne!(pin_hash(b"0000", &salt), pin_hash(b"1234", &salt));
    }

    #[test]
    fn pin_hash_changes_with_salt()
    {
        let pin = *b"0000";
        let salt1 = [0u8; HASH_LEN];
        let salt2 = [1u8; HASH_LEN];
        assert_ne!(pin_hash(&pin, &salt1), pin_hash(&pin, &salt2));
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

        let mut o = other_data;
        o[0] ^= 0xFF;
        assert_ne!(checkmac_response(&slot_value, &challenge, &o, &serial), base);

        // Mutate a serial byte that participates in the hash. Per the
        // CheckMac formula, the chip uses serial[2..3] and serial[4..7].
        let mut s = serial;
        s[2] ^= 0xFF;
        assert_ne!(checkmac_response(&slot_value, &challenge, &other_data, &s), base);
    }

    #[test]
    fn checkmac_response_ignores_serial_bytes_outside_known_offsets()
    {
        // The ATECC's CheckMac formula only consumes a subset of the serial
        // bytes: byte 2 and bytes 4..=6. The remaining serial bytes do not
        // affect the MAC. Document that by example so a future change to
        // the formula gets caught by the test, not by a chip on a bench.
        let slot_value = [0xAAu8; HASH_LEN];
        let challenge = [0xBBu8; HASH_LEN];
        let other_data = [0xCCu8; 13];
        let serial = [0xDDu8; 9];
        let base = checkmac_response(&slot_value, &challenge, &other_data, &serial);

        for ignored_index in [0, 1, 3, 7, 8]
        {
            let mut s = serial;
            s[ignored_index] ^= 0xFF;
            assert_eq!(
                checkmac_response(&slot_value, &challenge, &other_data, &s),
                base,
                "byte {ignored_index} of serial should not affect the MAC",
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