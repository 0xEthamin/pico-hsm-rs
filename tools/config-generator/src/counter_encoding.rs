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

//! Encoding of the 8-byte initial value for the ATECC608B monotonic
//! counters (`Counter0` at bytes 52..60 of the config zone, `Counter1` at
//! bytes 60..68).
//!
//! The chip stores each counter as a redundant 8-byte structure split
//! into two 16-bit linear ("lin") halves and two 16-bit binary ("bin")
//! halves. Linear halves encode the low 5 bits of the count by clearing
//! one bit per increment (popcount-style); binary halves encode the high
//! 16 bits as a normal big-endian unsigned 16-bit integer. The two halves
//! are offset by 16 increments so a corruption of either is detected by
//! the chip.
//!
//! Writing `0xFF` to all 8 bytes does **not** represent "count = 0". It
//! leaves `bin_a` and `bin_b` at `0xFFFF`, which the chip interprets as
//! a high-bit count near the hardware ceiling (`2^21 - 1`). A chip that
//! is config-locked with this stray initialization comes out of the lock
//! with `count ≈ 2_097_120` (= `0xFFFF * 32`), losing virtually all of
//! its `2^21` lifetime increments.
//!
//! The correct factory initialization is `FF FF FF FF 00 00 00 00`,
//! which decodes to `count = 0`. The function in this module produces
//! that, plus any other target count up to the maximum.
//!
//! # Reference
//!
//! Translation of `calib_write_config_counter` in
//! `lib/calib/calib_basic.c` of Microchip CryptoAuthLib. The formula:
//!
//! ```text
//!     lin_a = 0xFFFF >> (counter_value % 32)
//!     lin_b = 0xFFFF >> ((counter_value - 16) % 32)     if counter_value >= 16 else 0xFFFF
//!     bin_a = counter_value / 32
//!     bin_b = (counter_value - 16) / 32                  if counter_value >= 16 else 0
//! ```
//!
//! is serialized big-endian as:
//!
//! ```text
//!     bytes = [lin_a_hi, lin_a_lo, lin_b_hi, lin_b_lo,
//!              bin_a_hi, bin_a_lo, bin_b_hi, bin_b_lo]
//! ```

/// Maximum supported counter value on the ATECC608B (`2^21 - 1`).
///
/// Each successful "key-usage event" against a slot whose `LimitedUse`
/// bit is set bumps the counter by one. When the counter reaches this
/// ceiling the chip refuses further increments. The value is fixed by
/// the chip's storage size (21 bits encoded in the 8-byte structure).
pub const COUNTER_MAX_VALUE: u32 = 2_097_151;

/// Number of bytes consumed by one counter in the config zone.
pub const COUNTER_STORAGE_SIZE: usize = 8;

/// Encode a target counter value into the 8-byte storage representation
/// the ATECC608B expects in the configuration zone.
///
/// `value == 0` produces the factory initialization, the canonical
/// "fresh chip" state. Any value in `0..=COUNTER_MAX_VALUE` is accepted
/// and produces a valid storage; values above are clamped to
/// `COUNTER_MAX_VALUE` because the chip cannot represent more.
///
/// Mirrors `calib_write_config_counter` from CryptoAuthLib exactly. The
/// `[u8; 8]` returned is what gets written to bytes 52..60 (Counter0)
/// or 60..68 (Counter1) of the configuration zone blob.
///
/// # Examples
///
/// ```ignore
/// // Factory init: count = 0 → FF FF FF FF 00 00 00 00.
/// assert_eq!(encode_counter_value(0), [0xFF, 0xFF, 0xFF, 0xFF, 0, 0, 0, 0]);
/// ```
#[must_use]
pub fn encode_counter_value(value: u32) -> [u8; COUNTER_STORAGE_SIZE]
{
    let value = value.min(COUNTER_MAX_VALUE);

    let lin_a: u16 = (0xFFFFu32 >> (value % 32)) as u16;
    let lin_b: u16 = if value >= 16
    {
        (0xFFFFu32 >> ((value - 16) % 32)) as u16
    }
    else
    {
        0xFFFF
    };
    // `bin_a` and `bin_b` fit in 16 bits because `value <= 2^21 - 1` and
    // `bin_a = value / 32` is therefore at most `(2^21 - 1) / 32 = 65535`.
    let bin_a: u16 = (value / 32) as u16;
    let bin_b: u16 = if value >= 16
    {
        ((value - 16) / 32) as u16
    }
    else
    {
        0
    };

    [
        (lin_a >> 8) as u8, (lin_a & 0xFF) as u8,
        (lin_b >> 8) as u8, (lin_b & 0xFF) as u8,
        (bin_a >> 8) as u8, (bin_a & 0xFF) as u8,
        (bin_b >> 8) as u8, (bin_b & 0xFF) as u8,
    ]
}

#[cfg(test)]
mod tests
{
    use super::*;

    /// Reference vectors generated from `encode_counter_cryptoauthlib`
    /// (the Python translation we used to validate the chip's behavior
    /// during bring-up). If this list ever diverges from CryptoAuthLib,
    /// the test fails and we know we've drifted from the spec.
    #[test]
    fn matches_cryptoauthlib_reference_vectors()
    {
        let cases: &[(u32, [u8; 8])] =
        &[
            (0,        [0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00]),
            (1,        [0x7F, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00]),
            (5,        [0x07, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00]),
            (31,       [0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00]),
            (32,       [0xFF, 0xFF, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00]),
            (100,      [0x0F, 0xFF, 0x00, 0x00, 0x00, 0x03, 0x00, 0x02]),
            (2_097_120,[0xFF, 0xFF, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFE]),
            (COUNTER_MAX_VALUE, [0x00, 0x00, 0x00, 0x01, 0xFF, 0xFF, 0xFF, 0xFF]),
        ];
        for (value, expected) in cases
        {
            let got = encode_counter_value(*value);
            assert_eq!(
                got, *expected,
                "encode_counter_value({value}) = {got:02X?}, expected {expected:02X?}",
            );
        }
    }

    #[test]
    fn factory_zero_is_all_ff_then_all_zero()
    {
        // The most important case: a freshly initialized chip must see
        // its counter at 0. Any other value here means we ship a chip
        // with a degraded budget, which is exactly the bug this module
        // was created to fix.
        assert_eq!
        (
            encode_counter_value(0),
            [0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00],
        );
    }

    #[test]
    fn values_above_max_clamp()
    {
        // u32::MAX is way above the chip's 2^21 - 1 ceiling. Encoding
        // such a value must produce the same byte pattern as encoding
        // exactly `COUNTER_MAX_VALUE`, never a wraparound that the chip
        // would interpret as a small count.
        assert_eq!(encode_counter_value(u32::MAX), encode_counter_value(COUNTER_MAX_VALUE));
    }
}