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

//! Construction of the 128-byte configuration zone blob.
//!
//! Every field, every bit, every value here matches
//! `docs/config-zone-layout.md` section by section. If you change anything
//! in this file, update the doc and re-run the tests.

// ---------------------------------------------------------------------------
// SlotConfig values, computed bit by bit.
//
// For ECC private key slots, the SlotConfig u16 layout is:
//
// bit 0    : ExtSig     (1 = allow ECDSA Sign on external messages)
// bit 1    : IntSig     (1 = allow internal-message sign, unused here)
// bit 2    : ECDH       (1 = allow ECDH, unused here)
// bit 3    : WriteECDH  (1 = allow writing ECDH output, unused)
// bit 4    : NoMac      (1 = forbid use in MAC commands)
// bit 5    : LimitedUse (1 = rate-limit usage via Counter0)
// bit 6    : EncRead    (1 = encrypted reads required)
// bit 7    : IsSecret   (1 = slot value never readable in cleartext)
// bit 8    : GenKey     (1 = allow GenKey to (re)generate the key)
// bit 9    : PrivWrite  (1 = allow PrivWrite encrypted import)
// bits 10-11: reserved
// bits 12-15: WriteConfig (see below)
//
// For data slots, the layout is:
//
// bits 0-3  : ReadKey
// bit  4    : NoMac
// bit  5    : LimitedUse
// bit  6    : EncRead
// bit  7    : IsSecret
// bits 8-11 : WriteKey
// bits 12-15: WriteConfig
//
// WriteConfig values:
//
// 0x0 : Always              (cleartext until data lock, never after)
// 0x2 : Never               (cleartext write never permitted)
// 0x4 : Always_then_Encrypt (cleartext pre-lock, encrypted via WriteKey post-lock)
// 0x6 : Encrypt             (encrypted only, never cleartext)
// 0x8 : Never               (alternate encoding)
// 0xC : Never_then_Encrypt  (never cleartext, encrypted post-lock)
//
// Reference: docs/config-zone-layout.md and Microchip CryptoAuthLib
// `lib/calib/calib_device.h`.
// ---------------------------------------------------------------------------

/// SlotConfig for ECC P-256 slots that allow GenKey but not PrivWrite.
///
/// Used by slots 0 and 1, the maximum-security identity slots.
///
/// Bits: `IsSecret=1, GenKey=1, ExtSig=1, WriteConfig=Never`.
const SLOT_CFG_ECC_GENKEY_ONLY: u16 = 0x2181;

/// SlotConfig for ECC P-256 slots that allow both GenKey and encrypted
/// PrivWrite import.
///
/// Used by slots 2, 3, 4, 7, and 9 through 15.
///
/// Same as `SLOT_CFG_ECC_GENKEY_ONLY` plus the `PrivWrite` bit set.
const SLOT_CFG_ECC_GENKEY_OR_IMPORT: u16 = 0x2381;

/// SlotConfig for the PIN hash slot (slot 5) and the PUK hash slot (slot 6).
///
/// Bits: `ReadKey=8, LimitedUse=1, IsSecret=1, WriteKey=8,
/// WriteConfig=Always_then_Encrypt`.
const SLOT_CFG_DATA_PIN_PUK: u16 = 0x48A8;

/// SlotConfig for the I/O Protection master key (slot 8).
///
/// Bits: `IsSecret=1, WriteConfig=Always`.
///
/// `Always` means the slot accepts cleartext writes only until the data
/// zone is locked. After data lock, the slot becomes immutable.
const SLOT_CFG_DATA_IO_KEY: u16 = 0x0080;

// ---------------------------------------------------------------------------
// KeyConfig values.
//
// KeyConfig u16 layout:
//
// bit 0     : Private    (1 = ECC private key)
// bit 1     : PubInfo    (1 = GenKey mode=public allowed)
// bits 2-4  : KeyType    (4 = P-256, 7 = Data 32B)
// bit 5     : Lockable   (1 = Lock(mode=slot) is permitted)
// bit 6     : ReqRandom  (1 = chip-side random nonce required before use)
// bit 7     : ReqAuth    (1 = CheckMac on AuthKey must succeed first)
// bits 8-11 : AuthKey    (slot index that authorizes use)
// bit 12    : PersistDis
// bit 13    : reserved
// bits 14-15: X509id
// ---------------------------------------------------------------------------

/// KeyConfig for ECC P-256 slots with `Lockable = 0`.
///
/// Used by slots 0 and 1. Sign and GenKey are PIN-gated (ReqAuth = 1,
/// AuthKey = 5). The slot cannot be individually locked; the key can be
/// regenerated indefinitely.
const KEY_CFG_ECC_LOCKABLE_OFF: u16 = 0x0593;

/// KeyConfig for ECC P-256 slots with `Lockable = 1`.
///
/// Used by slots 2-4, 7, 9-15. Same policy as `KEY_CFG_ECC_LOCKABLE_OFF`
/// except that the slot can be individually locked via Lock(mode=slot)
/// if the operator decides to freeze a particular key permanently.
const KEY_CFG_ECC_LOCKABLE_ON: u16 = 0x05B3;

/// KeyConfig for generic data slots.
///
/// Used by slots 5, 6, and 8. `KeyType = 7` (Data 32 B), all other bits
/// at zero.
const KEY_CFG_DATA_GENERIC: u16 = 0x001C;

/// I2C address byte stored at offset 16.
///
/// The chip stores the I2C 7-bit address in 8-bit form (shifted left by
/// one). For our default 7-bit address 0x60, the stored value is 0xC0.
const I2C_ADDRESS_BYTE: u8 = 0x60u8 << 1;

/// Value of byte 17. Required to be zero by the ATECC608B reference.
const RESERVED2: u8 = 0x00;

/// Value of byte 18, CountMatch. The CountMatch feature is unused, the
/// byte stays at zero.
const COUNT_MATCH: u8 = 0x00;

/// Value of byte 19, ChipMode.
///
/// Layout:
/// - bit 0    : I2C_Extra      = 0 (extra I2C address feature disabled)
/// - bit 1    : TTL_Enable     = 0 (fixed Vcc reference)
/// - bit 2    : Watchdog_Long  = 0 (short watchdog, about 1.3 s)
/// - bits 3-7 : Clock_Divider  = 0 (M0, maximum speed)
///
/// All zero gives us M0 mode with the short watchdog.
const CHIP_MODE: u8 = 0x00;

/// Value placed at the LockValue (byte 86) field. `0x55` means the data
/// zone is unlocked. The chip overwrites this with `0x00` when the
/// `Lock(data)` command is issued.
const LOCK_VALUE_UNLOCKED: u8 = 0x55;

/// Value placed at the LockConfig (byte 87) field. `0x55` means the
/// configuration zone is unlocked. The chip overwrites this with `0x00`
/// when the `Lock(config)` command is issued.
const LOCK_CONFIG_UNLOCKED: u8 = 0x55;

/// Total size of the configuration zone.
pub const CONFIG_ZONE_SIZE: usize = 128;

/// Build the full 128-byte configuration zone blob, including factory-area
/// placeholders at bytes 0-15.
///
/// The factory area is filled with zeros as a placeholder. The chip refuses
/// to overwrite it during the Write command, so its content in the blob is
/// irrelevant to the actual provisioning operation. The firmware reads the
/// real factory values from the chip at runtime.
#[must_use]
pub fn build() -> [u8; CONFIG_ZONE_SIZE]
{
    let mut cfg = [0u8; CONFIG_ZONE_SIZE];

    // Bytes 0-15: factory area, left at zero. The chip ignores Write
    // commands targeted here.

    // Bytes 16-19: device-level configuration.
    cfg[16] = I2C_ADDRESS_BYTE;
    cfg[17] = RESERVED2;
    cfg[18] = COUNT_MATCH;
    cfg[19] = CHIP_MODE;

    // Bytes 20-51: SlotConfig[16]. Each slot occupies 2 bytes in
    // little-endian form.
    for slot in 0..16u8
    {
        let sc = slot_config_for(slot);
        let offset = 20 + 2 * (slot as usize);
        cfg[offset]     = (sc & 0xFF) as u8;
        cfg[offset + 1] = (sc >> 8)   as u8;
    }

    // Bytes 52-67: Counter0 and Counter1 initial values, eight bytes each,
    // all 0xFF (factory-default "counter at zero" representation).
    for byte in cfg.iter_mut().take(68).skip(52)
    {
        *byte = 0xFF;
    }

    // Bytes 68-83: feature configuration fields, all unused, all zero.
    // Already initialized to zero by the `cfg` initializer.

    // Bytes 84-85: UserExtra and UserExtraAdd, kept at zero.
    // Already initialized to zero.

    // Bytes 86-87: lock state bytes, 0x55 = unlocked at provisioning.
    cfg[86] = LOCK_VALUE_UNLOCKED;
    cfg[87] = LOCK_CONFIG_UNLOCKED;

    // Bytes 88-89: SlotLocked bitmap, all slots unlocked = 0xFFFF.
    cfg[88] = 0xFF;
    cfg[89] = 0xFF;

    // Bytes 90-91: ChipOptions, all features disabled = 0x0000.
    // Already initialized to zero.

    // Bytes 92-95: X509format, unused = 0x00 0x00 0x00 0x00.
    // Already initialized to zero.

    // Bytes 96-127: KeyConfig[16]. Same layout as SlotConfig area, two
    // bytes per slot, little-endian.
    for slot in 0..16u8
    {
        let kc = key_config_for(slot);
        let offset = 96 + 2 * (slot as usize);
        cfg[offset]     = (kc & 0xFF) as u8;
        cfg[offset + 1] = (kc >> 8)   as u8;
    }

    cfg
}

/// Return the SlotConfig value for a given slot index.
fn slot_config_for(slot: u8) -> u16
{
    match slot
    {
        0 | 1                   => SLOT_CFG_ECC_GENKEY_ONLY,
        5 | 6                   => SLOT_CFG_DATA_PIN_PUK,
        8                       => SLOT_CFG_DATA_IO_KEY,
        2 | 3 | 4 | 7           => SLOT_CFG_ECC_GENKEY_OR_IMPORT,
        9..=15                  => SLOT_CFG_ECC_GENKEY_OR_IMPORT,
        _                       => SLOT_CFG_ECC_GENKEY_OR_IMPORT,
    }
}

/// Return the KeyConfig value for a given slot index.
fn key_config_for(slot: u8) -> u16
{
    match slot
    {
        0 | 1                   => KEY_CFG_ECC_LOCKABLE_OFF,
        5 | 6 | 8               => KEY_CFG_DATA_GENERIC,
        2 | 3 | 4 | 7           => KEY_CFG_ECC_LOCKABLE_ON,
        9..=15                  => KEY_CFG_ECC_LOCKABLE_ON,
        _                       => KEY_CFG_ECC_LOCKABLE_ON,
    }
}

#[cfg(test)]
mod tests
{
    use super::*;
    use crate::crc::crc16;

    /// Expected byte map for the writable portion of the blob, taken
    /// verbatim from `docs/config-zone-layout.md`.
    const EXPECTED_WRITABLE: [u8; 112] =
    [
        // Bytes 16-31
        0xC0, 0x00, 0x00, 0x00, 0x81, 0x21, 0x81, 0x21,
        0x81, 0x23, 0x81, 0x23, 0x81, 0x23, 0xA8, 0x48,
        // Bytes 32-47
        0xA8, 0x48, 0x81, 0x23, 0x80, 0x00, 0x81, 0x23,
        0x81, 0x23, 0x81, 0x23, 0x81, 0x23, 0x81, 0x23,
        // Bytes 48-63
        0x81, 0x23, 0x81, 0x23, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        // Bytes 64-79
        0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        // Bytes 80-95
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x55, 0x55,
        0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        // Bytes 96-111
        0x93, 0x05, 0x93, 0x05, 0xB3, 0x05, 0xB3, 0x05,
        0xB3, 0x05, 0x1C, 0x00, 0x1C, 0x00, 0xB3, 0x05,
        // Bytes 112-127
        0x1C, 0x00, 0xB3, 0x05, 0xB3, 0x05, 0xB3, 0x05,
        0xB3, 0x05, 0xB3, 0x05, 0xB3, 0x05, 0xB3, 0x05,
    ];

    #[test]
    fn blob_size_is_128_bytes()
    {
        let blob = build();
        assert_eq!(blob.len(), CONFIG_ZONE_SIZE);
    }

    #[test]
    fn writable_portion_matches_specification()
    {
        let blob = build();
        let writable = &blob[16..128];
        assert_eq!(writable, &EXPECTED_WRITABLE);
    }

    #[test]
    fn crc_of_writable_portion_is_canonical()
    {
        let blob = build();
        let crc = crc16(&blob[16..128]);
        assert_eq!(crc, 0xCB23, "expected 0xCB23, got 0x{crc:04X}");
    }

    #[test]
    fn slot_configs_match_documented_values()
    {
        let blob = build();
        let expected: [(u8, u16); 16] =
        [
            (0,  0x2181), (1,  0x2181),
            (2,  0x2381), (3,  0x2381), (4,  0x2381),
            (5,  0x48A8), (6,  0x48A8),
            (7,  0x2381),
            (8,  0x0080),
            (9,  0x2381), (10, 0x2381), (11, 0x2381),
            (12, 0x2381), (13, 0x2381), (14, 0x2381), (15, 0x2381),
        ];
        for (slot, expected_sc) in expected
        {
            let offset = 20 + 2 * (slot as usize);
            let actual_sc = u16::from(blob[offset]) | (u16::from(blob[offset + 1]) << 8);
            assert_eq!
            (
                actual_sc, expected_sc,
                "SlotConfig[{slot}] expected 0x{expected_sc:04X}, got 0x{actual_sc:04X}",
            );
        }
    }

    #[test]
    fn key_configs_match_documented_values()
    {
        let blob = build();
        let expected: [(u8, u16); 16] =
        [
            (0,  0x0593), (1,  0x0593),
            (2,  0x05B3), (3,  0x05B3), (4,  0x05B3),
            (5,  0x001C), (6,  0x001C),
            (7,  0x05B3),
            (8,  0x001C),
            (9,  0x05B3), (10, 0x05B3), (11, 0x05B3),
            (12, 0x05B3), (13, 0x05B3), (14, 0x05B3), (15, 0x05B3),
        ];
        for (slot, expected_kc) in expected
        {
            let offset = 96 + 2 * (slot as usize);
            let actual_kc = u16::from(blob[offset]) | (u16::from(blob[offset + 1]) << 8);
            assert_eq!
            (
                actual_kc, expected_kc,
                "KeyConfig[{slot}] expected 0x{expected_kc:04X}, got 0x{actual_kc:04X}",
            );
        }
    }

    #[test]
    fn lock_bytes_initially_unlocked()
    {
        let blob = build();
        assert_eq!(blob[86], 0x55, "LockValue (data zone) must be unlocked at provisioning");
        assert_eq!(blob[87], 0x55, "LockConfig (config zone) must be unlocked at provisioning");
    }

    #[test]
    fn slotlocked_bitmap_all_unlocked()
    {
        let blob = build();
        assert_eq!(blob[88], 0xFF);
        assert_eq!(blob[89], 0xFF);
    }

    #[test]
    fn i2c_address_is_0x60_in_8bit_form()
    {
        let blob = build();
        assert_eq!(blob[16], 0xC0, "0x60 << 1 = 0xC0");
    }

    #[test]
    fn chip_mode_is_m0_short_watchdog()
    {
        let blob = build();
        assert_eq!(blob[19], 0x00, "M0 + short watchdog + TTL off + no extra I2C addr");
    }

    #[test]
    fn counters_are_factory_default()
    {
        let blob = build();
        for byte in &blob[52..68]
        {
            assert_eq!(*byte, 0xFF, "Counter bytes must be 0xFF at provisioning");
        }
    }
}
