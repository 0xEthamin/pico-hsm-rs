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

//! Human-readable rendering of the configuration zone blob.
//!
//! Produces a multi-line text annotation that pairs every byte with its
//! semantic meaning. Useful as a sanity check before committing to the
//! irreversible Lock command.

use std::fmt::Write;

/// Render a 128-byte blob as an annotated text document.
///
/// The annotation lists every byte alongside the field it belongs to and
/// flags the value (factory-area, lock state, slot configuration, etc.).
/// The CRC value passed in is included at the bottom and is meant to be
/// the CRC of the writable portion (bytes 16-127), computed by the caller.
#[must_use]
pub fn format(blob: &[u8], crc: u16) -> String
{
    let mut out = String::with_capacity(8192);

    let _ = writeln!(out, "ATECC608B configuration zone, 128 bytes");
    let _ = writeln!(out, "========================================");
    let _ = writeln!(out);
    let _ = writeln!(out, "Bytes 0-15 are the read-only factory area. The chip ignores any");
    let _ = writeln!(out, "Write command targeted at this range. The values shown here are");
    let _ = writeln!(out, "placeholders from the generator and do not reflect what is actually");
    let _ = writeln!(out, "stored in the chip.");
    let _ = writeln!(out);

    write_factory_area(&mut out, &blob[0..16]);
    let _ = writeln!(out);

    write_device_config(&mut out, &blob[16..20]);
    let _ = writeln!(out);

    write_slot_configs(&mut out, &blob[20..52]);
    let _ = writeln!(out);

    write_counters(&mut out, &blob[52..68]);
    let _ = writeln!(out);

    write_feature_area(&mut out, &blob[68..84]);
    let _ = writeln!(out);

    write_lock_area(&mut out, &blob[84..96]);
    let _ = writeln!(out);

    write_key_configs(&mut out, &blob[96..128]);
    let _ = writeln!(out);

    write_summary(&mut out, blob, crc);
    out
}

fn write_factory_area(out: &mut String, bytes: &[u8])
{
    let _ = writeln!(out, "Factory area (bytes 0-15, read-only):");
    let _ = writeln!(out, "  SN[0..4]      (0-3):   {}", hex_row(&bytes[0..4]));
    let _ = writeln!(out, "  RevNum        (4-7):   {}", hex_row(&bytes[4..8]));
    let _ = writeln!(out, "  SN[4..8]      (8-11):  {}", hex_row(&bytes[8..12]));
    let _ = writeln!(out, "  SN[8]         (12):    {:02X} (must be 0xEE on real chip)", bytes[12]);
    let _ = writeln!(out, "  AES_Enable    (13):    {:02X}", bytes[13]);
    let _ = writeln!(out, "  I2C_Enable    (14):    {:02X}", bytes[14]);
    let _ = writeln!(out, "  Reserved1     (15):    {:02X}", bytes[15]);
}

fn write_device_config(out: &mut String, bytes: &[u8])
{
    let _ = writeln!(out, "Device configuration (bytes 16-19):");
    let _ = writeln!(out, "  I2C_Address   (16):    0x{:02X}  (7-bit addr 0x{:02X} in 8-bit form)",
        bytes[0], bytes[0] >> 1);
    let _ = writeln!(out, "  Reserved2     (17):    0x{:02X}  (must be 0x00)", bytes[1]);
    let _ = writeln!(out, "  CountMatch    (18):    0x{:02X}  (feature disabled)", bytes[2]);
    let _ = writeln!(out, "  ChipMode      (19):    0x{:02X}  ({})",
        bytes[3], decode_chip_mode(bytes[3]));
}

fn write_slot_configs(out: &mut String, bytes: &[u8])
{
    let _ = writeln!(out, "SlotConfig[16] (bytes 20-51), 2 bytes per slot, little-endian:");
    for slot in 0..16
    {
        let lo = bytes[2 * slot];
        let hi = bytes[2 * slot + 1];
        let word = u16::from(lo) | (u16::from(hi) << 8);
        let _ = writeln!(out,
            "  Slot {slot:2}: bytes {lo:02X} {hi:02X} -> 0x{word:04X}  {}",
            describe_slot_config(slot as u8, word),
        );
    }
}

fn write_counters(out: &mut String, bytes: &[u8])
{
    let _ = writeln!(out, "Counters (bytes 52-67):");
    let _ = writeln!(out, "  Counter0      (52-59): {}", hex_row(&bytes[0..8]));
    let _ = writeln!(out, "  Counter1      (60-67): {}", hex_row(&bytes[8..16]));
    let _ = writeln!(out, "  Note: 0xFF... means factory-default 'counter at zero'.");
}

fn write_feature_area(out: &mut String, bytes: &[u8])
{
    let _ = writeln!(out, "Feature configuration (bytes 68-83):");
    let _ = writeln!(out, "  UseLock              (68):    0x{:02X}", bytes[0]);
    let _ = writeln!(out, "  VolatileKeyPermission (69):   0x{:02X}", bytes[1]);
    let _ = writeln!(out, "  SecureBoot           (70-71): {} {}",
        hex_byte(bytes[2]), hex_byte(bytes[3]));
    let _ = writeln!(out, "  KdflvLoc             (72):    0x{:02X}", bytes[4]);
    let _ = writeln!(out, "  KdflvStr             (73-74): {} {}",
        hex_byte(bytes[5]), hex_byte(bytes[6]));
    let _ = writeln!(out, "  Reserved3            (75-83): {}", hex_row(&bytes[7..16]));
}

fn write_lock_area(out: &mut String, bytes: &[u8])
{
    let _ = writeln!(out, "Lock and chip-option area (bytes 84-95):");
    let _ = writeln!(out, "  UserExtra            (84):    0x{:02X}", bytes[0]);
    let _ = writeln!(out, "  UserExtraAdd         (85):    0x{:02X}", bytes[1]);
    let _ = writeln!(out, "  LockValue (data)     (86):    0x{:02X}  ({})",
        bytes[2], if bytes[2] == 0x55 { "unlocked" } else { "locked" });
    let _ = writeln!(out, "  LockConfig (config)  (87):    0x{:02X}  ({})",
        bytes[3], if bytes[3] == 0x55 { "unlocked" } else { "locked" });
    let _ = writeln!(out, "  SlotLocked bitmap    (88-89): {} {}",
        hex_byte(bytes[4]), hex_byte(bytes[5]));
    let _ = writeln!(out, "  ChipOptions          (90-91): {} {}",
        hex_byte(bytes[6]), hex_byte(bytes[7]));
    let _ = writeln!(out, "  X509format           (92-95): {} {} {} {}",
        hex_byte(bytes[8]), hex_byte(bytes[9]), hex_byte(bytes[10]), hex_byte(bytes[11]));
}

fn write_key_configs(out: &mut String, bytes: &[u8])
{
    let _ = writeln!(out, "KeyConfig[16] (bytes 96-127), 2 bytes per slot, little-endian:");
    for slot in 0..16
    {
        let lo = bytes[2 * slot];
        let hi = bytes[2 * slot + 1];
        let word = u16::from(lo) | (u16::from(hi) << 8);
        let _ = writeln!
        (   out,
            "  Slot {slot:2}: bytes {lo:02X} {hi:02X} -> 0x{word:04X}  {}",
            describe_key_config(word),
        );
    }
}

fn write_summary(out: &mut String, blob: &[u8], crc: u16)
{
    let _ = writeln!(out, "Summary:");
    let _ = writeln!(out, "  Total bytes:                  {}", blob.len());
    let _ = writeln!(out, "  Writable portion (16-127):    {} bytes", blob.len() - 16);
    let _ = writeln!(out, "  CRC-16 of writable portion:   0x{crc:04X}");
    let _ = writeln!(out);
    let _ = writeln!(out, "Lock the configuration zone only after verifying that the chip");
    let _ = writeln!(out, "contains the same bytes 16-127 as above, and only with a host");
    let _ = writeln!(out, "command that passes the expected CRC 0x{crc:04X} as a safety check.");
}

fn decode_chip_mode(byte: u8) -> String
{
    let i2c_extra = byte & 1;
    let ttl       = (byte >> 1) & 1;
    let wdg_long  = (byte >> 2) & 1;
    let clk_div   = (byte >> 3) & 0x1F;

    let clock = match clk_div
    {
        0x00 => "M0",
        0x05 => "M1",
        0x0D => "M2",
        _    => "unknown",
    };
    let watchdog = if wdg_long == 1 { "long" } else { "short" };

    format!
    (
        "I2C_Extra={i2c_extra}, TTL={ttl}, watchdog={watchdog}, clock_divider={clock}",
    )
}

fn describe_slot_config(slot: u8, word: u16) -> String
{
    // We assume the matching KeyConfig.Private bit dictates which layout
    // applies, but for annotation purposes we always print the ECC view.
    // Slots known to hold data are explicitly labelled.
    let ext_sig     =  word        & 1;
    let is_secret   = (word >> 7)  & 1;
    let gen_key     = (word >> 8)  & 1;
    let priv_write  = (word >> 9)  & 1;
    let write_config= (word >> 12) & 0xF;
    let limited_use = (word >> 5)  & 1;
    let read_key    =  word        & 0xF;
    let write_key   = (word >> 8)  & 0xF;

    let wc = match write_config
    {
        0x0 => "Always",
        0x2 => "Never",
        0x4 => "Always_then_Encrypt",
        0x6 => "Encrypt",
        0x8 => "Never (alt)",
        0xC => "Never_then_Encrypt",
        _   => "reserved",
    };

    match slot
    {
        5 | 6 => format!
        (
            "(data) ReadKey={read_key}, LimitedUse={limited_use}, IsSecret={is_secret}, WriteKey={write_key}, WriteConfig={wc}",
        ),
        8 => format!
        (
            "(I/O master key) IsSecret={is_secret}, WriteConfig={wc}",
        ),
        _ => format!
        (
            "(ECC) ExtSig={ext_sig}, IsSecret={is_secret}, GenKey={gen_key}, PrivWrite={priv_write}, WriteConfig={wc}",
        ),
    }
}

fn describe_key_config(word: u16) -> String
{
    let private  =  word        & 1;
    let pub_info = (word >> 1)  & 1;
    let key_type = (word >> 2)  & 0x07;
    let lockable = (word >> 5)  & 1;
    let req_auth = (word >> 7)  & 1;
    let auth_key = (word >> 8)  & 0xF;

    let kt = match key_type
    {
        0 => "B283",
        1 => "K283",
        4 => "P-256",
        6 => "AES",
        7 => "Data 32B",
        _ => "unknown",
    };

    if private == 1
    {
        format!
        (
            "Private={private}, PubInfo={pub_info}, KeyType={kt}, Lockable={lockable}, ReqAuth={req_auth}, AuthKey={auth_key}",
        )
    }
    else
    {
        format!
        (
            "Private={private}, KeyType={kt}, Lockable={lockable}",
        )
    }
}

fn hex_row(bytes: &[u8]) -> String
{
    bytes.iter().map(|b| format!("{b:02X}")).collect::<Vec<_>>().join(" ")
}

fn hex_byte(byte: u8) -> String
{
    format!("{byte:02X}")
}

#[cfg(test)]
mod tests
{
    use super::*;
    use crate::blob::build;
    use crate::crc::crc16;

    #[test]
    fn annotation_runs_without_panicking()
    {
        let blob = build();
        let crc = crc16(&blob[16..128]);
        let text = format(&blob, crc);
        assert!(text.contains("0xCB23"));
        assert!(text.contains("Slot  0"));
        assert!(text.contains("Slot 15"));
    }

    #[test]
    fn slot_0_annotation_mentions_genkey_only()
    {
        let blob = build();
        let crc = crc16(&blob[16..128]);
        let text = format(&blob, crc);
        // Slot 0 line should mention GenKey=1, PrivWrite=0.
        let slot0_line = text
            .lines()
            .find(|line| line.contains("Slot  0:") && line.contains("ECC"))
            .expect("slot 0 line must be present");
        assert!(slot0_line.contains("GenKey=1"));
        assert!(slot0_line.contains("PrivWrite=0"));
    }

    #[test]
    fn slot_2_annotation_mentions_privwrite_on()
    {
        let blob = build();
        let crc = crc16(&blob[16..128]);
        let text = format(&blob, crc);
        let slot2_line = text
            .lines()
            .find(|line| line.contains("Slot  2:") && line.contains("ECC"))
            .expect("slot 2 line must be present");
        assert!(slot2_line.contains("GenKey=1"));
        assert!(slot2_line.contains("PrivWrite=1"));
    }

    #[test]
    fn slot_5_annotation_labelled_as_data()
    {
        let blob = build();
        let crc = crc16(&blob[16..128]);
        let text = format(&blob, crc);
        let slot5_line = text
            .lines()
            .find(|line| line.starts_with("  Slot  5:"))
            .expect("slot 5 line must be present");
        assert!(slot5_line.contains("(data)"));
        assert!(slot5_line.contains("LimitedUse=1"));
    }
}
