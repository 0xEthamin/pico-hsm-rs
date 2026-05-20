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

//! CLI used to operate the mini-HSM dongle from a development host.
//!
//! Most subcommands map one-to-one to a USB-HID opcode. The two
//! exceptions are `enumerate` (no chip command involved) and the lock
//! commands (interactive double-confirm before the opcode is sent).

mod device;

use std::fs;
use std::io::{self, BufRead, Write};

use anyhow::{anyhow, bail, Context, Result};
use clap::{Parser, Subcommand};

use hsm_usb_protocol::commands::EMERGENCY_RESET_MAGIC;
use hsm_usb_protocol::CommandOpcode;

/// Magic word required to actually lock the config zone. Picked to be
/// unforgettable in hex (`DEADBEEF`) and clearly not a value that could
/// arise from typos.
const LOCK_CONFIG_MAGIC: [u8; 4] = [0xDE, 0xAD, 0xBE, 0xEF];

/// Magic word required to actually lock the data zone (`CAFEBABE`).
const LOCK_DATA_MAGIC: [u8; 4] = [0xCA, 0xFE, 0xBA, 0xBE];

/// Magic word required to actually lock an individual slot (`F00DCAFE`).
const LOCK_SLOT_MAGIC: [u8; 4] = [0xF0, 0x0D, 0xCA, 0xFE];

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Cli
{
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command
{
    /// Enumerate all USB HID devices and print those matching the
    /// mini-HSM vendor / product IDs.
    Enumerate,

    /// Send an `Info` request and pretty-print the response.
    Info,

    /// Read the chip's 128-byte config zone and dump it as hex.
    ReadConfig,

    /// Read the per-slot configuration (SlotConfig + KeyConfig).
    /// Returns 4 bytes : [SlotConfig lo/hi, KeyConfig lo/hi].
    ReadConfigSlot
    {
        #[arg(long)]
        slot: u8,
    },

    /// Write the writable bytes of the config zone (provisioning).
    /// Reversible while the zone is unlocked.
    WriteConfig
    {
        /// Path to the 128-byte config blob produced by
        /// `tools/config-generator`.
        #[arg(long)]
        path: String,
    },

    /// Write a 32-byte value in cleartext into one of the data slots
    /// 5, 6, or 8. Only legal before the data zone is locked. Used for
    /// the initial provisioning of the PIN hash, PUK hash, and IO key.
    ProvisionSlot
    {
        #[arg(long)]
        slot:  u8,
        /// 32-byte value, hex-encoded (64 chars).
        #[arg(long)]
        value: String,
    },

    /// Orchestrate the full data-zone provisioning of a fresh,
    /// config-locked token in one shot: generate IO key (slot 8),
    /// initial PIN hash (slot 5, PIN = "0000"), initial PUK (slot 6,
    /// random 8 digits), and the primary identity key (slot 0). The
    /// IO key and PUK are written to `secrets_file` (JSON) and also
    /// printed on stdout. Both are required for later operations and
    /// cannot be retrieved later.
    ProvisionToken
    {
        /// Path to the JSON file that will receive the chip's
        /// serial, the IO key, and the initial PUK. Refuses to
        /// overwrite an existing file.
        #[arg(long)]
        secrets_file: String,
    },

    /// Read the public key of a slot.
    GetPubkey
    {
        #[arg(long)]
        slot: u8,
    },

    /// Regenerate the private key in a slot (P-256, on-chip).
    Genkey
    {
        #[arg(long)]
        slot: u8,
    },

    /// Sign a 32-byte challenge after PIN + touch.
    Sign
    {
        #[arg(long)]
        slot:      u8,
        /// 32-byte challenge as a hex string (64 chars).
        #[arg(long)]
        challenge: String,
    },

    /// Open a PIN session.
    VerifyPin
    {
        #[arg(long)]
        pin: String,
    },

    /// Change the PIN. Requires an active PIN session.
    SetPin
    {
        #[arg(long)]
        old:    String,
        #[arg(long)]
        new:    String,
        /// 32-byte IO Protection Key as a hex string (64 chars).
        #[arg(long)]
        io_key: String,
    },

    /// Reset the PIN using the PUK.
    UnblockPin
    {
        #[arg(long)]
        puk:     String,
        #[arg(long)]
        new_pin: String,
        /// 32-byte IO Protection Key as a hex string (64 chars).
        #[arg(long)]
        io_key:  String,
    },

    /// Change the PUK. Requires an active PIN session (call `verify-pin`
    /// first) AND the current PUK. The current PUK is re-verified
    /// against slot 6, which consumes one Counter1 attempt internally
    /// (refreshed on success).
    SetPuk
    {
        #[arg(long)]
        old:    String,
        #[arg(long)]
        new:    String,
        /// 32-byte IO Protection Key as a hex string (64 chars).
        #[arg(long)]
        io_key: String,
    },

    /// **LAST-CHANCE RECOVERY.** Only usable when both the PIN and the
    /// PUK batches are exhausted (i.e. the user has forgotten both and
    /// tried until they hit zero attempts on both). Destroys every
    /// user secret in the chip and rebuilds a clean baseline with PIN
    /// "0000" and a fresh random PUK. ECC private keys in slots 0..=4
    /// and 7 are lost. The chip survives.
    #[command(name = "emergency-reset-DANGEROUS")]
    EmergencyResetDangerous
    {
        /// 32-byte IO Protection Key as a hex string (64 chars).
        #[arg(long)]
        io_key: String,
    },

    /// Read current PIN / PUK retry counters and session state.
    PinStatus,

    /// Lock the config zone. **Irreversible.** Requires the CRC-16 of
    /// the expected config (as printed by `config-generator`) to be
    /// passed explicitly as a safety check, plus an interactive
    /// confirmation.
    #[command(name = "lock-config-DANGEROUS")]
    LockConfigDangerous
    {
        /// CRC-16 of the config blob, as `0x1234` hex.
        #[arg(long)]
        expected_crc: String,
    },

    /// Lock the data zone. **Irreversible.** Requires the expected
    /// CRC-16 of the locked-data-zone contents (as the chip will
    /// compute it), plus an interactive confirmation.
    #[command(name = "lock-data-DANGEROUS")]
    LockDataDangerous
    {
        /// CRC-16 of the data zone, as `0x1234` hex.
        #[arg(long)]
        expected_crc: String,
    },

    /// Lock an individual slot. **Irreversible.** Requires the slot
    /// index and an interactive confirmation.
    #[command(name = "lock-slot-DANGEROUS")]
    LockSlotDangerous
    {
        #[arg(long)]
        slot: u8,
    },
}

fn main() -> Result<()>
{
    let cli = Cli::parse();

    match cli.command
    {
        Command::Enumerate => device::enumerate(),
        Command::Info => cmd_info(),
        Command::ReadConfig => cmd_read_config(),
        Command::ReadConfigSlot { slot } => cmd_read_config_slot(slot),
        Command::WriteConfig { path } => cmd_write_config(&path),
        Command::ProvisionSlot { slot, value } => cmd_provision_slot(slot, &value),
        Command::ProvisionToken { secrets_file } => cmd_provision_token(&secrets_file),
        Command::GetPubkey { slot } => cmd_get_pubkey(slot),
        Command::Genkey { slot } => cmd_genkey(slot),
        Command::Sign { slot, challenge } => cmd_sign(slot, &challenge),
        Command::VerifyPin { pin } => cmd_verify_pin(&pin),
        Command::SetPin { old, new, io_key } => cmd_set_pin(&old, &new, &io_key),
        Command::UnblockPin { puk, new_pin, io_key } =>
        {
            cmd_unblock_pin(&puk, &new_pin, &io_key)
        }
        Command::SetPuk { old, new, io_key } => cmd_set_puk(&old, &new, &io_key),
        Command::EmergencyResetDangerous { io_key } =>
        {
            cmd_emergency_reset_dangerous(&io_key)
        }
        Command::PinStatus => cmd_pin_status(),
        Command::LockConfigDangerous { expected_crc } =>
        {
            cmd_lock_config_dangerous(&expected_crc)
        }
        Command::LockDataDangerous { expected_crc } =>
        {
            cmd_lock_data_dangerous(&expected_crc)
        }
        Command::LockSlotDangerous { slot } => cmd_lock_slot_dangerous(slot),
    }
}

fn cmd_info() -> Result<()>
{
    let device = device::open()?;
    let payload = device::send_command(&device, CommandOpcode::Info.as_u8(), &[])?;
    if payload.len() != 14
    {
        bail!("unexpected Info payload length: {}", payload.len());
    }
    let revision: [u8; 4] = payload[0..4].try_into().unwrap();
    let serial: [u8; 9] = payload[4..13].try_into().unwrap();
    let is_provisioned = payload[13] != 0;
    println!("Chip revision    : {:02X} {:02X} {:02X} {:02X}",
        revision[0], revision[1], revision[2], revision[3]);
    println!("Serial number    : {}", hex::encode_upper(serial));
    println!("Provisioned      : {}", if is_provisioned { "yes" } else { "no (zones unlocked)" });
    Ok(())
}

fn cmd_read_config() -> Result<()>
{
    let device = device::open()?;
    let mut full = [0u8; 128];
    for block in 0u8..=3
    {
        let payload = device::send_command
        (
            &device,
            CommandOpcode::ReadConfigZone.as_u8(),
            &[block],
        )?;
        if payload.len() != 32
        {
            bail!("ReadConfigZone block {block}: expected 32 bytes, got {}", payload.len());
        }
        let start = (block as usize) * 32;
        full[start..start + 32].copy_from_slice(&payload);
    }
    for (i, b) in full.iter().enumerate()
    {
        if i % 16 == 0
        {
            if i != 0 { println!(); }
            print!("{:03}:  ", i);
        }
        print!("{:02x} ", b);
    }
    println!();
    Ok(())
}

fn cmd_write_config(path: &str) -> Result<()>
{
    let blob = fs::read(path)
        .with_context(|| format!("failed to read config blob from {path}"))?;
    if blob.len() != 128
    {
        bail!("config blob must be exactly 128 bytes, got {}", blob.len());
    }
    let device = device::open()?;
    // Send 4 writes, one per 32-byte block.
    for block in 0u8..=3
    {
        let mut payload = [0u8; 33];
        payload[0] = block;
        let start = (block as usize) * 32;
        payload[1..33].copy_from_slice(&blob[start..start + 32]);
        device::send_command
        (
            &device,
            CommandOpcode::WriteConfigZone.as_u8(),
            &payload,
        )?;
        println!("wrote block {block}");
    }
    Ok(())
}

fn cmd_read_config_slot(slot: u8) -> Result<()>
{
    let device = device::open()?;
    let payload = device::send_command
    (
        &device,
        CommandOpcode::ReadConfigSlot.as_u8(),
        &[slot],
    )?;
    if payload.len() != 4
    {
        bail!("unexpected ReadConfigSlot payload length: {}", payload.len());
    }
    let slot_config = u16::from_le_bytes([payload[0], payload[1]]);
    let key_config  = u16::from_le_bytes([payload[2], payload[3]]);
    println!("Slot {slot} configuration:");
    println!("  SlotConfig: 0x{:04X}  ({} {})",
        slot_config,
        format_args!("{:08b}", payload[1]),
        format_args!("{:08b}", payload[0]),
    );
    println!("  KeyConfig : 0x{:04X}  ({} {})",
        key_config,
        format_args!("{:08b}", payload[3]),
        format_args!("{:08b}", payload[2]),
    );
    Ok(())
}

fn cmd_provision_slot(slot: u8, value_hex: &str) -> Result<()>
{
    let value = parse_hex_array::<32>(value_hex, "value")?;
    let mut payload = [0u8; 1 + 32];
    payload[0] = slot;
    payload[1..].copy_from_slice(&value);

    let device = device::open()?;
    device::send_command
    (
        &device,
        CommandOpcode::ProvisionSlot.as_u8(),
        &payload,
    )?;
    println!("Slot {slot} written (cleartext, {} bytes).", value.len());
    Ok(())
}

/// Provision a fresh chip in one orchestrated pass.
///
/// Sequence:
/// 1. `Info` to capture the chip serial.
/// 2. `ProvisionIoKey` -> chip generates random 32 bytes, writes
///    slot 8, returns the key.
/// 3. `ProvisionInitialPin` -> chip writes SHA-256("0000" || salt)
///    to slot 5.
/// 4. `ProvisionInitialPuk` -> chip generates 8-digit PUK, writes
///    hash to slot 6, returns the PUK.
/// 5. `GenKey --slot 0` -> chip generates primary ECC key on chip.
/// 6. Write the IO key + PUK + serial to `secrets_file` (JSON) and
///    print on stdout.
///
/// Refuses to overwrite an existing `secrets_file`: the caller must
/// move or delete an existing one to re-provision.
fn cmd_provision_token(secrets_file_path: &str) -> Result<()>
{
    use std::path::Path;
    let secrets_path = Path::new(secrets_file_path);
    if secrets_path.exists()
    {
        bail!(
            "secrets file `{secrets_file_path}` already exists, refusing to overwrite. \
             Move it aside or pick a different path."
        );
    }

    let device = device::open()?;

    // 1. Info: capture serial.
    let info = device::send_command(&device, CommandOpcode::Info.as_u8(), &[])?;
    if info.len() != 14
    {
        bail!("unexpected Info payload: {} bytes", info.len());
    }
    let serial_hex = hex::encode_upper(&info[4..13]);
    let already_provisioned = info[13] != 0;
    if already_provisioned
    {
        bail!("chip reports it is already provisioned (both zones locked). Refusing.");
    }
    println!("Chip serial : {serial_hex}");

    // 2. IO key.
    println!("Generating IO key...");
    let io_key_bytes = device::send_command(&device, CommandOpcode::ProvisionIoKey.as_u8(), &[])?;
    if io_key_bytes.len() != 32
    {
        bail!("unexpected IO key length: {}", io_key_bytes.len());
    }
    let io_key_hex = hex::encode_upper(&io_key_bytes);
    println!("IO key written to slot 8.");

    // 3. Initial PIN.
    println!("Writing default PIN hash to slot 5...");
    device::send_command(&device, CommandOpcode::ProvisionInitialPin.as_u8(), &[])?;

    // 4. Initial PUK.
    println!("Generating PUK...");
    let puk_bytes = device::send_command(
        &device,
        CommandOpcode::ProvisionInitialPuk.as_u8(),
        &[],
    )?;
    if puk_bytes.len() != 8
    {
        bail!("unexpected PUK length: {}", puk_bytes.len());
    }
    let puk_str = core::str::from_utf8(&puk_bytes)
        .context("PUK is not valid UTF-8")?
        .to_string();

    // 5. Primary identity key.
    println!("Generating ECC P-256 key in slot 0...");
    let pubkey = device::send_command(&device, CommandOpcode::GenKey.as_u8(), &[0u8])?;
    if pubkey.len() != 64
    {
        bail!("unexpected pubkey length: {}", pubkey.len());
    }
    let pubkey_x = hex::encode_upper(&pubkey[..32]);
    let pubkey_y = hex::encode_upper(&pubkey[32..]);

    // 6. Persist to JSON.
    let json = format!
    (
        "{{\n  \"chip_serial\": \"{serial_hex}\",\n  \
         \"io_key\": \"{io_key_hex}\",\n  \
         \"initial_puk\": \"{puk_str}\",\n  \
         \"primary_pubkey_x\": \"{pubkey_x}\",\n  \
         \"primary_pubkey_y\": \"{pubkey_y}\"\n}}\n"
    );
    fs::write(secrets_path, &json)
        .with_context(|| format!("failed to write secrets to {secrets_file_path}"))?;

    println!();
    println!("=== PROVISIONING DONE ===");
    println!("Chip serial      : {serial_hex}");
    println!("IO key           : {io_key_hex}");
    println!("Initial PIN      : 0000");
    println!("Initial PUK      : {puk_str}");
    println!("Primary pubkey X : {pubkey_x}");
    println!("Primary pubkey Y : {pubkey_y}");
    println!();
    println!("Secrets written to: {secrets_file_path}");
    println!();
    println!("WRITE THE PUK AND IO KEY DOWN NOW. There is no way to recover");
    println!("them after this command exits. The secrets file is your");
    println!("only durable copy.");
    println!();
    println!("Next step: lock the data zone with");
    println!("  hsm-host lock-data-DANGEROUS --expected-crc <CRC>");
    println!("once you have verified the slot contents via `read-config`.");
    Ok(())
}

fn cmd_get_pubkey(slot: u8) -> Result<()>
{
    let device = device::open()?;
    let payload = device::send_command
    (
        &device,
        CommandOpcode::GetPubkey.as_u8(),
        &[slot],
    )?;
    if payload.len() != 64
    {
        bail!("unexpected GetPubkey payload length: {}", payload.len());
    }
    println!("X: {}", hex::encode_upper(&payload[..32]));
    println!("Y: {}", hex::encode_upper(&payload[32..]));
    Ok(())
}

fn cmd_genkey(slot: u8) -> Result<()>
{
    let device = device::open()?;
    let payload = device::send_command
    (
        &device,
        CommandOpcode::GenKey.as_u8(),
        &[slot],
    )?;
    if payload.len() != 64
    {
        bail!("unexpected GenKey payload length: {}", payload.len());
    }
    println!("New public key for slot {slot}:");
    println!("X: {}", hex::encode_upper(&payload[..32]));
    println!("Y: {}", hex::encode_upper(&payload[32..]));
    Ok(())
}

fn cmd_sign(slot: u8, challenge: &str) -> Result<()>
{
    let digest = parse_hex_array::<32>(challenge, "challenge")?;
    let mut payload = [0u8; 33];
    payload[0] = slot;
    payload[1..].copy_from_slice(&digest);

    let device = device::open()?;
    println!("touch the dongle within 30s...");
    let response = device::send_command
    (
        &device,
        CommandOpcode::Sign.as_u8(),
        &payload,
    )?;
    if response.len() != 64
    {
        bail!("unexpected Sign response length: {}", response.len());
    }
    println!("R: {}", hex::encode_upper(&response[..32]));
    println!("S: {}", hex::encode_upper(&response[32..]));
    Ok(())
}

fn cmd_verify_pin(pin: &str) -> Result<()>
{
    let pin_bytes = pin.as_bytes();
    if pin_bytes.len() != 4
    {
        bail!("PIN must be exactly 4 digits, got {}", pin_bytes.len());
    }
    let device = device::open()?;
    device::send_command
    (
        &device,
        CommandOpcode::VerifyPin.as_u8(),
        pin_bytes,
    )?;
    println!("PIN accepted, session opened (30s window).");
    Ok(())
}

fn cmd_set_pin(old: &str, new: &str, io_key_hex: &str) -> Result<()>
{
    let old_bytes = check_pin(old, "old")?;
    let new_bytes = check_pin(new, "new")?;
    let io_key = parse_hex_array::<32>(io_key_hex, "io-key")?;

    // set-pin re-verifies `old` against the chip via CheckMac. No
    // separate verify-pin is needed before this call. The verify
    // consumes one Counter0 attempt internally (refreshed on success).
    let mut payload = [0u8; 4 + 4 + 32];
    payload[..4].copy_from_slice(&old_bytes);
    payload[4..8].copy_from_slice(&new_bytes);
    payload[8..].copy_from_slice(&io_key);

    let device = device::open()?;
    device::send_command(&device, CommandOpcode::SetPin.as_u8(), &payload)?;
    println!("PIN changed.");
    Ok(())
}

fn cmd_unblock_pin(puk: &str, new_pin: &str, io_key_hex: &str) -> Result<()>
{
    let puk_bytes = check_puk(puk)?;
    let new_pin_bytes = check_pin(new_pin, "new-pin")?;
    let io_key = parse_hex_array::<32>(io_key_hex, "io-key")?;

    let mut payload = [0u8; 8 + 4 + 32];
    payload[..8].copy_from_slice(&puk_bytes);
    payload[8..12].copy_from_slice(&new_pin_bytes);
    payload[12..].copy_from_slice(&io_key);

    let device = device::open()?;
    device::send_command(&device, CommandOpcode::UnblockPin.as_u8(), &payload)?;
    println!("PIN reset via PUK, fresh tries window granted.");
    Ok(())
}

fn cmd_set_puk(old: &str, new: &str, io_key_hex: &str) -> Result<()>
{
    let old_bytes = check_puk(old)?;
    let new_bytes = check_puk(new)?;
    let io_key = parse_hex_array::<32>(io_key_hex, "io-key")?;

    let mut payload = [0u8; 8 + 8 + 32];
    payload[..8].copy_from_slice(&old_bytes);
    payload[8..16].copy_from_slice(&new_bytes);
    payload[16..].copy_from_slice(&io_key);

    let device = device::open()?;
    device::send_command(&device, CommandOpcode::SetPuk.as_u8(), &payload)?;
    println!("PUK changed.");
    Ok(())
}

fn cmd_emergency_reset_dangerous(io_key_hex: &str) -> Result<()>
{
    let io_key = parse_hex_array::<32>(io_key_hex, "io-key")?;

    println!();
    println!("=== EMERGENCY RESET -- LAST-CHANCE RECOVERY ===");
    println!();
    println!("This command is only intended for the case where you have");
    println!("forgotten BOTH the PIN and the PUK, AND have tried enough times");
    println!("on each to exhaust both retry batches. The token will refuse");
    println!("this operation otherwise.");
    println!();
    println!("If you go through with it:");
    println!(" - ALL identity ECC private keys (slots 0..=4 and 7) are");
    println!("   destroyed. Any signature made under those keys cannot be");
    println!("   reproduced. Public keys you published become useless.");
    println!(" - PIN is reset to '0000'.");
    println!(" - A fresh random PUK is generated and printed ONCE.");
    println!(" - You get one fresh batch of PIN attempts and one fresh");
    println!("   batch of PUK attempts. The chip's hardware counters are");
    println!("   still consumed; you cannot do this indefinitely.");
    println!();
    println!("If you remember either the PIN or the PUK, STOP HERE and use");
    println!("the appropriate command instead:");
    println!("   PUK known  -> `hsm-host unblock-pin`");
    println!();
    confirm_interactive("EMERGENCY-RESET")?;

    let mut payload = [0u8; 4 + 32];
    payload[..4].copy_from_slice(&EMERGENCY_RESET_MAGIC);
    payload[4..].copy_from_slice(&io_key);

    let device = device::open()?;
    let response = device::send_command(
        &device,
        CommandOpcode::EmergencyReset.as_u8(),
        &payload,
    )?;
    if response.len() != 8
    {
        bail!("unexpected response length: {} (expected 8 for the new PUK)", response.len());
    }
    let new_puk = core::str::from_utf8(&response)
        .context("new PUK is not valid UTF-8")?;
    println!();
    println!("Emergency reset complete.");
    println!(" - All identity keys regenerated (slots 0..=4 and 7).");
    println!(" - PIN reset to: 0000");
    println!(" - NEW PUK     : {new_puk}");
    println!();
    println!("WRITE THE PUK DOWN NOW. It cannot be retrieved later.");
    println!("Change the default PIN immediately.");
    Ok(())
}

fn cmd_pin_status() -> Result<()>
{
    let device = device::open()?;
    let payload = device::send_command
    (
        &device,
        CommandOpcode::GetPinStatus.as_u8(),
        &[],
    )?;
    if payload.len() != 3
    {
        bail!("unexpected PinStatus payload: {} bytes", payload.len());
    }
    println!("PIN tries remaining: {}", payload[0]);
    println!("PUK tries remaining: {}", payload[1]);
    println!("Session active     : {}", payload[2] != 0);
    Ok(())
}

fn cmd_lock_config_dangerous(expected_crc_hex: &str) -> Result<()>
{
    let expected = parse_u16_hex(expected_crc_hex, "expected-crc")?;
    println!();
    println!("=== LOCK CONFIG ZONE : IRREVERSIBLE ===");
    println!("Expected config CRC-16: 0x{expected:04X}");
    println!();
    println!("This permanently freezes the config zone of the ATECC chip.");
    println!("Slot policies, key configs, and counters can never be changed");
    println!("again. If the CRC of the config currently on the chip does not");
    println!("match 0x{expected:04X}, the chip will refuse and report an error.");
    println!();
    confirm_interactive("LOCK-CONFIG")?;

    let mut payload = [0u8; 6];
    payload[..4].copy_from_slice(&LOCK_CONFIG_MAGIC);
    payload[4..].copy_from_slice(&expected.to_le_bytes());

    let device = device::open()?;
    device::send_command(&device, CommandOpcode::LockConfigZone.as_u8(), &payload)?;
    println!("Config zone locked.");
    Ok(())
}

fn cmd_lock_data_dangerous(expected_crc_hex: &str) -> Result<()>
{
    let expected = parse_u16_hex(expected_crc_hex, "expected-crc")?;
    println!();
    println!("=== LOCK DATA ZONE : IRREVERSIBLE ===");
    println!("Expected data zone CRC-16: 0x{expected:04X}");
    println!();
    println!("This permanently freezes the data zone. Slots can no longer be");
    println!("written in cleartext; only the encrypted-write protocol against");
    println!("the IO key (slot 8) remains. Make sure provisioning is complete");
    println!("(PIN hash, PUK hash, IO key, identity keys) before doing this.");
    println!();
    println!("If the CRC of the data currently on the chip does not match");
    println!("0x{expected:04X}, the chip will refuse and report a CRC mismatch.");
    println!();
    confirm_interactive("LOCK-DATA")?;

    let mut payload = [0u8; 6];
    payload[..4].copy_from_slice(&LOCK_DATA_MAGIC);
    payload[4..].copy_from_slice(&expected.to_le_bytes());

    let device = device::open()?;
    device::send_command
    (
        &device,
        CommandOpcode::LockDataZone.as_u8(),
        &payload,
    )?;
    println!("Data zone locked.");
    Ok(())
}

fn cmd_lock_slot_dangerous(slot: u8) -> Result<()>
{
    println!();
    println!("=== LOCK SLOT {slot} : IRREVERSIBLE ===");
    println!();
    println!("Slot {slot} will no longer accept writes, even via the encrypted");
    println!("write protocol. The current contents are frozen for life.");
    println!();
    confirm_interactive(&format!("LOCK-SLOT-{slot}"))?;

    let mut payload = [0u8; 5];
    payload[..4].copy_from_slice(&LOCK_SLOT_MAGIC);
    payload[4] = slot;

    let device = device::open()?;
    device::send_command(&device, CommandOpcode::LockSlot.as_u8(), &payload)?;
    println!("Slot {slot} locked.");
    Ok(())
}

fn check_pin(pin: &str, name: &str) -> Result<[u8; 4]>
{
    if pin.len() != 4
    {
        bail!("{name} PIN must be 4 digits, got {}", pin.len());
    }
    let mut out = [0u8; 4];
    out.copy_from_slice(pin.as_bytes());
    Ok(out)
}

fn check_puk(puk: &str) -> Result<[u8; 8]>
{
    if puk.len() != 8
    {
        bail!("PUK must be 8 digits, got {}", puk.len());
    }
    let mut out = [0u8; 8];
    out.copy_from_slice(puk.as_bytes());
    Ok(out)
}

fn parse_hex_array<const N: usize>(s: &str, name: &str) -> Result<[u8; N]>
{
    let s = s.strip_prefix("0x").unwrap_or(s);
    let bytes = hex::decode(s)
        .with_context(|| format!("{name} is not valid hex"))?;
    if bytes.len() != N
    {
        bail!("{name} must be {N} bytes ({} hex chars), got {} bytes", N * 2, bytes.len());
    }
    let mut out = [0u8; N];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn parse_u16_hex(s: &str, name: &str) -> Result<u16>
{
    let s = s.strip_prefix("0x").unwrap_or(s);
    u16::from_str_radix(s, 16)
        .map_err(|e| anyhow!("{name} is not valid u16 hex: {e}"))
}

/// Print a confirmation prompt and read a line from stdin. Returns OK
/// only if the line matches `expected` exactly. Anything else aborts
/// with an error.
fn confirm_interactive(expected: &str) -> Result<()>
{
    print!("Type '{expected}' to confirm, anything else to abort: ");
    io::stdout().flush().ok();
    let mut buf = String::new();
    io::stdin().lock().read_line(&mut buf).context("failed to read stdin")?;
    let trimmed = buf.trim();
    if trimmed != expected
    {
        bail!("confirmation did not match (got {trimmed:?}), aborting");
    }
    Ok(())
}