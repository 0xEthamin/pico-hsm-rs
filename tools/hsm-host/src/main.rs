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

    /// Write the writable bytes of the config zone (provisioning).
    /// Reversible while the zone is unlocked.
    WriteConfig
    {
        /// Path to the 128-byte config blob produced by
        /// `tools/config-generator`.
        #[arg(long)]
        path: String,
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

    /// Change the PUK. Requires an active PIN session.
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

    /// Revert the chip to factory state: regenerate identity keys,
    /// reset PIN to "0000". Requires the current PIN.
    FactoryReset
    {
        #[arg(long)]
        pin:    String,
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

    /// Lock the data zone. **Irreversible.** Requires an interactive
    /// confirmation.
    #[command(name = "lock-data-DANGEROUS")]
    LockDataDangerous,

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
        Command::WriteConfig { path } => cmd_write_config(&path),
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
        Command::FactoryReset { pin, io_key } => cmd_factory_reset(&pin, &io_key),
        Command::PinStatus => cmd_pin_status(),
        Command::LockConfigDangerous { expected_crc } =>
        {
            cmd_lock_config_dangerous(&expected_crc)
        }
        Command::LockDataDangerous => cmd_lock_data_dangerous(),
        Command::LockSlotDangerous { slot } => cmd_lock_slot_dangerous(slot),
    }
}

// ---------------------------------------------------------------------------
// Subcommand implementations
// ---------------------------------------------------------------------------

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
        let payload = device::send_command(
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
        device::send_command(
            &device,
            CommandOpcode::WriteConfigZone.as_u8(),
            &payload,
        )?;
        println!("wrote block {block}");
    }
    Ok(())
}

fn cmd_get_pubkey(slot: u8) -> Result<()>
{
    let device = device::open()?;
    let payload = device::send_command(
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
    let payload = device::send_command(
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
    let response = device::send_command(
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
    device::send_command(
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

fn cmd_factory_reset(pin: &str, io_key_hex: &str) -> Result<()>
{
    let pin_bytes = check_pin(pin, "pin")?;
    let io_key = parse_hex_array::<32>(io_key_hex, "io-key")?;

    println!("This will regenerate all identity keys and reset the PIN to '0000'.");
    println!("Previous public keys will be invalidated.");
    confirm_interactive("FACTORY-RESET")?;

    let mut payload = [0u8; 4 + 32];
    payload[..4].copy_from_slice(&pin_bytes);
    payload[4..].copy_from_slice(&io_key);

    let device = device::open()?;
    device::send_command(&device, CommandOpcode::FactoryReset.as_u8(), &payload)?;
    println!("Factory reset complete. New PIN: 0000. Verify and change it immediately.");
    Ok(())
}

fn cmd_pin_status() -> Result<()>
{
    let device = device::open()?;
    let payload = device::send_command(
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
    println!("=== LOCK CONFIG ZONE -- IRREVERSIBLE ===");
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

fn cmd_lock_data_dangerous() -> Result<()>
{
    println!();
    println!("=== LOCK DATA ZONE -- IRREVERSIBLE ===");
    println!();
    println!("This permanently freezes the data zone. Slots can no longer be");
    println!("written in cleartext; only the encrypted-write protocol against");
    println!("the IO key (slot 8) remains. Make sure provisioning is complete");
    println!("(PIN hash, PUK hash, IO key, identity keys) before doing this.");
    println!();
    confirm_interactive("LOCK-DATA")?;

    let device = device::open()?;
    device::send_command(
        &device,
        CommandOpcode::LockDataZone.as_u8(),
        &LOCK_DATA_MAGIC,
    )?;
    println!("Data zone locked.");
    Ok(())
}

fn cmd_lock_slot_dangerous(slot: u8) -> Result<()>
{
    println!();
    println!("=== LOCK SLOT {slot} -- IRREVERSIBLE ===");
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

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

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