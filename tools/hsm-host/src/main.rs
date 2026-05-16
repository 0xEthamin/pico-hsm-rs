//! CLI used to operate the mini-HSM dongle from a development host.

use anyhow::Result;
use clap::{Parser, Subcommand};

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
    /// Enumerate all USB HID devices and print those matching the mini-HSM
    /// vendor / product IDs.
    Enumerate,

    /// Send an `Info` request and pretty-print the response.
    Info,

    /// Read the chip's 128-byte config zone and dump it as hex.
    ReadConfig,

    /// Read the public key of a slot.
    GetPubkey
    {
        #[arg(long)]
        slot: u8,
    },

    /// Sign a 32-byte challenge after PIN + touch.
    Sign
    {
        #[arg(long)]
        slot:      u8,
        #[arg(long)]
        challenge: String,
    },

    /// Open a PIN session.
    VerifyPin
    {
        #[arg(long)]
        pin: String,
    },

    /// Change the PIN.
    SetPin
    {
        #[arg(long)]
        old: String,
        #[arg(long)]
        new: String,
    },

    /// Reset the PIN using the PUK.
    UnblockPin
    {
        #[arg(long)]
        puk:     String,
        #[arg(long)]
        new_pin: String,
    },

    /// Write the writable bytes of the config zone (provisioning).
    /// Reversible while the zone is unlocked.
    WriteConfig
    {
        #[arg(long)]
        path: String,
    },

    /// Lock the config zone. **Irreversible.** Requires the CRC-16 of the
    /// expected config to be passed explicitly as a safety check.
    #[command(name = "lock-config-DANGEROUS")]
    LockConfigDangerous
    {
        #[arg(long)]
        expected_crc: String,
    },

    /// Lock the data zone. **Irreversible.** Requires the magic word.
    #[command(name = "lock-data-DANGEROUS")]
    LockDataDangerous
    {
        #[arg(long)]
        magic: String,
    },
}

fn main() -> Result<()>
{
    let cli = Cli::parse();

    match cli.command
    {
        Command::Enumerate =>
        {
            todo!("enumerate USB HID devices")
        }
        _ =>
        {
            todo!("other subcommands")
        }
    }
}
