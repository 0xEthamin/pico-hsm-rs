//! Generator for the ATECC608B configuration zone blob used by the
//! mini-HSM.
//!
//! Produces a 128-byte binary file matching the specification documented
//! in `docs/config-zone-layout.md`. The bytes 0 to 15 (factory area) are
//! placeholders. They are not transmitted to the chip during the Write
//! command. Bytes 16 to 127 are the writable portion, which is what the
//! firmware writes to the chip during provisioning.
//!
//! See the documentation for the bit-by-bit justification of every value.

use std::fs;
use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::Parser;

mod annotate;
mod blob;
mod crc;

/// Expected CRC-16 of the writable portion (bytes 16 to 127) of the
/// generated blob. This is a constant safety check. If `blob::build()`
/// ever returns a different value, something has drifted from the
/// specification.
const EXPECTED_CRC: u16 = 0xCB23;

#[derive(Parser, Debug)]
#[command(author, version, about)]
struct Cli
{
    /// Path of the binary output. Defaults to `config_zone.bin` in the
    /// current directory.
    #[arg(short, long, default_value = "config_zone.bin")]
    output: PathBuf,

    /// Also write a human-readable annotation file next to the binary,
    /// with the same basename and the `.txt` extension.
    #[arg(long)]
    annotate: bool,

    /// Print the CRC-16 of the writable portion of the blob and exit
    /// without writing any file.
    #[arg(long, conflicts_with = "annotate")]
    crc_only: bool,
}

fn main() -> Result<()>
{
    let cli = Cli::parse();

    let blob = blob::build();

    let writable = &blob[16..128];
    let crc = crc::crc16(writable);

    if crc != EXPECTED_CRC
    {
        anyhow::bail!(
            "internal error: generated blob CRC is 0x{crc:04X} but spec says 0x{EXPECTED_CRC:04X}. \
             The generator is out of sync with docs/config-zone-layout.md.",
        );
    }

    if cli.crc_only
    {
        println!("0x{crc:04X}");
        return Ok(());
    }

    fs::write(&cli.output, blob)
        .with_context(|| format!("failed to write {}", cli.output.display()))?;
    println!("Wrote {} bytes to {}", blob.len(), cli.output.display());
    println!("CRC-16 of writable portion: 0x{crc:04X}");

    if cli.annotate
    {
        let annotation_path = cli.output.with_extension("txt");
        let annotation = annotate::format(&blob, crc);
        fs::write(&annotation_path, annotation)
            .with_context(|| format!("failed to write {}", annotation_path.display()))?;
        println!("Wrote annotation to {}", annotation_path.display());
    }

    Ok(())
}
