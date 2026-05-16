//! Produce the 128-byte config zone blob for an ATECC608B configured per the
//! mini-HSM slot policy.

use anyhow::Result;
use clap::Parser;

#[derive(Parser, Debug)]
#[command(author, version, about)]
struct Cli
{
    /// Output file. Defaults to `config_zone.bin`.
    #[arg(short, long, default_value = "config_zone.bin")]
    output: String,

    /// Also write a human-readable annotation file next to the binary.
    #[arg(long)]
    annotate: bool,
}

fn main() -> Result<()>
{
    let _cli = Cli::parse();
    todo!("config zone bytes generation")
}
