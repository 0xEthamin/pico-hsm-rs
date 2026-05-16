//! Test vectors for the CRC-16/DNP implementation of the ATECC608B.
//!
//! Vectors come from:
//! - The packet examples in the CryptoAuthLib reference (`lib/calib/calib_command.c`).
//! - Manually computed values cross-checked with `crccalc.com` (poly 0x8005,
//!   init 0x0000, MSB-first, reflect=false, xorout=0x0000).

#[test]
#[ignore = "to be implemented in M1"]
fn placeholder_crc_test()
{
}
