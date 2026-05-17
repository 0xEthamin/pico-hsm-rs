//! `Read` and `Write` commands.
//!
//! These access the config, data, or OTP zones. They support 4-byte and
//! 32-byte transfers. Writes to the data zone are subject to the per-slot
//! `SlotConfig.WriteConfig` rules captured in `crates/hsm-crypto-service`.
//!
//! Reference: CryptoAuthLib `lib/calib/calib_read.c` and `calib_write.c`.
