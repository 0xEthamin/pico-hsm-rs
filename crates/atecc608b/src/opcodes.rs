//! Numeric constants of the ATECC608B protocol.
//!
//! Every byte value, command opcode, max execution time, polling parameter,
//! and packet size lives here. The rest of the driver imports symbols by name
//! and **never** uses magic numbers.
//!
//! Source of truth: Microchip CryptoAuthLib (`lib/calib/calib_command.h` and
//! `lib/calib/calib_execution.c`). Cross-references to the public summary
//! datasheet (DS40002239A) are included in comments where they exist.

// I2C addressing

/// Factory default 7-bit I2C address of an ATECC608B-SSHDA. Programmable via
/// the `ChipMode.I2C_Address` byte of the config zone, but never changed in
/// this project.
pub const I2C_ADDRESS: u8 = 0x60;

// Word addresses (first byte of every I2C transaction)

/// Word address sent before reading the response.
pub const WORD_ADDRESS_RESET: u8 = 0x00;
/// Word address that puts the chip in low-power sleep.
pub const WORD_ADDRESS_SLEEP: u8 = 0x01;
/// Word address that puts the chip in idle (keeps TempKey, drops the watchdog).
pub const WORD_ADDRESS_IDLE: u8 = 0x02;
/// Word address sent before every command packet.
pub const WORD_ADDRESS_COMMAND: u8 = 0x03;

// Wake timings

/// Minimum duration SDA must be held low to wake the chip (datasheet `tWLO`).
pub const WAKE_LOW_DURATION_US: u32 = 60;

/// Time to wait after the wake pulse before the first I2C transaction
/// (datasheet `tWHI`).
pub const WAKE_DELAY_US: u32 = 1_500;

/// Bytes returned by the chip after a successful wake.
pub const WAKE_RESPONSE_OK: [u8; 4] = [0x04, 0x11, 0x33, 0x43];

/// Bytes returned if the chip's self-test failed at wake.
pub const WAKE_RESPONSE_SELFTEST_FAIL: [u8; 4] = [0x04, 0x07, 0xC4, 0x40];

// Polling parameters

/// Time the driver waits between the command send and the first response read.
pub const POLLING_INIT_MS: u32 = 1;

/// Time the driver waits between two consecutive response reads.
pub const POLLING_PERIOD_MS: u32 = 2;

/// Upper bound on the total polling window before [`crate::AteccError::Timeout`].
pub const POLLING_MAX_MS: u32 = 2_500;

// Packet sizes

/// Maximum size of a command packet sent to the chip.
///
/// 1 (word addr) + 1 (count) + 1 (opcode) + 1 (param1) + 2 (param2)
/// + up to 155 bytes of data + 2 (CRC) = 163 bytes.
pub const MAX_PACKET_SIZE: usize = 163;

/// Maximum size of a response read from the chip.
pub const MAX_RESPONSE_SIZE: usize = 155;

// Command opcodes
// Source: `lib/calib/calib_command.h` of CryptoAuthLib.

/// `Info`     - retrieve revision / status / KeyValid.
pub const OP_INFO: u8 = 0x30;
/// `Random`   - produce 32 cryptographically random bytes.
pub const OP_RANDOM: u8 = 0x1B;
/// `Read`     - read 4 or 32 bytes from config / data / OTP.
pub const OP_READ: u8 = 0x02;
/// `Write`    - write 4 or 32 bytes to config / data / OTP.
pub const OP_WRITE: u8 = 0x12;
/// `Lock`     - irreversibly lock a zone or a slot.
pub const OP_LOCK: u8 = 0x17;
/// `Nonce`    - load TempKey or `MsgDigBuf` for subsequent commands.
pub const OP_NONCE: u8 = 0x16;
/// `GenKey`   - generate a P-256 key pair in a slot, or compute a public key.
pub const OP_GENKEY: u8 = 0x40;
/// `Sign`     - produce an ECDSA P-256 signature.
pub const OP_SIGN: u8 = 0x41;
/// `Verify`   - verify an ECDSA P-256 signature.
pub const OP_VERIFY: u8 = 0x45;
/// `PrivWrite`- encrypted write of a P-256 private key into a slot.
pub const OP_PRIVWRITE: u8 = 0x46;
/// `Counter`  - read or increment the monotonic counters.
pub const OP_COUNTER: u8 = 0x24;
/// `CheckMac` - verify a precomputed MAC against a stored secret.
pub const OP_CHECKMAC: u8 = 0x28;
/// `GenDig`   - derive a digest into TempKey for use with `Write` encrypted.
pub const OP_GENDIG: u8 = 0x15;

// Expected execution time per command, in milliseconds
// Source: `lib/calib/calib_execution.c`, table for ATECC608-M1 (clock divider
// most commonly used). The driver uses these as the initial wait when
// polling; the actual ready time is observed via the response.

pub(crate) const EXEC_TIME_INFO_MS: u32 = 5;
pub(crate) const EXEC_TIME_RANDOM_MS: u32 = 23;
pub(crate) const EXEC_TIME_READ_MS: u32 = 5;
pub(crate) const EXEC_TIME_WRITE_MS: u32 = 45;
pub(crate) const EXEC_TIME_LOCK_MS: u32 = 35;
pub(crate) const EXEC_TIME_NONCE_MS: u32 = 20;
pub(crate) const EXEC_TIME_GENKEY_MS: u32 = 215;
pub(crate) const EXEC_TIME_SIGN_MS: u32 = 220;
pub(crate) const EXEC_TIME_VERIFY_MS: u32 = 295;
pub(crate) const EXEC_TIME_PRIVWRITE_MS: u32 = 50;
pub(crate) const EXEC_TIME_COUNTER_MS: u32 = 25;
pub(crate) const EXEC_TIME_CHECKMAC_MS: u32 = 40;
pub(crate) const EXEC_TIME_GENDIG_MS: u32 = 25;
