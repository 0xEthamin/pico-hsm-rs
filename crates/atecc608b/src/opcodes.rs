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

//! Numeric constants of the ATECC608B protocol.
//!
//! Every byte value, command opcode, max execution time, polling parameter,
//! and packet size lives here. The rest of the driver imports symbols by name
//! and **never** uses magic numbers.
//!
//! Source of truth: Microchip `CryptoAuthLib` (`lib/calib/calib_command.h` and
//! `lib/calib/calib_execution.c`). Cross-references to the public summary
//! datasheet (DS40002239A) are included in comments where they exist.

// I2C addressing

/// Factory default 7-bit I2C address of an ATECC608B-SSHDA. Programmable via
/// the `ChipMode.I2C_Address` byte of the config zone, but never changed in
/// this project.
pub(crate) const I2C_ADDRESS: u8 = 0x60;

// Word addresses (first byte of every I2C transaction)

/// Word address that puts the chip into deep sleep (clears volatile state).
pub(crate) const WORD_ADDRESS_SLEEP: u8 = 0x01;
/// Word address that puts the chip in idle (keeps `TempKey`, drops the watchdog).
pub(crate) const WORD_ADDRESS_IDLE: u8 = 0x02;
/// Word address sent before every command packet.
pub(crate) const WORD_ADDRESS_COMMAND: u8 = 0x03;

// Wake timings

/// Minimum duration SDA must be held low to wake the chip (datasheet `tWLO`).
pub const WAKE_LOW_DURATION_US: u32 = 60;

/// Time to wait after the wake pulse before the first I2C transaction.
///
/// The datasheet specifies two relevant timings here:
/// - `tWHI`: 1500 us minimum, the legacy I2C-bus-recovery delay,
/// - `tHTSU`: 4100 us maximum, the host-to-target setup time before the
///   chip will ACK its address.
///
/// `CryptoAuthLib` historically uses 1500 us and it works on most chip
/// revisions, but some 608B silicon needs the full `tHTSU` window. We
/// pick 4500 us as a single delay that covers both with margin. The
/// extra ~3 ms over the strict `tWHI` is invisible to the user (PIN
/// operations take tens of ms anyway) and removes a class of "first
/// transaction NACKs" bring-up bugs.
pub const WAKE_DELAY_US: u32 = 4_500;

/// Bytes returned by the chip after a successful wake.
pub(crate) const WAKE_RESPONSE_OK: [u8; 4] = [0x04, 0x11, 0x33, 0x43];

/// Bytes returned if the chip's self-test failed at wake.
pub(crate) const WAKE_RESPONSE_SELFTEST_FAIL: [u8; 4] = [0x04, 0x07, 0xC4, 0x40];

// Polling parameters

/// Time the driver waits between two consecutive response reads.
pub(crate) const POLLING_PERIOD_MS: u32 = 2;

/// Upper bound on the total polling window before [`crate::AteccError::Timeout`].
pub(crate) const POLLING_MAX_MS: u32 = 2_500;

// Packet sizes

/// Maximum size of a command packet sent to the chip, including the word
/// address byte prepended at the I2C level.
///
/// 1 (word addr) + 1 (count) + 1 (opcode) + 1 (param1) + 2 (param2)
/// + up to 155 bytes of data + 2 (CRC) = 163 bytes.
pub(crate) const MAX_PACKET_SIZE: usize = 163;

/// Maximum size of a response read from the chip.
pub(crate) const MAX_RESPONSE_SIZE: usize = 155;

/// Number of bytes a command frame contains besides its data payload.
///
/// Layout: count (1) + opcode (1) + param1 (1) + param2 (2) + crc (2) = 7.
/// This does not include the word address byte, which is prepended by the
/// I2C transmit routine and is not covered by the CRC.
pub(crate) const COMMAND_FRAME_OVERHEAD: usize = 7;

/// Maximum size of the data field of a command, equal to
/// `MAX_PACKET_SIZE - 1 (word addr) - COMMAND_FRAME_OVERHEAD = 155`.
pub(crate) const MAX_COMMAND_DATA_LEN: usize = MAX_PACKET_SIZE - 1 - COMMAND_FRAME_OVERHEAD;

// Command opcodes
// Source: `lib/calib/calib_command.h` of CryptoAuthLib.

/// `Info`     - retrieve revision / status / `KeyValid`.
pub(crate) const OP_INFO: u8 = 0x30;
/// `Random`   - produce 32 cryptographically random bytes.
pub(crate) const OP_RANDOM: u8 = 0x1B;
/// `Read`     - read 4 or 32 bytes from config / data / OTP.
pub(crate) const OP_READ: u8 = 0x02;
/// `Write`    - write 4 or 32 bytes to config / data / OTP.
pub(crate) const OP_WRITE: u8 = 0x12;
/// `Lock`     - irreversibly lock a zone or a slot.
pub(crate) const OP_LOCK: u8 = 0x17;
/// `Nonce`    - load `TempKey` or `MsgDigBuf` for subsequent commands.
pub(crate) const OP_NONCE: u8 = 0x16;
/// `GenKey`   - generate a P-256 key pair in a slot, or compute a public key.
pub(crate) const OP_GENKEY: u8 = 0x40;
/// `Sign`     - produce an ECDSA P-256 signature.
pub(crate) const OP_SIGN: u8 = 0x41;
/// `Verify`   - verify an ECDSA P-256 signature.
pub(crate) const OP_VERIFY: u8 = 0x45;
/// `PrivWrite`- encrypted write of a P-256 private key into a slot.
pub(crate) const OP_PRIVWRITE: u8 = 0x46;
/// `Counter`  - read or increment the monotonic counters.
pub(crate) const OP_COUNTER: u8 = 0x24;
/// `CheckMac` - verify a precomputed MAC against a stored secret.
pub(crate) const OP_CHECKMAC: u8 = 0x28;
/// `GenDig`   - derive a digest into `TempKey` for use with `Write` encrypted.
pub(crate) const OP_GENDIG: u8 = 0x15;

// Expected execution time per command, in milliseconds
// Source: `lib/calib/calib_execution.c`, table for ATECC608-M1 (clock divider
// most commonly used). The driver uses these as the initial wait when
// polling. The actual ready time is observed via the response.

/// Nominal execution time of `Info`, in milliseconds.
pub(crate) const EXEC_TIME_INFO_MS: u32 = 5;
/// Nominal execution time of `Random`, in milliseconds.
pub(crate) const EXEC_TIME_RANDOM_MS: u32 = 23;
/// Nominal execution time of `Read`, in milliseconds.
pub(crate) const EXEC_TIME_READ_MS: u32 = 5;
/// Nominal execution time of `Write`, in milliseconds.
pub(crate) const EXEC_TIME_WRITE_MS: u32 = 45;
/// Nominal execution time of `Lock`, in milliseconds.
pub(crate) const EXEC_TIME_LOCK_MS: u32 = 35;
/// Nominal execution time of `Nonce`, in milliseconds.
pub(crate) const EXEC_TIME_NONCE_MS: u32 = 20;
/// Nominal execution time of `GenKey`, in milliseconds.
pub(crate) const EXEC_TIME_GENKEY_MS: u32 = 215;
/// Nominal execution time of `Sign`, in milliseconds.
pub(crate) const EXEC_TIME_SIGN_MS: u32 = 220;
/// Nominal execution time of `Verify`, in milliseconds.
pub(crate) const EXEC_TIME_VERIFY_MS: u32 = 295;
/// Nominal execution time of `PrivWrite`, in milliseconds.
pub(crate) const EXEC_TIME_PRIVWRITE_MS: u32 = 50;
/// Nominal execution time of `Counter`, in milliseconds.
pub(crate) const EXEC_TIME_COUNTER_MS: u32 = 25;
/// Nominal execution time of `CheckMac`, in milliseconds.
pub(crate) const EXEC_TIME_CHECKMAC_MS: u32 = 40;
/// Nominal execution time of `GenDig`, in milliseconds.
pub(crate) const EXEC_TIME_GENDIG_MS: u32 = 25;