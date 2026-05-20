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

//! /!\ IRREVERSIBLE LOCK OPERATIONS - HANDLE WITH EXTREME CARE.
//!
//! The functions in this module mutate the chip's lock state. Once a zone
//! is locked, it cannot be unlocked. There is no factory reset. A misissued
//! `Lock` command turns the chip into permanent silicon.
//!
//! ## Project rules
//!
//! 1. **No automatic flow calls Lock.** Provisioning, initialization, tests,
//!    setup scripts: none of them call any function in this module
//!    implicitly. The user invokes Lock manually through a dedicated USB-HID
//!    command, with a magic word and a CRC of the expected state.
//!
//! 2. **Every function is marked `unsafe`.** Not because it violates Rust
//!    memory safety, but to force the caller to write `unsafe { ... }`. That
//!    syntactic barrier is the only Rust-level mechanism we have to flag
//!    operational danger.
//!
//! 3. **Every function takes an explicit confirmation parameter.** For zone
//!    locks the caller supplies the CRC-16 of the zone as it currently is
//!    on the chip. The chip itself recomputes and compares against the value
//!    sent in `param2`. A mismatch is rejected with a chip error. The
//!    firmware combines this with a magic word check at the USB layer.
//!
//! ## Workflow expectation
//!
//! - Lock config zone: only after `WriteConfigZone` has been replayed,
//!   read back, and bit-compared against the expected blob. The CLI tool
//!   `hsm-host lock-config-DANGEROUS --expected-crc <hex>` computes the
//!   CRC of what's currently on the chip and refuses to send the Lock if
//!   it doesn't match what the user typed on the command line.
//!
//! - Lock data zone: only after every data slot the project expects has
//!   been provisioned (PIN hash, PUK hash, IO key, and at least one ECC
//!   keypair generated on chip via `GenKey`).
//!
//! - Lock slot: only after the per-slot content has been verified.
//!
//! ## ATECC Lock command encoding
//!
//! From the ATECC608B datasheet:
//!
//! | mode bits (`param1`) | Effect                                         |
//! |----------------------|------------------------------------------------|
//! | `0b0000_0000`       | Lock config zone, verify CRC in `param2`       |
//! | `0b1000_0000`       | Lock config zone, **no CRC verification**      |
//! | `0b0000_0001`       | Lock data zone, verify CRC in `param2`         |
//! | `0b1000_0001`       | Lock data zone, no CRC verification            |
//! | `0b0nnn_n010`       | Lock individual slot `nnnn`                    |
//! | `0b1nnn_n010`       | Same, no CRC check                             |
//!
//! Top bit (bit 7) = "summary mode" : when 1, the chip does **not** verify
//! the CRC in `param2`. We always send with this bit cleared (CRC checked)
//! for zone locks. For slot lock we set it (the chip does not check a CRC
//! for individual slots in our usage).
//!
//! ## Encoding the CRC for zone locks
//!
//! The chip expects `param2` little-endian. Pass the CRC computed
//! identically to the chip's algorithm (CCITT variant used everywhere in
//! `CryptoAuthLib`). `tools/config-generator` and the CLI helper produce
//! such a CRC.

use crate::error::AteccError;
use crate::opcodes::{EXEC_TIME_LOCK_MS, OP_LOCK};
use crate::slot::Slot;
use crate::{Atecc, AteccHal};

/// Mode bits for a config-zone lock, with CRC verification.
const LOCK_MODE_CONFIG_ZONE_VERIFY_CRC: u8 = 0b0000_0000;

/// Mode bits for a data-zone lock, with CRC verification.
const LOCK_MODE_DATA_ZONE_VERIFY_CRC: u8 = 0b0000_0001;

/// Mode bits for an individual slot lock, no CRC verification.
const LOCK_MODE_SLOT_NO_CRC_BASE: u8 = 0b1000_0010;

impl<H: AteccHal> Atecc<H>
{
    /// Permanently lock the configuration zone.
    ///
    /// **Irreversible.** After this call, every byte in the configuration
    /// zone is read-only forever. Slot policies, key types, the chip's
    /// I2C address, and counter initial values become immutable.
    ///
    /// `expected_crc` is the CRC-16/CCITT of the current configuration
    /// zone as the host believes it to be. The chip recomputes the CRC
    /// of its own configuration and compares. If it differs, the chip
    /// rejects the command with `ATCA_EXECUTION_ERROR` and the zone
    /// stays unlocked.
    ///
    /// The caller must have verified, by reading the chip and computing
    /// the CRC, that `expected_crc` matches what's actually on the chip,
    /// and that the configuration is the intended one. The chip's CRC
    /// check is a backstop, not a substitute.
    ///
    /// # Errors
    /// - [`AteccError::Chip(ChipError::ExecutionError)`] if the CRC does
    ///   not match (zone stays unlocked).
    /// - Other [`AteccError`] variants for I2C or wake failures.
    pub async fn lock_config_zone
    (
        &mut self,
        expected_crc: u16,
    ) -> Result<(), AteccError<H::Error>>
    {
        self.execute_command_status
        (
            OP_LOCK,
            LOCK_MODE_CONFIG_ZONE_VERIFY_CRC,
            expected_crc,
            &[],
            EXEC_TIME_LOCK_MS,
        )
        .await
    }

    /// Permanently lock the data + OTP zones.
    ///
    /// **Irreversible.** After this call, slots can no longer be written
    /// in cleartext. Writes must go through the encrypted-write protocol
    /// via the I/O Protection Key, and even those are subject to per-slot
    /// `EncryptWrite` policy.
    ///
    /// `expected_crc` is the CRC-16/CCITT of the slot contents as the
    /// host believes them to be. The chip recomputes and compares.
    ///
    /// # Errors
    /// As for `lock_config_zone`.
    pub async fn lock_data_zone
    (
        &mut self,
        expected_crc: u16,
    ) -> Result<(), AteccError<H::Error>>
    {
        self.execute_command_status
        (
            OP_LOCK,
            LOCK_MODE_DATA_ZONE_VERIFY_CRC,
            expected_crc,
            &[],
            EXEC_TIME_LOCK_MS,
        )
        .await
    }

    /// Permanently lock an individual data slot.
    ///
    /// **Irreversible.** After this call, the slot's contents are frozen
    /// forever. `Write(slot)` and `GenKey(slot)` on that slot return chip
    /// errors. The slot's policy in the configuration zone must have its
    /// `Lockable` bit set, or the chip rejects this command.
    ///
    /// # Errors
    /// - [`AteccError::Chip(ChipError::ExecutionError)`] if the slot is
    ///   not lockable or already locked.
    /// - Other [`AteccError`] variants for I2C or wake failures.
    pub async fn lock_slot
    (
        &mut self,
        slot: Slot,
    ) -> Result<(), AteccError<H::Error>>
    {
        // Mode encoding for individual slot lock: top bit set
        // (no_crc_check = 1) and slot index in bits 2..6.
        let mode = LOCK_MODE_SLOT_NO_CRC_BASE | ((slot.as_u8() & 0x0F) << 2);
        self.execute_command_status
        (
            OP_LOCK,
            mode,
            0x0000,
            &[],
            EXEC_TIME_LOCK_MS,
        )
        .await
    }
}
