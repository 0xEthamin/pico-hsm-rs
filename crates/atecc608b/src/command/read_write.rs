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

//! `Read` and `Write` commands.
//!
//! These access the config, data, or OTP zones. They support 4-byte and
//! 32-byte transfers. Writes to the data zone are subject to the per-slot
//! `SlotConfig.WriteConfig` rules captured in `crates/hsm-crypto-service`.
//!
//! # Address encoding
//!
//! The ATECC608B encodes the target of a Read or Write into the 16-bit
//! `param2` of the command frame. The format depends on the zone.
//!
//! - **Config zone**. The zone is 128 bytes laid out as 4 blocks of 32 bytes.
//!   Each block is addressable as 8 "words" of 4 bytes.
//!
//!   ```text
//!   bits 0..=2  : offset within block (word index, 0..=7).
//!   bits 3..=4  : block index (0..=3).
//!   bits 5..=15 : reserved (zero).
//!   ```
//!
//! - **OTP zone**. Same layout as the config zone but only 2 blocks of 32
//!   bytes (block index in 0..=1).
//!
//! - **Data zone**. One slot per row.
//!
//!   ```text
//!   bits 0..=2  : offset within block (word index).
//!   bits 3..=7  : slot index (0..=15).
//!   bits 8..=15 : block index.
//!   ```
//!
//! In 32-byte transfers the offset bits must be zero, the chip rejects the
//! command otherwise.
//!
//! # `param1` encoding
//!
//! `param1` carries the zone identifier in its low two bits, an optional
//! encryption flag, and a single "this is a 32-byte transfer" flag.
//!
//! ```text
//! bits 0..=1 : zone (0 = Config, 1 = OTP, 2 = Data).
//! bit  6     : 1 -> data field is encrypted with TempKey + MAC (Write only).
//! bit  7     : 1 -> 32-byte transfer, 0 -> 4-byte transfer.
//! ```
//!
//! Reference: `CryptoAuthLib` `lib/calib/calib_read.c` and
//! `lib/calib/calib_write.c`, constants `ATCA_ZONE_CONFIG`, `ATCA_ZONE_OTP`,
//! `ATCA_ZONE_DATA`, `ATCA_ZONE_READWRITE_32`, `ATCA_ZONE_ENCRYPTED`.

use crate::driver::AteccChannel;
use crate::error::AteccError;
use crate::hal::AteccHal;
use crate::opcodes::{EXEC_TIME_READ_MS, EXEC_TIME_WRITE_MS, OP_READ, OP_WRITE};
use crate::slot::Slot;

/// One of the three addressable zones of the ATECC608B.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Zone
{
    /// 128-byte configuration zone. Contains slot policies, counters, lock
    /// bytes, `KeyConfig`, and factory data (serial number, revision).
    Config,
    /// 64-byte one-time-programmable zone.
    Otp,
    /// 16 slots of variable size holding ECC keys and arbitrary data.
    Data,
}

impl Zone
{
    /// Numeric value of the zone as it appears in the low bits of `param1`.
    const fn as_param1_bits(self) -> u8
    {
        match self
        {
            Zone::Config => 0x00,
            Zone::Otp    => 0x01,
            Zone::Data   => 0x02,
        }
    }
}

/// Number of 32-byte blocks in the config zone (128 / 32 = 4).
pub(crate) const CONFIG_ZONE_BLOCK_COUNT: u8 = 4;

/// Size of the config zone in bytes.
pub(crate) const CONFIG_ZONE_SIZE: usize = 128;

/// Size of one block transferred in a 32-byte read or write.
pub const BLOCK_SIZE: usize = 32;

/// Size of one word transferred in a 4-byte read or write.
pub const WORD_SIZE: usize = 4;

/// Size of the MAC appended to an encrypted 32-byte write.
pub(crate) const ENCRYPTED_WRITE_MAC_SIZE: usize = 32;

/// Total size of the data field for an encrypted 32-byte write: 32 bytes of
/// ciphertext followed by 32 bytes of MAC.
pub const ENCRYPTED_WRITE_DATA_SIZE: usize = BLOCK_SIZE + ENCRYPTED_WRITE_MAC_SIZE;

/// Flag OR'd into `param1` to switch from a 4-byte to a 32-byte transfer.
const PARAM1_FLAG_32_BYTES: u8 = 0x80;

/// Flag OR'd into `param1` to indicate the data field is encrypted with
/// `TempKey` and is followed by a MAC. Only valid for 32-byte Writes.
const PARAM1_FLAG_ENCRYPTED: u8 = 0x40;

/// Build the `param2` address for a config or OTP zone access.
///
/// `block` indexes one of the 32-byte blocks of the zone. `offset_words`
/// indexes a 4-byte word inside that block. For 32-byte transfers
/// `offset_words` must be 0.
#[must_use]
pub const fn config_or_otp_address(block: u8, offset_words: u8) -> u16
{
    let block_bits = ((block & 0x03) as u16) << 3;
    let offset_bits = (offset_words & 0x07) as u16;
    block_bits | offset_bits
}

/// Build the `param2` address for a data zone access.
///
/// `slot` is the target slot. `block` is the 32-byte block within that slot
/// (slots have variable sizes, slot 8 alone has 11 blocks). `offset_words`
/// indexes a 4-byte word inside the block. For 32-byte transfers
/// `offset_words` must be 0.
#[must_use]
pub const fn data_address(slot: Slot, block: u8, offset_words: u8) -> u16
{
    let block_bits = (block as u16) << 8;
    let slot_bits = ((slot.as_u8() & 0x1F) as u16) << 3;
    let offset_bits = (offset_words & 0x07) as u16;
    block_bits | slot_bits | offset_bits
}

/// Compose the `param1` byte for a Read.
const fn read_param1(zone: Zone, is_32_bytes: bool) -> u8
{
    let flag = if is_32_bytes { PARAM1_FLAG_32_BYTES } else { 0 };
    zone.as_param1_bits() | flag
}

/// Compose the `param1` byte for a Write.
///
/// `encrypted` is only meaningful in 32-byte mode. The chip silently
/// accepts the bit in 4-byte mode and rejects the command at execution,
/// callers should pass `false` for `encrypted` when `is_32_bytes` is false.
const fn write_param1(zone: Zone, is_32_bytes: bool, encrypted: bool) -> u8
{
    let mut p1 = zone.as_param1_bits();
    if is_32_bytes
    {
        p1 |= PARAM1_FLAG_32_BYTES;
    }
    if encrypted
    {
        p1 |= PARAM1_FLAG_ENCRYPTED;
    }
    p1
}

impl<'a, H> AteccChannel<'a, H>
where
    H: AteccHal,
{
    /// Read a 4-byte word from the given zone at the given address.
    ///
    /// `address` is the raw 16-bit value encoded in `param2`. Callers
    /// generally build it with [`config_or_otp_address`] or [`data_address`].
    ///
    /// # Errors
    /// See [`Atecc::execute_command`]. In particular, reads of locked or
    /// permission-restricted regions surface as [`AteccError::Chip`] with
    /// the relevant status byte.
    pub(crate) async fn read_4
    (
        &mut self,
        zone: Zone,
        address: u16,
    ) -> Result<[u8; WORD_SIZE], AteccError<H::Error>>
    {
        // Response: count(1) + 4 data + crc(2) = 7 bytes.
        let mut response_buf = [0u8; 1 + WORD_SIZE + 2];
        let payload = self
            .execute_command
            (
                OP_READ,
                read_param1(zone, false),
                address,
                &[],
                EXEC_TIME_READ_MS,
                &mut response_buf,
            )
            .await?;

        let bytes: &[u8; WORD_SIZE] = payload
            .try_into()
            .map_err(|_| AteccError::MalformedResponse)?;
        Ok(*bytes)
    }

    /// Read a 32-byte block from the given zone at the given address.
    ///
    /// `address` is the raw 16-bit value encoded in `param2`. The offset
    /// bits must be zero, the chip rejects 32-byte transfers otherwise.
    ///
    /// # Errors
    /// See [`AteccChannel::execute_command`].
    pub(crate) async fn read_32
    (
        &mut self,
        zone: Zone,
        address: u16,
    ) -> Result<[u8; BLOCK_SIZE], AteccError<H::Error>>
    {
        // Response: count(1) + 32 data + crc(2) = 35 bytes.
        let mut response_buf = [0u8; 1 + BLOCK_SIZE + 2];
        let payload = self
            .execute_command
            (
                OP_READ,
                read_param1(zone, true),
                address,
                &[],
                EXEC_TIME_READ_MS,
                &mut response_buf,
            )
            .await?;

        let bytes: &[u8; BLOCK_SIZE] = payload
            .try_into()
            .map_err(|_| AteccError::MalformedResponse)?;
        Ok(*bytes)
    }

    /// Read the entire 128-byte config zone into `out`.
    ///
    /// Internally performs four 32-byte reads, one per block. The channel
    /// stays open between the reads.
    ///
    /// # Errors
    /// See [`AteccChannel::execute_command`]. The first failing block aborts
    /// the whole operation.
    pub async fn read_config_zone
    (
        &mut self,
        out: &mut [u8; CONFIG_ZONE_SIZE],
    ) -> Result<(), AteccError<H::Error>>
    {
        for block in 0..CONFIG_ZONE_BLOCK_COUNT
        {
            let address = config_or_otp_address(block, 0);
            let chunk = self.read_32(Zone::Config, address).await?;
            let start = usize::from(block) * BLOCK_SIZE;
            out[start..start + BLOCK_SIZE].copy_from_slice(&chunk);
        }
        Ok(())
    }

    /// Read a 4-byte word from a data slot.
    ///
    /// `block` and `offset_words` are interpreted per the ATECC608B address
    /// layout for the data zone.
    ///
    /// # Errors
    /// See [`Atecc::execute_command`].
    pub(crate) async fn read_slot_word
    (
        &mut self,
        slot: Slot,
        block: u8,
        offset_words: u8,
    ) -> Result<[u8; WORD_SIZE], AteccError<H::Error>>
    {
        self.read_4(Zone::Data, data_address(slot, block, offset_words)).await
    }

    /// Read a 32-byte block from a data slot.
    ///
    /// # Errors
    /// See [`Atecc::execute_command`].
    pub(crate) async fn read_slot_block
    (
        &mut self,
        slot: Slot,
        block: u8,
    ) -> Result<[u8; BLOCK_SIZE], AteccError<H::Error>>
    {
        self.read_32(Zone::Data, data_address(slot, block, 0)).await
    }

    /// Write a 4-byte word to the given zone at the given address.
    ///
    /// Cleartext only: encrypted writes are not supported in 4-byte mode
    /// (this is a chip limitation, not a driver one).
    ///
    /// # Errors
    /// See [`AteccChannel::execute_command_status`]. Writes to locked
    /// regions or to slots whose `SlotConfig.WriteConfig` forbids cleartext
    /// writes surface as [`AteccError::Chip`].
    pub async fn write_4
    (
        &mut self,
        zone: Zone,
        address: u16,
        data: &[u8; WORD_SIZE],
    ) -> Result<(), AteccError<H::Error>>
    {
        self.execute_command_status
        (
            OP_WRITE,
            write_param1(zone, false, false),
            address,
            data,
            EXEC_TIME_WRITE_MS,
        )
        .await
    }

    /// Write a 32-byte block to the given zone in cleartext.
    ///
    /// `address` must have its offset bits set to zero. The block index is
    /// the upper bits per the zone layout.
    ///
    /// # Errors
    /// See [`AteccChannel::execute_command_status`].
    pub async fn write_32
    (
        &mut self,
        zone: Zone,
        address: u16,
        data: &[u8; BLOCK_SIZE],
    ) -> Result<(), AteccError<H::Error>>
    {
        self.execute_command_status
        (
            OP_WRITE,
            write_param1(zone, true, false),
            address,
            data,
            EXEC_TIME_WRITE_MS,
        )
        .await
    }

    /// Write a 32-byte block to a data slot in encrypted mode.
    ///
    /// The caller must supply the ciphertext and the precomputed MAC. The
    /// derivation of both is the responsibility of the higher-level
    /// `hsm-crypto-service` (see its provisioning module).
    ///
    /// This entry point exists in the driver so that the encrypted-write
    /// path can be exercised against the mock HAL. It assumes the chip is
    /// already loaded with a fresh `GenDig`-derived `TempKey` for the I/O
    /// protection slot. Calling this without that prior step yields a chip
    /// error.
    ///
    /// # Errors
    /// See [`AteccChannel::execute_command_status`].
    pub async fn write_32_encrypted
    (
        &mut self,
        zone: Zone,
        address: u16,
        ciphertext_and_mac: &[u8; ENCRYPTED_WRITE_DATA_SIZE],
    ) -> Result<(), AteccError<H::Error>>
    {
        self.execute_command_status
        (
            OP_WRITE,
            write_param1(zone, true, true),
            address,
            ciphertext_and_mac,
            EXEC_TIME_WRITE_MS,
        )
        .await
    }

    /// Write a 4-byte word into a data slot in cleartext.
    ///
    /// # Errors
    /// See [`AteccChannel::execute_command_status`].
    pub async fn write_slot_word
    (
        &mut self,
        slot: Slot,
        block: u8,
        offset_words: u8,
        data: &[u8; WORD_SIZE],
    ) -> Result<(), AteccError<H::Error>>
    {
        self.write_4(Zone::Data, data_address(slot, block, offset_words), data).await
    }

    /// Write a 32-byte block into a data slot in cleartext.
    ///
    /// # Errors
    /// See [`AteccChannel::execute_command_status`].
    pub async fn write_slot_block
    (
        &mut self,
        slot: Slot,
        block: u8,
        data: &[u8; BLOCK_SIZE],
    ) -> Result<(), AteccError<H::Error>>
    {
        self.write_32(Zone::Data, data_address(slot, block, 0), data).await
    }
}

#[cfg(test)]
mod tests
{
    use super::*;

    #[test]
    fn read_param1_config_4_bytes_is_zero()
    {
        assert_eq!(read_param1(Zone::Config, false), 0x00);
    }

    #[test]
    fn read_param1_config_32_bytes_sets_flag()
    {
        assert_eq!(read_param1(Zone::Config, true), 0x80);
    }

    #[test]
    fn read_param1_data_4_bytes()
    {
        assert_eq!(read_param1(Zone::Data, false), 0x02);
    }

    #[test]
    fn read_param1_data_32_bytes()
    {
        assert_eq!(read_param1(Zone::Data, true), 0x82);
    }

    #[test]
    fn read_param1_otp_variants()
    {
        assert_eq!(read_param1(Zone::Otp, false), 0x01);
        assert_eq!(read_param1(Zone::Otp, true), 0x81);
    }

    #[test]
    fn write_param1_cleartext_variants_match_read_param1()
    {
        // Cleartext writes share the same bit layout as reads in p1.
        assert_eq!(write_param1(Zone::Config, false, false), 0x00);
        assert_eq!(write_param1(Zone::Data, true, false), 0x82);
        assert_eq!(write_param1(Zone::Otp, true, false), 0x81);
    }

    #[test]
    fn write_param1_encrypted_sets_bit_6()
    {
        assert_eq!(write_param1(Zone::Data, true, true), 0xC2);
        assert_eq!(write_param1(Zone::Config, true, true), 0xC0);
    }

    #[test]
    fn config_address_block_0_offset_0_is_zero()
    {
        assert_eq!(config_or_otp_address(0, 0), 0x0000);
    }

    #[test]
    fn config_address_block_index_in_bits_3_4()
    {
        assert_eq!(config_or_otp_address(1, 0), 0x0008);
        assert_eq!(config_or_otp_address(2, 0), 0x0010);
        assert_eq!(config_or_otp_address(3, 0), 0x0018);
    }

    #[test]
    fn config_address_offset_in_low_bits()
    {
        assert_eq!(config_or_otp_address(0, 1), 0x0001);
        assert_eq!(config_or_otp_address(0, 7), 0x0007);
        // Block 2, offset 3.
        assert_eq!(config_or_otp_address(2, 3), 0x0013);
    }

    #[test]
    fn config_address_truncates_oversized_fields()
    {
        // Block is masked to 2 bits, offset to 3 bits. Anything else is
        // silently dropped, callers are responsible for valid inputs.
        assert_eq!(config_or_otp_address(0xFF, 0xFF), 0x001F);
    }

    #[test]
    fn data_address_slot_5_block_0_offset_0()
    {
        let slot = Slot::const_new(5);
        assert_eq!(data_address(slot, 0, 0), 0x0028);
    }

    #[test]
    fn data_address_slot_8_block_0_offset_0()
    {
        let slot = Slot::const_new(8);
        assert_eq!(data_address(slot, 0, 0), 0x0040);
    }

    #[test]
    fn data_address_slot_0_block_1_offset_0()
    {
        let slot = Slot::const_new(0);
        assert_eq!(data_address(slot, 1, 0), 0x0100);
    }

    #[test]
    fn data_address_slot_15_block_0_offset_7()
    {
        let slot = Slot::const_new(15);
        // (15 << 3) | 7 = 0x78 | 0x07 = 0x7F.
        assert_eq!(data_address(slot, 0, 7), 0x007F);
    }

    #[test]
    fn encrypted_data_size_is_64_bytes()
    {
        assert_eq!(ENCRYPTED_WRITE_DATA_SIZE, 64);
    }
}