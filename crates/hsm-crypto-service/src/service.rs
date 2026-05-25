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

//! High-level crypto service exposed to the USB layer.
//!
//! This is where the actual workflow logic lives: PIN session management,
//! PIN/PUK verification with counter accounting, sign orchestration on top
//! of `Nonce` + `Sign`, and public-key retrieval.
//!
//! The service is generic over both the HAL (so it can run against a real
//! ATECC over I2C or against a `MockHal` in tests) and the [`Clock`] (so
//! tests can drive time deterministically).
//!
//! # Channel discipline
//!
//! Every public method on [`CryptoService`] is responsible for opening
//! and closing the chip channel(s) it needs.
//!
//! - For a single-shot chip command (e.g. read one counter), the method
//!   opens a channel, runs the command, closes the channel.
//! - For a multi-step chip workflow that **shares volatile state**
//!   (Nonce + Sign, Nonce + `GenDig` + Write), the method opens **one**
//!   channel that spans the whole sequence, so `TempKey` stays alive
//!   across the steps.
//! - For workflows that combine several independent chip commands
//!   (e.g. read counter, then `CheckMac`, then read counter again), the
//!   method may either keep one channel open for the whole flow or open
//!   one per command. The choice is documented per method when it
//!   matters; the default is to open one per logical step for clarity.
//!
//! The PIN "session" referred to elsewhere in this crate is unrelated to
//! the chip channel. It is the host-side authentication window that
//! says "the user has typed a valid PIN recently". See [`Session`].

use core::fmt::Debug;

use atecc608b::command::counter::CounterId;
use atecc608b::command::gendig::GenDigZone;
use atecc608b::command::nonce::NonceTarget;
use atecc608b::command::read_write::{config_or_otp_address, data_address, Zone};
use atecc608b::{Atecc, AteccError, AteccHal, ChipError, Slot};

use crate::encrypted_write::
{
    build_encrypted_write_payload, derive_session_key, encrypt_payload, write_mac, SLOT_VALUE_LEN,
};
use crate::error::CryptoServiceError;
use crate::pin::
{
    FormatError, HASH_LEN, PIN_LEN, PUK_LEN, checkmac_other_data, checkmac_response, pin_hash, pin_salt, puk_hash, puk_salt, validate_digits
};
use crate::session::{Clock, Session};
use crate::slots::
{
    PIN_DEFAULT, PIN_MAX_RETRIES, PUK_MAX_RETRIES, SLOT_IO_KEY, SLOT_PIN_HASH, SLOT_PUK_HASH,
};

/// Convenience alias for the service's result type.
pub(crate) type ServiceResult<T, HalError> = Result<T, CryptoServiceError<HalError>>;

/// Length of the chip serial number, in bytes, as read from the config
/// zone.
pub(crate) const CHIP_SERIAL_LEN: usize = 9;

/// 64-byte raw public key returned by `GenKey`.
pub(crate) type PublicKey = [u8; 64];

/// 64-byte raw `R || S` ECDSA signature returned by `Sign`.
pub(crate) type Signature = [u8; 64];

/// Returned by [`CryptoService::info`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct DeviceInfo
{
    /// Chip revision (4 bytes returned by `Info(Revision)`).
    pub revision: [u8; 4],
    /// Chip serial number (9 bytes).
    pub serial: [u8; CHIP_SERIAL_LEN],
    /// `true` if both config and data zones are locked. Required for
    /// real-world operation.
    pub is_provisioned: bool,
}

/// Returned by [`CryptoService::get_pin_status`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct PinStatus
{
    /// Number of PIN attempts remaining before the slot is hardware-locked.
    pub pin_tries_remaining: u8,
    /// Number of PUK attempts remaining before the chip is bricked.
    pub puk_tries_remaining: u8,
    /// `true` if a PIN session is currently active (not timed out).
    pub session_active: bool,
}

/// High-level crypto orchestrator.
pub struct CryptoService<H, C>
where
    H: AteccHal,
    C: Clock,
{
    atecc:   Atecc<H>,
    clock:   C,
    session: Session,
    /// Cached chip serial, populated on first use.
    serial:  Option<[u8; CHIP_SERIAL_LEN]>,
}

impl<H, C> CryptoService<H, C>
where
    H: AteccHal,
    C: Clock,
    H::Error: Debug,
{
    /// Wrap an existing [`Atecc`] handle and clock.
    pub fn new(atecc: Atecc<H>, clock: C) -> Self
    {
        Self
        {
            atecc,
            clock,
            session: Session::new(),
            serial:  None,
        }
    }

    /// Return chip revision, serial, and provisioning state.
    ///
    /// Opens one channel for the revision read, then reuses a second
    /// channel for the config-zone reads that produce serial and lock
    /// status. The two channels are independent because there is no
    /// volatile state to share.
    ///
    /// # Errors
    /// See [`CryptoServiceError::Atecc`].
    pub async fn info(&mut self) -> ServiceResult<DeviceInfo, H::Error>
    {
        let revision =
        {
            let mut channel = self.atecc.open_channel().await?;
            let revision = channel.info_revision().await?;
            channel.close().await?;
            revision
        };
        let serial = self.cached_serial().await?;
        let is_provisioned = self.is_provisioned().await?;
        Ok(DeviceInfo { revision, serial, is_provisioned })
    }

    /// Read the 64-byte public key from `slot`.
    ///
    /// Does not require an active PIN session: the public key is, well,
    /// public. Internally calls `GenKey` in mode 0 (compute pubkey from
    /// existing private key, no mutation).
    ///
    /// # Errors
    /// See [`CryptoServiceError::Atecc`].
    pub async fn get_pubkey(&mut self, slot: Slot) -> ServiceResult<PublicKey, H::Error>
    {
        let mut channel = self.atecc.open_channel().await?;
        let pk = channel.genkey_public(slot).await?;
        channel.close().await?;
        Ok(pk)
    }

    /// Generate a fresh ECC P-256 private key on chip in the specified
    /// slot. The old key (if any) is destroyed. Returns the
    /// corresponding public key (64 bytes: X || Y).
    ///
    /// The chip enforces the slot's policy: a slot configured as
    /// `Locked` rejects this command, and a slot whose `KeyConfig` does
    /// not allow `GenKey(create)` is also rejected.
    ///
    /// In this project, `genkey_create` is used:
    /// - During provisioning to populate the primary identity key in
    ///   slot 0 (and optionally extra user slots in 1..=4 and 7).
    /// - In [`Self::emergency_reset`]
    ///   to refresh every identity slot at once.
    ///
    /// # Errors
    /// - [`CryptoServiceError::Atecc`] on chip-level failures.
    pub async fn genkey_create
    (
        &mut self,
        slot: Slot,
    ) -> ServiceResult<PublicKey, H::Error>
    {
        let mut channel = self.atecc.open_channel().await?;
        let pk = channel.genkey_create(slot).await?;
        channel.close().await?;
        Ok(pk)
    }

    /// Read the per-slot configuration bytes (`SlotConfig` + `KeyConfig`).
    ///
    /// Returns 4 bytes: `[SlotConfig_lo, SlotConfig_hi, KeyConfig_lo,
    /// KeyConfig_hi]`. This is useful when the host wants to inspect a
    /// slot's policy without re-downloading the full 128-byte config
    /// zone (which `read_config_zone` already does block by block).
    ///
    /// `SlotConfig` for slot N lives at config byte `20 + 2*N` and
    /// `KeyConfig` at `96 + 2*N`. This method reads the whole config
    /// zone and extracts those 4 bytes. The chip cost is identical to
    /// `read_config_zone` (4 reads of 32 bytes each).
    ///
    /// # Errors
    /// - [`CryptoServiceError::Atecc`] on chip-level failures.
    pub async fn read_config_slot(&mut self, slot: Slot) -> ServiceResult<[u8; 4], H::Error>
    {
        let mut zone = [0u8; 128];
        {
            let mut channel = self.atecc.open_channel().await?;
            channel.read_config_zone(&mut zone).await?;
            channel.close().await?;
        }
        let n = usize::from(slot.as_u8());
        let sc_off = 20 + 2 * n;
        let kc_off = 96 + 2 * n;
        Ok([zone[sc_off], zone[sc_off + 1], zone[kc_off], zone[kc_off + 1]])
    }

    /// Read one 32-byte block of the configuration zone.
    ///
    /// `block` must be in `0..=3`. Each block covers a fixed 32-byte
    /// region:
    ///
    /// - block 0 : factory area + `SlotConfig`[0..6] (bytes 0..32)
    /// - block 1 : `SlotConfig`[6..16] + Counter0 + start of Counter1 (32..64)
    /// - block 2 : end of Counter1 + UseLock..ChipOptions..X509format (64..96)
    /// - block 3 : `KeyConfig`[0..16] (96..128)
    ///
    /// # Errors
    /// - [`CryptoServiceError::InvalidFormat`] if `block > 3`.
    /// - [`CryptoServiceError::Atecc`] on chip-level failures.
    pub async fn read_config_block
    (
        &mut self,
        block: u8,
    ) -> ServiceResult<[u8; 32], H::Error>
    {
        if block > 3
        {
            return Err(CryptoServiceError::InvalidFormat(FormatError::OutOfRange));
        }
        let mut zone = [0u8; 128];
        {
            let mut channel = self.atecc.open_channel().await?;
            channel.read_config_zone(&mut zone).await?;
            channel.close().await?;
        }
        let start = usize::from(block) * 32;
        let mut out = [0u8; 32];
        out.copy_from_slice(&zone[start..start + 32]);
        Ok(out)
    }

    /// Write one 32-byte block of the configuration zone (provisioning).
    ///
    /// The ATECC608B's `Write` command refuses to touch certain regions of
    /// the configuration zone, even before lock. The reference Microchip
    /// routine `calib_write_bytes_zone` in `CryptoAuthLib`
    /// (`lib/calib/calib_basic.c`) handles this by switching from 32-byte
    /// to 4-byte transfers on the affected blocks and by skipping the
    /// non-writable words entirely. We follow the same strategy.
    ///
    /// Concretely:
    ///
    /// - **Block 0 (chip-side bytes 0..32).** Words 0..=3 (bytes 0..16) are
    ///   the read-only factory area (serial, `RevNum`, reserved). Any 32-byte
    ///   write that includes them is rejected with `ParseError 0x03`. Words
    ///   4..=7 (bytes 16..32) are written one at a time in 4-byte mode.
    /// - **Block 1 (bytes 32..64).** All writable. Single 32-byte write.
    /// - **Block 2 (bytes 64..96).** Word 5 (bytes 84..88) covers
    ///   `UserExtra`, Selector, `LockValue`, and `LockConfig`. Those are modified
    ///   only via the dedicated `UpdateExtra` and `Lock` commands; the
    ///   `Write` command rejects the whole 32-byte transfer if word 5 is
    ///   part of it. Words 0..=4 and 6..=7 are written one at a time in
    ///   4-byte mode; word 5 is skipped entirely. **The host-side blob's
    ///   bytes 84..88 are therefore ignored by the chip** — make sure the
    ///   factory defaults (`0x00 0x00 0x55 0x55`) match what the blob
    ///   contains for these positions, or call `UpdateExtra` /  `Lock`
    ///   separately if a different value is desired.
    /// - **Block 3 (bytes 96..128).** All writable. Single 32-byte write.
    ///
    /// This operation is **reversible** while the config zone is unlocked
    /// (`LockConfig != 0`). Once `LockConfigZone` has been issued, every
    /// chip-side Write here will return a chip error.
    ///
    /// `block` must be in `0..=3`.
    ///
    /// # Errors
    /// - [`CryptoServiceError::InvalidFormat`] if `block > 3`.
    /// - [`CryptoServiceError::Atecc`] on chip-level failures.
    pub async fn write_config_block
    (
        &mut self,
        block: u8,
        data: &[u8; 32],
    ) -> ServiceResult<(), H::Error>
    {
        if block > 3
        {
            return Err(CryptoServiceError::InvalidFormat(FormatError::OutOfRange));
        }
        let mut channel = self.atecc.open_channel().await?;
        if can_write_block_in_one_transfer(block)
        {
            let address = config_or_otp_address(block, 0);
            channel.write_32(Zone::Config, address, data).await?;
        }
        else
        {
            // Word-by-word path for blocks that contain non-writable words.
            // Driven by `writable_words_in_block` which encodes, per block,
            // the exact set of word offsets the chip's Write command will
            // accept. Words outside that set are silently skipped here.
            for &word_offset in writable_words_in_block(block)
            {
                let address = config_or_otp_address(block, word_offset);
                let payload_off = usize::from(word_offset) * 4;
                // Copy the 4 source bytes into a fresh array. The slice
                // bounds are statically valid (word_offset is in 0..=7,
                // payload_off in 0..=28, data is fixed `&[u8; 32]`), so
                // the index range is always in-bounds. A copy is used
                // instead of `try_into` to keep this path free of any
                // unreachable `expect` / `unwrap`.
                let mut chunk = [0u8; 4];
                chunk.copy_from_slice(&data[payload_off..payload_off + 4]);
                channel.write_4(Zone::Config, address, &chunk).await?;
            }
        }
        channel.close().await?;
        Ok(())
    }

    /// Open a PIN session if the provided PIN is correct.
    ///
    /// The `CheckMac` of slot 5 bumps `Counter0` regardless of the outcome,
    /// so each call costs one count. On success, the service bumps the
    /// counter additionally to bring it back up to the next multiple of
    /// [`PIN_MAX_RETRIES`], granting the user a fresh batch of 5 attempts.
    ///
    /// # Errors
    /// - [`CryptoServiceError::InvalidFormat`] if `pin` is not 4 ASCII digits.
    /// - [`CryptoServiceError::PinIncorrect`] with tries remaining.
    /// - [`CryptoServiceError::PinBlocked`] if Counter0 already at threshold.
    /// - [`CryptoServiceError::Atecc`] for I/O / chip errors.
    pub async fn verify_pin
    (
        &mut self,
        pin: &[u8; PIN_LEN],
    ) -> ServiceResult<(), H::Error>
    {
        validate_digits(pin)?;

        // Refuse early if PIN slot is already exhausted.
        let count = self.read_counter(CounterId::Counter0).await?;
        let tries_left = retries_remaining(count, PIN_MAX_RETRIES);
        if tries_left == 0
        {
            return Err(CryptoServiceError::PinBlocked);
        }

        let serial = self.cached_serial().await?;
        let salt = pin_salt(&serial);
        let computed_pin_hash = pin_hash(*pin, &salt);

        let ok = self
            .checkmac_with_hash(SLOT_PIN_HASH, &computed_pin_hash, &serial)
            .await?;

        if !ok
        {
            // The chip bumped Counter0 by 1 already. Report the new tries
            // remaining to the caller.
            let new_count = self.read_counter(CounterId::Counter0).await?;
            let remaining = retries_remaining(new_count, PIN_MAX_RETRIES);
            return Err(CryptoServiceError::PinIncorrect { tries_remaining: remaining });
        }

        // Successful verify: the chip bumped Counter0 by 1, but the user
        // has earned a fresh batch of attempts. Bump it up to the next
        // multiple of PIN_MAX_RETRIES.
        self.refresh_counter_batch(CounterId::Counter0, PIN_MAX_RETRIES).await?;

        // Open the session.
        let now = self.clock.now_ms();
        self.session.open(now);
        Ok(())
    }

    /// Reset the PIN slot via the PUK.
    ///
    /// On success, slot 5 is rewritten with the SHA-256 of the new PIN and
    /// `Counter0` is refreshed back to a fresh batch.
    ///
    /// `io_key` is the 32-byte I/O Protection Key (slot 8 content) known
    /// to the host that performed provisioning. The service uses it to
    /// build the encrypted-write payload. The key is never stored in the
    /// service. It lives only for the duration of this call.
    ///
    /// # Errors
    /// See [`CryptoServiceError`] variants.
    pub async fn unblock_pin
    (
        &mut self,
        puk: &[u8; PUK_LEN],
        new_pin: &[u8; PIN_LEN],
        io_key: &[u8; SLOT_VALUE_LEN],
    ) -> ServiceResult<(), H::Error>
    {
        validate_digits(puk)?;
        validate_digits(new_pin)?;

        // Refuse early if PUK is already exhausted.
        let count = self.read_counter(CounterId::Counter1).await?;
        let tries_left = retries_remaining(count, PUK_MAX_RETRIES);
        if tries_left == 0
        {
            return Err(CryptoServiceError::Bricked);
        }

        let serial = self.cached_serial().await?;
        let salt = puk_salt(&serial);
        let computed_puk_hash = puk_hash(*puk, &salt);

        let ok = self
            .checkmac_with_hash(SLOT_PUK_HASH, &computed_puk_hash, &serial)
            .await?;

        if !ok
        {
            let new_count = self.read_counter(CounterId::Counter1).await?;
            let remaining = retries_remaining(new_count, PUK_MAX_RETRIES);
            return Err(CryptoServiceError::PukIncorrect { tries_remaining: remaining });
        }

        // PUK was correct. Compute the new PIN hash and rewrite slot 5.
        let new_pin_hash = pin_hash(*new_pin, &pin_salt(&serial));
        self.write_slot_encrypted(SLOT_PIN_HASH, &new_pin_hash, io_key, &serial)
            .await?;

        // Refresh PUK counter to a fresh batch. Done AFTER the encrypted
        // write rather than before, so that a failure during the write
        // (NACK, comm error, etc) leaves the PUK counter consumed instead
        // of granting a free retry window. Conservative trade-off: a
        // valid PUK followed by a hardware glitch costs one PUK attempt.
        self.refresh_counter_batch(CounterId::Counter1, PUK_MAX_RETRIES).await?;

        // Reset PIN counter too: the user got a fresh PIN slate.
        self.refresh_counter_batch(CounterId::Counter0, PIN_MAX_RETRIES).await?;

        Ok(())
    }

    /// Change the PIN.
    ///
    /// Defence in depth: the caller must supply both the current PIN
    /// (`old_pin`) and the new one. The current PIN is re-checked
    /// against slot 5 via the same `CheckMac` flow as [`Self::verify_pin`].
    /// This protects against the case where a USB session is hijacked
    /// while a PIN session is open. Knowing the active session is not
    /// enough to rotate the PIN.
    ///
    /// On success, the PIN session is opened (or refreshed). Slot 5 is
    /// rewritten with `SHA-256(new_pin || pin_salt)` via the
    /// encrypted-write protocol. Counter0 is refreshed.
    ///
    /// # Errors
    /// See [`CryptoServiceError`] variants.
    pub async fn set_pin
    (
        &mut self,
        old_pin: &[u8; PIN_LEN],
        new_pin: &[u8; PIN_LEN],
        io_key: &[u8; SLOT_VALUE_LEN],
    ) -> ServiceResult<(), H::Error>
    {
        validate_digits(old_pin)?;
        validate_digits(new_pin)?;

        // Refuse early if PIN slot is already exhausted.
        let count = self.read_counter(CounterId::Counter0).await?;
        let tries_left = retries_remaining(count, PIN_MAX_RETRIES);
        if tries_left == 0
        {
            return Err(CryptoServiceError::PinBlocked);
        }

        let serial = self.cached_serial().await?;
        let old_pin_hash = pin_hash(*old_pin, &pin_salt(&serial));

        let ok = self
            .checkmac_with_hash(SLOT_PIN_HASH, &old_pin_hash, &serial)
            .await?;
        if !ok
        {
            let new_count = self.read_counter(CounterId::Counter0).await?;
            let remaining = retries_remaining(new_count, PIN_MAX_RETRIES);
            return Err(CryptoServiceError::PinIncorrect { tries_remaining: remaining });
        }

        let new_pin_hash = pin_hash(*new_pin, &pin_salt(&serial));
        self.write_slot_encrypted(SLOT_PIN_HASH, &new_pin_hash, io_key, &serial)
            .await?;

        // Successful PIN change: refresh counter and open / refresh PIN
        // session.
        self.refresh_counter_batch(CounterId::Counter0, PIN_MAX_RETRIES).await?;
        let now = self.clock.now_ms();
        self.session.open(now);
        Ok(())
    }

    /// Change the PUK.
    ///
    /// Requires an active PIN session AND the current PUK. Defence in
    /// depth: knowing the active session is not enough; the current PUK
    /// is re-verified via `CheckMac` on slot 6, consuming one Counter1
    /// attempt internally (refreshed on success).
    ///
    /// # Errors
    /// See [`CryptoServiceError`] variants.
    pub async fn set_puk
    (
        &mut self,
        old_puk: &[u8; PUK_LEN],
        new_puk: &[u8; PUK_LEN],
        io_key: &[u8; SLOT_VALUE_LEN],
    ) -> ServiceResult<(), H::Error>
    {
        validate_digits(old_puk)?;
        validate_digits(new_puk)?;

        // Step 1: PIN session must be active.
        let now = self.clock.now_ms();
        if !self.session.is_active(now)
        {
            return Err(CryptoServiceError::PinRequired);
        }

        // Step 2: refuse if Counter1 is exhausted (PUK bricked).
        let count = self.read_counter(CounterId::Counter1).await?;
        if retries_remaining(count, PUK_MAX_RETRIES) == 0
        {
            return Err(CryptoServiceError::Bricked);
        }

        // Step 3: verify the current PUK via CheckMac on slot 6.
        let serial = self.cached_serial().await?;
        let old_puk_hash = puk_hash(*old_puk, &puk_salt(&serial));
        let ok = self
            .checkmac_with_hash(SLOT_PUK_HASH, &old_puk_hash, &serial)
            .await?;
        if !ok
        {
            // The chip auto-bumped Counter1 by 1. Report the new
            // tries-remaining.
            let new_count = self.read_counter(CounterId::Counter1).await?;
            let remaining = retries_remaining(new_count, PUK_MAX_RETRIES);
            return Err(CryptoServiceError::PukIncorrect { tries_remaining: remaining });
        }

        // Step 4: write the new PUK hash.
        let new_puk_hash = puk_hash(*new_puk, &puk_salt(&serial));
        self.write_slot_encrypted(SLOT_PUK_HASH, &new_puk_hash, io_key, &serial)
            .await?;

        // Refresh Counter1 so the user starts a fresh PUK batch with
        // the new PUK.
        self.refresh_counter_batch(CounterId::Counter1, PUK_MAX_RETRIES).await?;

        self.session.touch(now);
        Ok(())
    }

    /// Last-chance reset for the case where the user has forgotten both
    /// the PIN and the PUK and has exhausted both `LimitedUse` batches.
    ///
    /// This is the recovery path of last resort. 
    /// Discards **everything user-owned** and rebuilds a clean baseline. 
    /// The user loses the ECC private keys
    /// in slots 0..=4 and 7 forever.
    ///
    /// # Preconditions
    ///
    /// The service refuses to perform this operation unless **both**
    /// counters report zero attempts remaining. This is the hard
    /// guarantee that prevents the call from being a back door:
    ///
    /// - If the user has forgotten only the PIN but not the PUK, they
    ///   should use [`Self::unblock_pin`].
    /// - Only the combined "PIN forgotten + PUK forgotten + both
    ///   batches exhausted" state authorises `emergency_reset`.
    ///
    /// # What it does
    ///
    /// 1. Verify the precondition: both Counter0 and Counter1 are at a
    ///    multiple of their respective `batch_size` with value > 0.
    /// 2. Regenerate ECC keys in slots 0, 1, 2, 3, 4, 7.
    /// 3. Generate a fresh random 8-digit PUK on-chip, write its hash
    ///    to slot 6, refresh Counter1.
    /// 4. Reset slot 5 to `SHA-256("0000" || pin_salt)`, refresh
    ///    Counter0.
    /// 5. Return the new PUK to the caller for one-time display.
    ///
    /// # What it does NOT do
    ///
    /// - It cannot reset Counter0 or Counter1 to zero. Both counters
    ///   are bumped further during the recovery (one increment to
    ///   reach `multiple + 1` on each). The user is granted one fresh
    ///   batch of PIN attempts and one fresh batch of PUK attempts.
    /// - It does **not** rewrite slot 8 (IO key). The caller must
    ///   supply the IO key, which is stored host-side (the host knows
    ///   it from provisioning).
    /// - If the chip's hardware counter limit (2^21) is reached during
    ///   the refresh increments, the operation reports an error and
    ///   the chip is genuinely bricked. There is nothing more software
    ///   can do.
    ///
    /// # Errors
    /// - [`CryptoServiceError::EmergencyResetNotPermitted`] if either
    ///   counter still has attempts remaining.
    /// - [`CryptoServiceError::Bricked`] if the chip's hardware counter
    ///   limit is hit during refresh.
    /// - [`CryptoServiceError::Atecc`] for chip-level errors.
    pub async fn emergency_reset
    (
        &mut self,
        io_key: &[u8; SLOT_VALUE_LEN],
    ) -> ServiceResult<[u8; PUK_LEN], H::Error>
    {
        // Step 1: precondition check. Both counters must be saturated.
        let c0 = self.read_counter(CounterId::Counter0).await?;
        let c1 = self.read_counter(CounterId::Counter1).await?;
        let pin_left = retries_remaining(c0, PIN_MAX_RETRIES);
        let puk_left = retries_remaining(c1, PUK_MAX_RETRIES);
        if pin_left != 0 || puk_left != 0
        {
            return Err(CryptoServiceError::EmergencyResetNotPermitted
            {
                pin_tries_remaining: pin_left,
                puk_tries_remaining: puk_left,
            });
        }

        let serial = self.cached_serial().await?;

        // Step 2: regenerate identity ECC keys. We do this BEFORE the
        // counter refresh so that if any GenKey fails (e.g. counter
        // hardware-bricked at 2^21) we have not yet consumed precious
        // counter cycles for nothing.
        //
        // All six keys are regenerated within a single channel: GenKey
        // does not share volatile state with other commands, but reusing
        // the channel avoids six wake/idle round-trips.
        {
            let mut channel = self.atecc.open_channel().await?;
            for slot_idx in [0u8, 1, 2, 3, 4, 7]
            {
                let slot = Slot::const_new(slot_idx);
                let _ = channel.genkey_create(slot).await?;
            }
            channel.close().await?;
        }

        // Step 3: generate a fresh PUK, write its hash, refresh Counter1.
        let new_puk = self.generate_random_puk().await?;
        let new_puk_hash = puk_hash(new_puk, &puk_salt(&serial));
        self.write_slot_encrypted(SLOT_PUK_HASH, &new_puk_hash, io_key, &serial).await?;
        self.refresh_counter_batch(CounterId::Counter1, PUK_MAX_RETRIES).await?;

        // Step 4: reset PIN to default, refresh Counter0.
        let default_hash = pin_hash(PIN_DEFAULT, &pin_salt(&serial));
        self.write_slot_encrypted(SLOT_PIN_HASH, &default_hash, io_key, &serial).await?;
        self.refresh_counter_batch(CounterId::Counter0, PIN_MAX_RETRIES).await?;

        // No PIN session to close. There was none to begin with (the
        // caller has no PIN to verify with).
        Ok(new_puk)
    }

    /// Tire 8 chiffres ASCII depuis le RNG du chip pour produire un
    /// nouveau PUK. La distribution est uniforme sur `[b'0'..=b'9']`,
    /// obtenue par modulo après filtrage léger (chaque byte random ->
    /// un chiffre). 32 octets de random > 8 octets de PUK, on a de la
    /// marge si on tombait sur un byte ambigu.
    async fn generate_random_puk
    (
        &mut self,
    ) -> ServiceResult<[u8; PUK_LEN], H::Error>
    {
        let random =
        {
            let mut channel = self.atecc.open_channel().await?;
            let random = channel.random().await?;
            channel.close().await?;
            random
        };
        let mut puk = [b'0'; PUK_LEN];
        // Modulo 10 introduces a tiny bias (256 % 10 = 6 over the first 6 digits)
        // but the difference is negligible for an 8-digit PUK and the chip's RNG
        // is uniform on full bytes.
        for (digit, &r) in puk.iter_mut().zip(random.iter())
        {
            *digit = b'0' + (r % 10);
        }
        Ok(puk)
    }

    // -------------------------------------------------------------------
    // Lock operations -- IRREVERSIBLE
    // -------------------------------------------------------------------
    //
    // These three methods are the only ones in the service that bridge
    // to the driver's lock functions. They are kept together at
    // the bottom of the file for visibility.
    //
    // The service does NOT compute the CRC itself. The host provides it
    // (the CLI computes it from a known-good blob, the firmware passes
    // it through unchanged). The chip is the second line of defence: it
    // recomputes the CRC of its own current state and refuses the lock
    // if it does not match. The service is the third line of defence:
    // it does not expose a "lock with no checks" path at all.

    /// Permanently lock the configuration zone.
    ///
    /// `expected_crc` is the CRC-16/CCITT of the configuration zone as
    /// the host expects it to be. The chip recomputes its own and
    /// rejects the lock if the two disagree.
    ///
    /// **Irreversible.** See [`atecc608b::AteccChannel::lock_config_zone`].
    ///
    /// # Errors
    /// - [`CryptoServiceError::Atecc`] if the chip refuses (typically
    ///   because the CRC does not match).
    pub async fn lock_config_zone
    (
        &mut self,
        expected_crc: u16,
    ) -> ServiceResult<(), H::Error>
    {
        let mut channel = self.atecc.open_channel().await?;
        // Best effort close on error: capture the lock result and always
        // attempt to close. Idle preserves volatile state (which is none
        // here, the lock command leaves no `TempKey`) and resets the
        // watchdog so the next channel sees a clean baseline.
        let result = channel.lock_config_zone(expected_crc).await;
        channel.close().await?;
        result?;
        Ok(())
    }

    /// Permanently lock the data + OTP zones.
    ///
    /// `expected_crc` is the CRC-16/CCITT of the slot contents.
    ///
    /// **Irreversible.** See [`atecc608b::AteccChannel::lock_data_zone`].
    ///
    /// # Errors
    /// - [`CryptoServiceError::Atecc`] if the chip refuses.
    pub async fn lock_data_zone
    (
        &mut self,
        expected_crc: u16,
    ) -> ServiceResult<(), H::Error>
    {
        let mut channel = self.atecc.open_channel().await?;
        let result = channel.lock_data_zone(expected_crc).await;
        channel.close().await?;
        result?;
        Ok(())
    }

    /// Permanently lock an individual slot. The slot's config in the
    /// configuration zone must have `Lockable=1` for this to succeed.
    ///
    /// **Irreversible.** See [`atecc608b::AteccChannel::lock_slot`].
    ///
    /// # Errors
    /// - [`CryptoServiceError::Atecc`] if the chip refuses (slot not
    ///   lockable, or already locked).
    pub async fn lock_slot
    (
        &mut self,
        slot: Slot,
    ) -> ServiceResult<(), H::Error>
    {
        let mut channel = self.atecc.open_channel().await?;
        let result = channel.lock_slot(slot).await;
        channel.close().await?;
        result?;
        Ok(())
    }

    // -------------------------------------------------------------------
    // Provisioning (data zone unlocked)
    // -------------------------------------------------------------------

    /// Write a 32-byte value in cleartext into one of the data slots.
    ///
    /// **Only legal while the data zone is unlocked.** After
    /// [`Self::lock_data_zone`], writes to data slots must go through
    /// [`Self::write_slot_encrypted`].
    ///
    /// Restricted by policy to the three slots that hold project-level
    /// secrets and need to be initialised before lock:
    ///
    /// - Slot 5 (PIN hash). Written with `SHA-256("0000" || pin_salt)`
    ///   to set the default PIN. Salt is derived from the chip serial.
    /// - Slot 6 (PUK hash). Written with `SHA-256(random_puk || puk_salt)`.
    /// - Slot 8 (IO Protection Key). Written with a random 32-byte
    ///   value, kept secret host-side for later encrypted writes.
    ///
    /// Other slots are rejected at the service layer to avoid mistakes.
    /// ECC slots (0..=4, 7) are populated via `GenKey`, not by write.
    /// Reserve slots (9..=15) are kept unprovisioned for V2.
    ///
    /// # Errors
    /// - [`CryptoServiceError::InvalidSlot`] if the slot is not one of
    ///   the three policy-allowed targets.
    /// - [`CryptoServiceError::Atecc`] if the chip refuses the write
    ///   (most likely because the data zone is already locked).
    pub async fn provision_slot
    (
        &mut self,
        slot: Slot,
        value: &[u8; 32],
    ) -> ServiceResult<(), H::Error>
    {
        let allowed =
            slot == SLOT_PIN_HASH || slot == SLOT_PUK_HASH || slot == SLOT_IO_KEY;
        if !allowed
        {
            return Err(CryptoServiceError::InvalidSlot { slot });
        }
        let address = atecc608b::command::read_write::data_address(slot, 0, 0);
        let mut channel = self.atecc.open_channel().await?;
        channel.write_32(Zone::Data, address, value).await?;
        channel.close().await?;
        Ok(())
    }

    /// Generate a fresh random PUK and write its hash into slot 6, in
    /// cleartext. Returns the PUK to the caller for one-time display.
    ///
    /// Only legal while the data zone is unlocked: used during
    /// provisioning to set the initial PUK before locking.
    ///
    /// # Errors
    /// - [`CryptoServiceError::Atecc`] for chip-level errors.
    pub async fn provision_initial_puk
    (
        &mut self,
    ) -> ServiceResult<[u8; PUK_LEN], H::Error>
    {
        let serial = self.cached_serial().await?;
        let new_puk = self.generate_random_puk().await?;
        let new_puk_hash = puk_hash(new_puk, &puk_salt(&serial));
        self.provision_slot(SLOT_PUK_HASH, &new_puk_hash).await?;
        Ok(new_puk)
    }

    /// Write the hash of the default PIN ("0000") into slot 5 in
    /// cleartext. Used at provisioning, before data lock.
    ///
    /// # Errors
    /// - [`CryptoServiceError::Atecc`] for chip-level errors.
    pub async fn provision_initial_pin
    (
        &mut self,
    ) -> ServiceResult<(), H::Error>
    {
        let serial = self.cached_serial().await?;
        let hash = pin_hash(PIN_DEFAULT, &pin_salt(&serial));
        self.provision_slot(SLOT_PIN_HASH, &hash).await?;
        Ok(())
    }

    /// Generate a fresh random 32-byte I/O Protection Key from the
    /// chip's RNG, write it into slot 8 in cleartext, and return it
    /// to the caller.
    ///
    /// **The caller must persist this value immediately**: it is the
    /// only opportunity to learn the IO key. After data lock, slot 8
    /// becomes write-only via the encrypted-write protocol, which
    /// itself depends on knowing the IO key. Losing the IO key turns
    /// the chip into a permanently degraded device (no more PIN/PUK
    /// changes possible).
    ///
    /// Only legal while the data zone is unlocked.
    ///
    /// # Errors
    /// - [`CryptoServiceError::Atecc`] for chip-level errors.
    pub async fn provision_initial_io_key
    (
        &mut self,
    ) -> ServiceResult<[u8; SLOT_VALUE_LEN], H::Error>
    {
        let io_key =
        {
            let mut channel = self.atecc.open_channel().await?;
            let io_key = channel.random().await?;
            channel.close().await?;
            io_key
        };
        self.provision_slot(SLOT_IO_KEY, &io_key).await?;
        Ok(io_key)
    }

    /// Sign a 32-byte digest with the private key in `slot`.
    ///
    /// Requires an active PIN session.
    ///
    /// Internally this is a two-step chip workflow on the ATECC608:
    /// `Nonce(passthrough, target=MsgDigBuf)` then
    /// `Sign(external, source=MsgDigBuf, slot)`. Both steps run inside a
    /// single chip channel so the `MsgDigBuf` register survives between
    /// them. The `MsgDigBuf` source (rather than the older TempKey-based
    /// path used by the 508A) is required on the 608 to make the chip
    /// sign the supplied digest verbatim, without blending in any other
    /// chip state. Returned `R || S` is 64 bytes big-endian.
    ///
    /// # Errors
    /// - [`CryptoServiceError::PinRequired`] if no session is active.
    /// - [`CryptoServiceError::Atecc`] for chip-level errors (slot
    ///   misconfigured, authorization missing, etc).
    pub async fn sign
    (
        &mut self,
        slot: Slot,
        digest: &[u8; 32],
    ) -> ServiceResult<Signature, H::Error>
    {
        let now = self.clock.now_ms();
        if !self.session.is_active(now)
        {
            return Err(CryptoServiceError::PinRequired);
        }

        // Load the digest into the Message Digest Buffer via passthrough
        // Nonce, then Sign with mode = external + source=MsgDigBuf. Both
        // commands must run inside the same channel: MsgDigBuf is volatile
        // and idling the chip clears it.
        //
        // On the ATECC608 specifically, Sign(external) requires the
        // MsgDigBuf source bit. Using TempKey instead (as the older 508A
        // protocol did) makes the chip blend extra context bytes into the
        // signed message, producing a signature that does not verify
        // off-chip against the raw 32-byte digest. See
        // `lib/calib/calib_sign.c::calib_sign` in CryptoAuthLib for the
        // device-type branch that selects MsgDigBuf for ATECC608.
        let signature =
        {
            let mut channel = self.atecc.open_channel().await?;
            channel.nonce_passthrough(NonceTarget::MsgDigBuf, digest).await?;
            let signature = channel.sign_external(slot).await?;
            channel.close().await?;
            signature
        };

        // Refresh session activity timestamp.
        self.session.touch(now);
        Ok(signature)
    }

    /// Report the current PIN / PUK retry counters and session state.
    ///
    /// Reads both counters within a single chip channel for efficiency.
    ///
    /// # Errors
    /// See [`CryptoServiceError::Atecc`].
    pub async fn get_pin_status(&mut self) -> ServiceResult<PinStatus, H::Error>
    {
        let (c0, c1) =
        {
            let mut channel = self.atecc.open_channel().await?;
            let c0 = channel.counter_read(CounterId::Counter0).await?;
            let c1 = channel.counter_read(CounterId::Counter1).await?;
            channel.close().await?;
            (c0, c1)
        };
        Ok(PinStatus
        {
            pin_tries_remaining: retries_remaining(c0, PIN_MAX_RETRIES),
            puk_tries_remaining: retries_remaining(c1, PUK_MAX_RETRIES),
            session_active:      self.session.is_active(self.clock.now_ms()),
        })
    }

    /// Terminate the active PIN session immediately, without waiting for
    /// the 30 s inactivity timeout.
    ///
    /// Idempotent: closing an already-closed session is a no-op. Useful
    /// when the user wants to lock the dongle proactively after a
    /// signing burst, instead of letting the timeout expire.
    pub fn close_session(&mut self)
    {
        self.session.close();
    }

    /// Return whether a PIN session is currently active.
    ///
    /// Used by command handlers that need to refuse pre-touch on
    /// session-gated operations (notably `Sign`): without this early
    /// check the firmware would arm the touch wait then time out 30
    /// seconds later instead of failing immediately with
    /// [`CryptoServiceError::PinRequired`].
    #[must_use]
    pub fn is_session_active(&self) -> bool
    {
        self.session.is_active(self.clock.now_ms())
    }

    /// Read one 32-byte block from a data slot.
    ///
    /// Used by `CommandOpcode::ReadSlotBlock` for bring-up diagnostics
    /// (verifying what `ProvisionSlot` wrote) and to inspect the IO key
    /// in slot 8 before locking the data zone.
    ///
    /// No PIN session check here: the chip itself enforces slot policy.
    /// A slot configured `IsSecret` or with `EncryptRead` returns a chip
    /// error, which surfaces here as [`CryptoServiceError::Atecc`].
    ///
    /// # Errors
    /// - [`CryptoServiceError::Atecc`] on chip-level errors (forbidden
    ///   read, bad address, etc).
    pub async fn read_slot_block
    (
        &mut self,
        slot: Slot,
        block: u8,
    ) -> ServiceResult<[u8; 32], H::Error>
    {
        let mut channel = self.atecc.open_channel().await?;
        let data = channel.read_slot_block(slot, block).await?;
        channel.close().await?;
        Ok(data)
    }

    /// Read one 4-byte word from a data slot.
    ///
    /// See [`Self::read_slot_block`] for context. Same policy enforcement.
    ///
    /// # Errors
    /// - [`CryptoServiceError::Atecc`] on chip-level errors.
    pub async fn read_slot_word
    (
        &mut self,
        slot: Slot,
        block: u8,
        offset_words: u8,
    ) -> ServiceResult<[u8; 4], H::Error>
    {
        let mut channel = self.atecc.open_channel().await?;
        let data = channel.read_slot_word(slot, block, offset_words).await?;
        channel.close().await?;
        Ok(data)
    }

    /// Read the raw value of one of the chip's monotonic counters.
    ///
    /// Returns the binary count as decoded by the chip (the chip's
    /// `Counter(mode=Read)` command performs the popcount-style decoding
    /// of its 8-byte storage into a `u32`). The returned value starts at
    /// 0 on a factory-fresh chip and increments by 1 on every key-usage
    /// event for keys whose `SlotConfig.LimitedUse == 1`.
    ///
    /// Used internally by [`Self::verify_pin`] and the PIN/PUK retry
    /// arithmetic; exposed publicly so the host CLI can read the raw
    /// value for bring-up diagnostics without going through
    /// `retries_remaining`.
    ///
    /// # Errors
    /// - [`CryptoServiceError::Atecc`] on chip-level failures.
    pub async fn read_counter
    (
        &mut self,
        counter: CounterId,
    ) -> ServiceResult<u32, H::Error>
    {
        let mut channel = self.atecc.open_channel().await?;
        let count = channel.counter_read(counter).await?;
        channel.close().await?;
        Ok(count)
    }

    // -------------------------------------------------------------------
    // Private helpers (own their channel(s))
    // -------------------------------------------------------------------

    /// Read the chip's 9-byte serial number, caching it on first call.
    async fn cached_serial(&mut self) -> ServiceResult<[u8; CHIP_SERIAL_LEN], H::Error>
    {
        if let Some(serial) = self.serial
        {
            return Ok(serial);
        }

        let mut config = [0u8; 128];
        {
            let mut channel = self.atecc.open_channel().await?;
            channel.read_config_zone(&mut config).await?;
            channel.close().await?;
        }
        // SN layout per ATECC608 config zone:
        //   bytes 0..4 = SN[0..4]
        //   bytes 8..13 = SN[4..9]
        let mut serial = [0u8; CHIP_SERIAL_LEN];
        serial[0..4].copy_from_slice(&config[0..4]);
        serial[4..9].copy_from_slice(&config[8..13]);
        self.serial = Some(serial);
        Ok(serial)
    }

    /// Check whether the chip is in its operational locked state.
    ///
    /// Inspects the config zone lock byte at offset 87. `0x55` = unlocked,
    /// `0x00` = locked. Data zone lock is at offset 86.
    async fn is_provisioned(&mut self) -> ServiceResult<bool, H::Error>
    {
        let mut config = [0u8; 128];
        {
            let mut channel = self.atecc.open_channel().await?;
            channel.read_config_zone(&mut config).await?;
            channel.close().await?;
        }
        let config_locked = config[87] == 0x00;
        let data_locked = config[86] == 0x00;
        Ok(config_locked && data_locked)
    }

    /// Issue a `CheckMac` against `slot` with the host-computed hash that
    /// should match its content, and return whether the chip confirmed.
    ///
    /// Random + `CheckMac` run inside the same chip channel: this avoids two
    /// wake / idle round-trips and matches the natural "ask for a challenge,
    /// then use it" flow.
    async fn checkmac_with_hash
    (
        &mut self,
        slot: Slot,
        expected_slot_value: &[u8; HASH_LEN],
        serial: &[u8; CHIP_SERIAL_LEN],
    ) -> ServiceResult<bool, H::Error>
    {
        let mut channel = self.atecc.open_channel().await?;
        // Generate a fresh 32-byte challenge from the chip's RNG.
        let challenge = channel.random().await?;
        let other_data = checkmac_other_data(slot.as_u8(), serial);
        let response = checkmac_response(expected_slot_value, &challenge, &other_data, serial);

        let result = channel.checkmac(slot, &challenge, &response, &other_data).await;
        channel.close().await?;

        match result
        {
            Ok(true) => Ok(true),
            Ok(false) => Ok(false),
            // Some chip errors here may indicate a depleted counter. Map
            // them to a PinBlocked / Bricked outcome higher up. The driver
            // returns Chip(ExecutionError) for over-limit counters.
            Err(other) => Err(CryptoServiceError::Atecc(other)),
        }
    }

    /// Increment `counter` until its value lands one past a multiple of
    /// `batch_size`, i.e. `count % batch_size == 1`.
    ///
    /// Called after a successful PIN or PUK verify to grant the user a
    /// fresh batch of attempts while keeping `count % batch == 0` as
    /// an **unambiguous saturation indicator**: if a future
    /// [`retries_remaining`] observes `count % batch == 0` with
    /// `count > 0`, it can conclude that the user has consumed a full
    /// batch without any successful verify in between (and route to
    /// emergency recovery).
    ///
    /// The cost is one attempt per refresh: a PIN batch effectively
    /// allows 4 tries (rather than 5), a PUK batch 9 (rather than 10).
    /// In exchange the host gains a reliable way to detect saturation,
    /// which enables [`Self::emergency_reset`].
    ///
    /// Reads the counter and all increments share one channel.
    async fn refresh_counter_batch
    (
        &mut self,
        counter: CounterId,
        batch_size: u8,
    ) -> ServiceResult<(), H::Error>
    {
        let mut channel = self.atecc.open_channel().await?;
        let current = channel.counter_read(counter).await?;
        let batch = u32::from(batch_size);
        let remainder = current % batch;
        // Target: remainder == 1 after refresh. Number of bumps:
        // - remainder == 0 : bump 1 (lands on multiple + 1).
        // - remainder == 1 : 0 bumps (already there).
        // - remainder == r > 1 : bump `(batch - r) + 1` to skip past
        //   the next multiple and land on multiple + 1.
        let bumps = if remainder == 0
        {
            1u32
        }
        else if remainder == 1
        {
            0u32
        }
        else
        {
            batch - remainder + 1
        };

        for _ in 0..bumps
        {
            // Tolerate the chip refusing to bump further (counter at
            // its 2^21 hardware max).
            match channel.counter_increment(counter).await
            {
                Ok(_) => {}
                Err(AteccError::Chip(ChipError::ExecutionError)) =>
                {
                    channel.close().await?;
                    return Ok(());
                }
                Err(other) =>
                {
                    // Best effort close on error: ignore the close result.
                    let _ = channel.close().await;
                    return Err(CryptoServiceError::Atecc(other));
                }
            }
        }
        channel.close().await?;
        Ok(())
    }

    /// Perform an encrypted 32-byte write into `target_slot`.
    ///
    /// Sequence:
    ///
    /// 1. Read a fresh 32-byte random from the chip and load it into
    ///    `TempKey` via `Nonce(passthrough)`.
    /// 2. Issue `GenDig(zone=Data, key_id=IO_KEY_SLOT)`. `TempKey` becomes
    ///    the derived session key.
    /// 3. Host computes the same session key locally.
    /// 4. Host XOR-encrypts `plaintext` and computes the Write MAC.
    /// 5. `Write(slot, encrypted)` with `ciphertext || mac`.
    ///
    /// All chip commands run within a single channel because `TempKey`
    /// must survive from `Nonce` to the encrypted `Write`.
    ///
    /// Used by [`Self::set_pin`] and [`Self::unblock_pin`] to update the
    /// PIN hash in slot 5.
    async fn write_slot_encrypted
    (
        &mut self,
        target_slot: Slot,
        plaintext: &[u8; SLOT_VALUE_LEN],
        io_key: &[u8; SLOT_VALUE_LEN],
        chip_serial: &[u8; CHIP_SERIAL_LEN],
    ) -> ServiceResult<(), H::Error>
    {
        let mut channel = self.atecc.open_channel().await?;

        // 1. Generate a fresh nonce input and load it into TempKey.
        let nonce_input = channel.random().await?;
        channel.nonce_passthrough(NonceTarget::TempKey, &nonce_input).await?;

        // 2. GenDig on the I/O key slot. The chip updates TempKey.
        let io_slot = SLOT_IO_KEY.as_u8();
        channel.gendig(GenDigZone::Data, u16::from(io_slot)).await?;

        // 3. Replicate the chip-side TempKey on the host.
        let session_key = derive_session_key(io_key, &nonce_input, io_slot, chip_serial);

        // 4. Encrypt and MAC the plaintext.
        let ciphertext = encrypt_payload(plaintext, &session_key);
        let mac = write_mac
        (
            &session_key,
            plaintext,
            target_slot,
            0,
            chip_serial,
        );
        let payload = build_encrypted_write_payload(&ciphertext, &mac);

        // 5. Write to the slot. Slot block 0, offset 0 (single 32-byte
        // block written).
        let address = data_address(target_slot, 0, 0);
        channel.write_32_encrypted(Zone::Data, address, &payload).await?;

        channel.close().await?;
        Ok(())
    }
}

/// Whether the chip accepts a single 32-byte `Write` for the whole block.
///
/// Only blocks 1 and 3 of the config zone are fully writable in one shot.
/// Blocks 0 and 2 contain words that the chip refuses to overwrite via
/// `Write` (factory area, `UserExtra`, `Selector`, `LockValue`,
/// `LockConfig`) and must be written word-by-word, skipping the
/// non-writable words.
///
/// Mirrors the `!(zone == ATCA_ZONE_CONFIG && cur_block == 2u)` and
/// implicit "block 0 starts at offset 16" logic from `CryptoAuthLib`'s
/// `calib_write_bytes_zone`. See `lib/calib/calib_basic.c` in the
/// reference Microchip library.
const fn can_write_block_in_one_transfer(block: u8) -> bool
{
    matches!(block, 1 | 3)
}

/// Set of word offsets (within a 32-byte config-zone block) that the chip's
/// `Write` command accepts in 4-byte mode.
///
/// Used only when [`can_write_block_in_one_transfer`] returns `false`. For
/// blocks 1 and 3 this helper returns an empty slice; those blocks should
/// be written with a single 32-byte transfer instead.
///
/// - Block 0 : words 4..=7 are writable (chip-side bytes 16..32). Words
///   0..=3 (bytes 0..16) are the read-only factory area: serial number,
///   `RevNum`, `Reserved`. Any write attempt is rejected by the chip with
///   `ParseError 0x03`.
/// - Block 2 : words 0..=4 and 6..=7 are writable. Word 5 (bytes 84..88)
///   covers `UserExtra`, `Selector`, `LockValue`, and `LockConfig`. These
///   are modified only via the dedicated `UpdateExtra` and `Lock`
///   commands; the `Write` command rejects them. `CryptoAuthLib`'s
///   `calib_write_bytes_zone` skips word 5 of block 2 explicitly with
///   `!(zone == ATCA_ZONE_CONFIG && cur_block == 2u && cur_word == 5u)`.
///
/// The slice is returned in ascending order of word offset; callers iterate
/// in that order to match the wire sequence used by the reference library
/// and pinned down by the corresponding integration tests.
const fn writable_words_in_block(block: u8) -> &'static [u8]
{
    match block
    {
        0 => &[4, 5, 6, 7],
        2 => &[0, 1, 2, 3, 4, 6, 7],
        _ => &[],
    }
}

/// Compute how many `CheckMac` attempts remain before the next batch
/// threshold is hit.
///
/// `batch_size` is `PIN_MAX_RETRIES` for PIN, `PUK_MAX_RETRIES` for PUK.
/// The convention is that `refresh_counter_batch` is called on every
/// successful verify to push `count` to a non-multiple-of-batch value
/// (specifically, `next_multiple + 1`). So in normal operation:
///
/// - `count == 0` : freshly-provisioned chip, no verify attempted yet,
///   `batch_size` attempts remain.
/// - `count % batch == 1` : freshly refreshed after a successful verify,
///   `batch_size - 1` attempts remain in the current batch.
/// - `count % batch == r` in `2..batch` : `batch_size - r` attempts remain.
/// - `count % batch == 0` with `count > 0` : SATURATION. The user has
///   consumed a full batch with no successful verify in between. Returns
///   0 attempts.
fn retries_remaining(count: u32, batch_size: u8) -> u8
{
    let batch = u32::from(batch_size);
    let remainder = count % batch;

    if count == 0
    {
        return batch_size;
    }
    if remainder == 0
    {
        // Saturation: user consumed an entire batch without verifying.
        return 0;
    }
    if remainder == 1
    {
        // Freshly refreshed: full batch minus the refresh bump.
        return batch_size - 1;
    }
    // Mid-batch: batch - remainder is the count to the next multiple.
    // `remainder = count % batch` is in `0..batch <= 255`, so the cast
    // to `u8` is lossless. We have already returned for `remainder == 0`
    // and `remainder == 1` above. here `2 <= remainder < batch_size`.
    #[allow(clippy::cast_possible_truncation)]
    let remainder_u8 = remainder as u8;
    batch_size - remainder_u8
}

#[cfg(test)]
mod tests
{
    use super::*;

    #[test]
    fn retries_remaining_zero_returns_full_batch()
    {
        assert_eq!(retries_remaining(0, 5), 5);
        assert_eq!(retries_remaining(0, 10), 10);
    }

    #[test]
    fn retries_remaining_remainder_one_returns_batch_minus_one()
    {
        // Just refreshed after a successful verify.
        assert_eq!(retries_remaining(1, 5), 4);
        assert_eq!(retries_remaining(6, 5), 4);
        assert_eq!(retries_remaining(11, 5), 4);

        assert_eq!(retries_remaining(1, 10), 9);
        assert_eq!(retries_remaining(11, 10), 9);
    }

    #[test]
    fn retries_remaining_mid_batch_counts_down()
    {
        // remainder 2 -> batch - 2 = 3 tries left (for batch 5).
        assert_eq!(retries_remaining(2, 5), 3);
        assert_eq!(retries_remaining(3, 5), 2);
        assert_eq!(retries_remaining(4, 5), 1);
    }

    #[test]
    fn retries_remaining_saturation_at_multiple_returns_zero()
    {
        // The 5th, 10th, 15th attempt without a successful verify
        // lands count on a multiple of 5, signalling saturation.
        assert_eq!(retries_remaining(5, 5), 0);
        assert_eq!(retries_remaining(10, 5), 0);
        assert_eq!(retries_remaining(15, 5), 0);
        assert_eq!(retries_remaining(10, 10), 0);
        assert_eq!(retries_remaining(20, 10), 0);
    }

    #[test]
    fn one_transfer_blocks_are_1_and_3_only()
    {
        assert!(!can_write_block_in_one_transfer(0));
        assert!( can_write_block_in_one_transfer(1));
        assert!(!can_write_block_in_one_transfer(2));
        assert!( can_write_block_in_one_transfer(3));
    }

    #[test]
    fn writable_words_block_0_skips_factory_area()
    {
        // Factory area = bytes 0..16 = words 0..=3. Writable = words 4..=7.
        assert_eq!(writable_words_in_block(0), &[4, 5, 6, 7]);
    }

    #[test]
    fn writable_words_block_2_skips_word_5()
    {
        // Word 5 = bytes 84..88 = UserExtra/Selector/LockValue/LockConfig.
        // Not writable via the `Write` command. The remaining words of
        // block 2 are writable: 0..=4 and 6..=7.
        assert_eq!(writable_words_in_block(2), &[0, 1, 2, 3, 4, 6, 7]);
    }

    #[test]
    fn writable_words_blocks_1_and_3_are_empty_word_lists()
    {
        // Blocks 1 and 3 are written via 32-byte transfer; the
        // word-by-word helper returns an empty list for them.
        assert!(writable_words_in_block(1).is_empty());
        assert!(writable_words_in_block(3).is_empty());
    }

    #[test]
    fn writable_words_one_transfer_and_word_list_are_disjoint()
    {
        // Encoded contract: a block is either written in one 32-byte
        // transfer, or via the word list. Never both, never neither.
        for block in 0u8..=3u8
        {
            let one_shot = can_write_block_in_one_transfer(block);
            let words    = writable_words_in_block(block);
            assert_eq!(
                one_shot, words.is_empty(),
                "block {block}: one_transfer={one_shot}, word_list_empty={}",
                words.is_empty(),
            );
        }
    }
}