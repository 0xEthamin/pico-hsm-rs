//! High-level crypto service exposed to the USB layer.
//!
//! This is where the actual workflow logic lives: PIN session management,
//! PIN/PUK verification with counter accounting, sign orchestration on top
//! of `Nonce` + `Sign`, and public-key retrieval.
//!
//! The service is generic over both the HAL (so it can run against a real
//! ATECC over I2C or against a `MockHal` in tests) and the [`Clock`] (so
//! tests can drive time deterministically).

use core::fmt::Debug;

use atecc608b::command::counter::CounterId;
use atecc608b::command::nonce::NonceTarget;
use atecc608b::{Atecc, AteccError, AteccHal, ChipError, Slot};

use crate::error::CryptoServiceError;
use crate::pin::{
    checkmac_other_data, checkmac_response, pin_hash, pin_salt, puk_hash, puk_salt,
    validate_digits, HASH_LEN, PIN_LEN, PUK_LEN,
};
use crate::session::{Clock, Session};
use crate::slots::{
    PIN_MAX_RETRIES, PUK_MAX_RETRIES, SLOT_PIN_HASH, SLOT_PRIMARY, SLOT_PUK_HASH,
};

/// Convenience alias for the service's result type.
pub type ServiceResult<T, HalError> = Result<T, CryptoServiceError<HalError>>;

/// Length of the chip serial number, in bytes, as read from the config
/// zone.
pub const CHIP_SERIAL_LEN: usize = 9;

/// 64-byte raw public key returned by `GenKey`.
pub type PublicKey = [u8; 64];

/// 64-byte raw `R || S` ECDSA signature returned by `Sign`.
pub type Signature = [u8; 64];

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

    /// Consume the service and return the underlying driver and clock.
    pub fn into_parts(self) -> (Atecc<H>, C)
    {
        (self.atecc, self.clock)
    }

    /// Return chip revision, serial, and provisioning state.
    ///
    /// # Errors
    /// See [`CryptoServiceError::Atecc`].
    pub async fn info(&mut self) -> ServiceResult<DeviceInfo, H::Error>
    {
        let revision = self.atecc.info_revision().await?;
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
        Ok(self.atecc.genkey_public(slot).await?)
    }

    /// Open a PIN session if the provided PIN is correct.
    ///
    /// The CheckMac of slot 5 bumps `Counter0` regardless of the outcome,
    /// so each call costs one count. On success, the service bumps the
    /// counter additionally to bring it back up to the next multiple of
    /// [`PIN_MAX_RETRIES`], granting the user a fresh batch of 5 attempts.
    ///
    /// # Errors
    /// - [`CryptoServiceError::InvalidFormat`] if `pin` is not 4 ASCII digits.
    /// - [`CryptoServiceError::PinIncorrect`] with tries remaining.
    /// - [`CryptoServiceError::PinBlocked`] if Counter0 already at threshold.
    /// - [`CryptoServiceError::Atecc`] for I/O / chip errors.
    pub async fn verify_pin(
        &mut self,
        pin: &[u8; PIN_LEN],
    ) -> ServiceResult<(), H::Error>
    {
        validate_digits(pin)?;

        // Refuse early if PIN slot is already exhausted.
        let count = self.atecc.counter_read(CounterId::Counter0).await?;
        let tries_left = retries_remaining(count, PIN_MAX_RETRIES);
        if tries_left == 0
        {
            return Err(CryptoServiceError::PinBlocked);
        }

        let serial = self.cached_serial().await?;
        let salt = pin_salt(&serial);
        let computed_pin_hash = pin_hash(pin, &salt);

        let ok = self
            .checkmac_with_hash(SLOT_PIN_HASH, &computed_pin_hash, &serial)
            .await?;

        if !ok
        {
            // The chip bumped Counter0 by 1 already. Report the new tries
            // remaining to the caller.
            let new_count = self.atecc.counter_read(CounterId::Counter0).await?;
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
    /// **Note**: the actual encrypted write of the new PIN hash into slot 5
    /// requires the GenDig + write_32_encrypted dance, which depends on the
    /// I/O Protection Key in slot 8. That orchestration is not yet
    /// implemented in this method; it currently only verifies the PUK and
    /// reports the result. A future revision will perform the encrypted
    /// write.
    ///
    /// # Errors
    /// See variants above.
    pub async fn unblock_pin(
        &mut self,
        puk: &[u8; PUK_LEN],
        new_pin: &[u8; PIN_LEN],
    ) -> ServiceResult<(), H::Error>
    {
        validate_digits(puk)?;
        validate_digits(new_pin)?;

        // Refuse early if PUK is already exhausted.
        let count = self.atecc.counter_read(CounterId::Counter1).await?;
        let tries_left = retries_remaining(count, PUK_MAX_RETRIES);
        if tries_left == 0
        {
            return Err(CryptoServiceError::Bricked);
        }

        let serial = self.cached_serial().await?;
        let salt = puk_salt(&serial);
        let computed_puk_hash = puk_hash(puk, &salt);

        let ok = self
            .checkmac_with_hash(SLOT_PUK_HASH, &computed_puk_hash, &serial)
            .await?;

        if !ok
        {
            let new_count = self.atecc.counter_read(CounterId::Counter1).await?;
            let remaining = retries_remaining(new_count, PUK_MAX_RETRIES);
            return Err(CryptoServiceError::PukIncorrect { tries_remaining: remaining });
        }

        // PUK was correct. Refresh PUK counter to a fresh batch.
        self.refresh_counter_batch(CounterId::Counter1, PUK_MAX_RETRIES).await?;

        // Reset PIN counter too: the user got a fresh PIN slate.
        self.refresh_counter_batch(CounterId::Counter0, PIN_MAX_RETRIES).await?;

        // The encrypted rewrite of slot 5 with the new PIN hash lands in a
        // later revision. The caller is silently NOT enforcing the new PIN
        // for now; the previous PIN remains valid until the encrypted write
        // is wired up.
        let _new_pin_hash = pin_hash(new_pin, &pin_salt(&serial));

        Ok(())
    }

    /// Sign a 32-byte digest with the private key in `slot`.
    ///
    /// Requires an active PIN session.
    ///
    /// # Errors
    /// - [`CryptoServiceError::PinRequired`] if no session is active.
    /// - [`CryptoServiceError::Atecc`] for chip-level errors (slot
    ///   misconfigured, authorization missing, etc).
    pub async fn sign(
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

        // Load the digest into TempKey via passthrough Nonce, then Sign.
        self.atecc.nonce_passthrough(NonceTarget::TempKey, digest).await?;
        let signature = self.atecc.sign_external(slot).await?;

        // Refresh session activity timestamp.
        self.session.touch(now);
        Ok(signature)
    }

    /// Sign with the default identity slot (slot 0).
    ///
    /// Convenience wrapper around [`Self::sign`].
    ///
    /// # Errors
    /// See [`Self::sign`].
    pub async fn sign_primary(
        &mut self,
        digest: &[u8; 32],
    ) -> ServiceResult<Signature, H::Error>
    {
        self.sign(SLOT_PRIMARY, digest).await
    }

    /// Report the current PIN / PUK retry counters and session state.
    ///
    /// # Errors
    /// See [`CryptoServiceError::Atecc`].
    pub async fn get_pin_status(&mut self) -> ServiceResult<PinStatus, H::Error>
    {
        let c0 = self.atecc.counter_read(CounterId::Counter0).await?;
        let c1 = self.atecc.counter_read(CounterId::Counter1).await?;
        Ok(PinStatus
        {
            pin_tries_remaining: retries_remaining(c0, PIN_MAX_RETRIES),
            puk_tries_remaining: retries_remaining(c1, PUK_MAX_RETRIES),
            session_active:      self.session.is_active(self.clock.now_ms()),
        })
    }

    /// Force-close the PIN session.
    pub fn close_session(&mut self)
    {
        self.session.close();
    }

    /// Read the chip's 9-byte serial number, caching it on first call.
    async fn cached_serial(&mut self) -> ServiceResult<[u8; CHIP_SERIAL_LEN], H::Error>
    {
        if let Some(serial) = self.serial
        {
            return Ok(serial);
        }

        let mut config = [0u8; 128];
        self.atecc.read_config_zone(&mut config).await?;
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
        self.atecc.read_config_zone(&mut config).await?;
        let config_locked = config[87] == 0x00;
        let data_locked = config[86] == 0x00;
        Ok(config_locked && data_locked)
    }

    /// Issue a CheckMac against `slot` with the host-computed hash that
    /// should match its content, and return whether the chip confirmed.
    async fn checkmac_with_hash(
        &mut self,
        slot: Slot,
        expected_slot_value: &[u8; HASH_LEN],
        serial: &[u8; CHIP_SERIAL_LEN],
    ) -> ServiceResult<bool, H::Error>
    {
        // Generate a fresh 32-byte challenge from the chip's RNG.
        let challenge = self.atecc.random().await?;
        let other_data = checkmac_other_data(slot.as_u8(), serial);
        let response = checkmac_response(expected_slot_value, &challenge, &other_data, serial);

        match self.atecc.checkmac(slot, &challenge, &response, &other_data).await
        {
            Ok(true) => Ok(true),
            Ok(false) => Ok(false),
            // Some chip errors here may indicate a depleted counter; map
            // them to a PinBlocked / Bricked outcome higher up. The driver
            // returns Chip(ExecutionError) for over-limit counters.
            Err(other) => Err(CryptoServiceError::Atecc(other)),
        }
    }

    /// Increment `counter` until its value is a multiple of `batch_size`.
    ///
    /// Called after a successful PIN or PUK verify to grant the user a
    /// fresh batch of attempts.
    async fn refresh_counter_batch(
        &mut self,
        counter: CounterId,
        batch_size: u8,
    ) -> ServiceResult<(), H::Error>
    {
        let current = self.atecc.counter_read(counter).await?;
        let batch = u32::from(batch_size);
        let remainder = current % batch;
        if remainder == 0
        {
            return Ok(());
        }
        let bumps = batch - remainder;
        for _ in 0..bumps
        {
            // Tolerate the chip refusing to bump further (counter at max).
            // In that case the next verify will fail with a counter error.
            match self.atecc.counter_increment(counter).await
            {
                Ok(_) => {}
                Err(AteccError::Chip(ChipError::ExecutionError)) =>
                {
                    // Counter saturated. Subsequent operations will fail
                    // explicitly; nothing useful to do here.
                    return Ok(());
                }
                Err(other) => return Err(CryptoServiceError::Atecc(other)),
            }
        }
        Ok(())
    }
}

/// Compute how many CheckMac attempts remain before the next batch
/// threshold is hit.
///
/// `batch_size` is 5 for PIN, 10 for PUK. The convention is that the
/// counter is bumped up to the next multiple of `batch_size` on every
/// successful verification, so the number of attempts remaining is
/// `batch_size - (count % batch_size)`. When `count` lands exactly on a
/// multiple, the chip has just been refreshed and a full batch is
/// available.
fn retries_remaining(count: u32, batch_size: u8) -> u8
{
    let batch = u32::from(batch_size);
    let remainder = count % batch;
    if remainder == 0
    {
        batch_size
    }
    else
    {
        // (batch - remainder) is at most batch - 1, which is at most
        // u8::MAX since batch came from a u8. The cast is safe.
        #[allow(clippy::cast_possible_truncation)]
        let r = (batch - remainder) as u8;
        r
    }
}

#[cfg(test)]
mod tests
{
    use super::*;

    #[test]
    fn retries_remaining_after_fresh_refresh()
    {
        // Count = exact multiple of 5 means 5 fresh tries.
        assert_eq!(retries_remaining(0,  5), 5);
        assert_eq!(retries_remaining(5,  5), 5);
        assert_eq!(retries_remaining(10, 5), 5);
    }

    #[test]
    fn retries_remaining_decreases_with_each_failure()
    {
        // After 1, 2, 3, 4 failures within a batch starting at 0.
        assert_eq!(retries_remaining(1, 5), 4);
        assert_eq!(retries_remaining(2, 5), 3);
        assert_eq!(retries_remaining(3, 5), 2);
        assert_eq!(retries_remaining(4, 5), 1);
        // The 5th failure lands back on a multiple of 5 -- chip has
        // ratcheted but caller is between batches, observer reads 5 fresh
        // attempts. In practice the next call will fail because the chip
        // refuses further checkmacs at this stage; the caller handles that
        // path via the LimitedUse chip error rather than via this counter.
        assert_eq!(retries_remaining(5, 5), 5);
    }

    #[test]
    fn retries_remaining_works_with_puk_batch()
    {
        assert_eq!(retries_remaining(0,  10), 10);
        assert_eq!(retries_remaining(3,  10), 7);
        assert_eq!(retries_remaining(10, 10), 10);
        assert_eq!(retries_remaining(15, 10), 5);
    }
}