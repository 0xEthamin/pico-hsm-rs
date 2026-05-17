//! `Nonce` command.
//!
//! Loads bytes into the chip's TempKey or MsgDigBuf register. The ATECC608B
//! supports several modes, of which two are useful from the host side:
//!
//! - **Random** (mode 0): the host sends 20 bytes of input (`NumIn`), the
//!   chip mixes them with its TRNG output, hashes the result, and stores
//!   the hash in `TempKey`. The chip returns the 32-byte TRNG value
//!   (`NumOut`) that was mixed in, so the host can reconstruct `TempKey`
//!   if needed (this is what CheckMac and GenDig depend on).
//!
//! - **Passthrough** (mode 3): the host sends 32 bytes that are stored
//!   verbatim in `TempKey` or in `MsgDigBuf`. No mixing, no RNG. The chip
//!   responds with a single status byte. This is the mode used to load a
//!   message digest into `TempKey` before calling `Sign`.
//!
//! Mode 1 ("no RNG re-generation") and the ATECC608-specific Mode 2 variants
//! are intentionally omitted: nothing in the project's workflow needs them.
//! They can be added later as additional methods rather than expanded as
//! parameters on the existing ones, to keep each entry point unambiguous.
//!
//! Reference: CryptoAuthLib `lib/calib/calib_nonce.c`, constants
//! `NONCE_MODE_SEED_UPDATE` (0x00), `NONCE_MODE_PASSTHROUGH` (0x03),
//! `NONCE_MODE_TARGET_TEMPKEY` (0x00), `NONCE_MODE_TARGET_MSGDIGBUF` (0x40),
//! `NONCE_NUMIN_SIZE` (20), `NONCE_NUMIN_SIZE_PASSTHROUGH` (32).

use crate::driver::Atecc;
use crate::error::AteccError;
use crate::hal::AteccHal;
use crate::opcodes::{EXEC_TIME_NONCE_MS, OP_NONCE};

/// Size of the `NumIn` block in a random Nonce command.
pub const NONCE_NUMIN_SIZE: usize = 20;

/// Size of the `NumOut` block returned by a random Nonce command.
pub const NONCE_NUMOUT_SIZE: usize = 32;

/// Size of the data field in a passthrough Nonce command.
pub const NONCE_PASSTHROUGH_SIZE: usize = 32;

/// `param1` low bits for mode 0 (random nonce, seed update).
const NONCE_MODE_RANDOM: u8 = 0x00;

/// `param1` low bits for mode 3 (passthrough).
const NONCE_MODE_PASSTHROUGH: u8 = 0x03;

/// `param1` bit 6 cleared selects `TempKey` as the passthrough target.
const NONCE_TARGET_TEMPKEY: u8 = 0x00;

/// `param1` bit 6 set selects `MsgDigBuf` as the passthrough target.
const NONCE_TARGET_MSGDIGBUF: u8 = 0x40;

/// Destination register for a passthrough Nonce.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum NonceTarget
{
    /// 32-byte TempKey register. Used to load a digest before `Sign`.
    TempKey,
    /// 32-byte MsgDigBuf register.
    MsgDigBuf,
}

impl NonceTarget
{
    /// Encode the target as the relevant bit in `param1`.
    const fn as_param1_bits(self) -> u8
    {
        match self
        {
            NonceTarget::TempKey   => NONCE_TARGET_TEMPKEY,
            NonceTarget::MsgDigBuf => NONCE_TARGET_MSGDIGBUF,
        }
    }
}

impl<H> Atecc<H>
where
    H: AteccHal,
{
    /// Issue a random Nonce (mode 0).
    ///
    /// `num_in` is 20 bytes of host-provided entropy that the chip mixes
    /// with its TRNG before hashing the combined block into `TempKey`.
    ///
    /// On success returns the 32-byte `NumOut` (the TRNG portion mixed in).
    /// The host can compute the resulting `TempKey` value as
    /// `SHA256(NumOut || NumIn || OpCode || Mode || LSB || 0..0)` per the
    /// CryptoAuthLib reference, but the driver does not do that derivation:
    /// it is a service-layer concern.
    ///
    /// # Errors
    /// See [`Atecc::execute_command`].
    pub async fn nonce_random(
        &mut self,
        num_in: &[u8; NONCE_NUMIN_SIZE],
    ) -> Result<[u8; NONCE_NUMOUT_SIZE], AteccError<H::Error>>
    {
        // Response: count(1) + 32 NumOut + crc(2) = 35 bytes.
        let mut response_buf = [0u8; 1 + NONCE_NUMOUT_SIZE + 2];
        let payload = self
            .execute_command(
                OP_NONCE,
                NONCE_MODE_RANDOM,
                0x0000,
                num_in,
                EXEC_TIME_NONCE_MS,
                &mut response_buf,
            )
            .await?;

        let bytes: &[u8; NONCE_NUMOUT_SIZE] = payload
            .try_into()
            .map_err(|_| AteccError::MalformedResponse)?;
        Ok(*bytes)
    }

    /// Issue a passthrough Nonce (mode 3).
    ///
    /// `value` is stored verbatim in the target register (no hashing, no RNG
    /// mixing). Mainly used to load a message digest into `TempKey` ahead
    /// of a `Sign` call.
    ///
    /// # Errors
    /// See [`Atecc::execute_command_status`].
    pub async fn nonce_passthrough(
        &mut self,
        target: NonceTarget,
        value: &[u8; NONCE_PASSTHROUGH_SIZE],
    ) -> Result<(), AteccError<H::Error>>
    {
        let param1 = NONCE_MODE_PASSTHROUGH | target.as_param1_bits();
        self.execute_command_status(
            OP_NONCE,
            param1,
            0x0000,
            value,
            EXEC_TIME_NONCE_MS,
        )
        .await
    }
}

#[cfg(test)]
mod tests
{
    use super::*;

    #[test]
    fn nonce_target_tempkey_clears_bit_6()
    {
        assert_eq!(NonceTarget::TempKey.as_param1_bits(), 0x00);
    }

    #[test]
    fn nonce_target_msgdigbuf_sets_bit_6()
    {
        assert_eq!(NonceTarget::MsgDigBuf.as_param1_bits(), 0x40);
    }

    #[test]
    fn passthrough_mode_bits_combine_with_target_bits()
    {
        let p1_tempkey = NONCE_MODE_PASSTHROUGH | NonceTarget::TempKey.as_param1_bits();
        let p1_msgdig  = NONCE_MODE_PASSTHROUGH | NonceTarget::MsgDigBuf.as_param1_bits();
        assert_eq!(p1_tempkey, 0x03);
        assert_eq!(p1_msgdig,  0x43);
    }

    #[test]
    fn sizes_match_protocol()
    {
        assert_eq!(NONCE_NUMIN_SIZE, 20);
        assert_eq!(NONCE_NUMOUT_SIZE, 32);
        assert_eq!(NONCE_PASSTHROUGH_SIZE, 32);
    }
}