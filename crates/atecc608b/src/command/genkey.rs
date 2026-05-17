//! `GenKey` command.
//!
//! Generates a P-256 ECC key pair inside a slot, or computes the public key
//! corresponding to a private key already stored in a slot.
//!
//! Two operating modes are exposed:
//!
//! - [`Atecc::genkey_create`]: instruct the chip to generate a new P-256
//!   private key entirely on-chip in the target slot. The private key never
//!   leaves the device. The corresponding 64-byte public key is returned.
//!   Subject to `KeyConfig.Private` and the data zone lock state.
//!
//! - [`Atecc::genkey_public`]: compute and output the public key
//!   corresponding to the private key already stored in the target slot.
//!   Read-only operation, useful at boot to retrieve the chip's identity
//!   without re-generating the private key.
//!
//! Reference: CryptoAuthLib `lib/calib/calib_genkey.c`, constants
//! `GENKEY_MODE_NEW_PRIVATE` (0x04), `GENKEY_MODE_PUBLIC` (0x00).
//!
//! # Public key format
//!
//! The returned 64 bytes are the uncompressed P-256 public key encoded as
//! `X || Y`, each coordinate big-endian and 32 bytes wide. To produce the
//! SEC1 uncompressed form expected by most libraries (including `p256`),
//! prepend the `0x04` octet:
//!
//! ```text
//! sec1 = [0x04] || X || Y
//! ```

use crate::driver::Atecc;
use crate::error::AteccError;
use crate::hal::AteccHal;
use crate::opcodes::{EXEC_TIME_GENKEY_MS, OP_GENKEY};
use crate::slot::Slot;

/// Size of the returned public key in bytes (X || Y, raw P-256).
pub const PUBLIC_KEY_SIZE: usize = 64;

/// `param1` mode bits: generate a brand new private key inside the slot.
const GENKEY_MODE_CREATE: u8 = 0x04;

/// `param1` mode bits: only output the public key for the existing private
/// key in the slot.
const GENKEY_MODE_PUBLIC: u8 = 0x00;

impl<H> Atecc<H>
where
    H: AteccHal,
{
    /// Generate a new P-256 private key inside the target slot.
    ///
    /// The private key is created and stored entirely on-chip. The 64-byte
    /// public key (uncompressed `X || Y`) is returned.
    ///
    /// # Errors
    /// See [`Atecc::execute_command`]. Common chip errors include attempting
    /// to write a slot configured `KeyConfig.Private = 0` or attempting to
    /// regenerate a slot whose `SlotConfig.WriteConfig` forbids it after
    /// data zone lock.
    pub async fn genkey_create(
        &mut self,
        slot: Slot,
    ) -> Result<[u8; PUBLIC_KEY_SIZE], AteccError<H::Error>>
    {
        self.genkey_internal(GENKEY_MODE_CREATE, slot).await
    }

    /// Compute and return the public key for the private key already stored
    /// in the target slot. Does not modify chip state.
    ///
    /// # Errors
    /// See [`Atecc::execute_command`].
    pub async fn genkey_public(
        &mut self,
        slot: Slot,
    ) -> Result<[u8; PUBLIC_KEY_SIZE], AteccError<H::Error>>
    {
        self.genkey_internal(GENKEY_MODE_PUBLIC, slot).await
    }

    async fn genkey_internal(
        &mut self,
        mode: u8,
        slot: Slot,
    ) -> Result<[u8; PUBLIC_KEY_SIZE], AteccError<H::Error>>
    {
        // Response: count(1) + 64 pubkey + crc(2) = 67 bytes.
        let mut response_buf = [0u8; 1 + PUBLIC_KEY_SIZE + 2];
        let param2 = u16::from(slot.as_u8());
        let payload = self
            .execute_command(
                OP_GENKEY,
                mode,
                param2,
                &[],
                EXEC_TIME_GENKEY_MS,
                &mut response_buf,
            )
            .await?;

        let bytes: &[u8; PUBLIC_KEY_SIZE] = payload
            .try_into()
            .map_err(|_| AteccError::MalformedResponse)?;
        Ok(*bytes)
    }
}

#[cfg(test)]
mod tests
{
    use super::*;

    #[test]
    fn modes_match_cryptoauthlib_constants()
    {
        assert_eq!(GENKEY_MODE_CREATE, 0x04);
        assert_eq!(GENKEY_MODE_PUBLIC, 0x00);
    }

    #[test]
    fn public_key_size_is_64()
    {
        assert_eq!(PUBLIC_KEY_SIZE, 64);
    }
}