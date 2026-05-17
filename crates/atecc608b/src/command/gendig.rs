//! `GenDig` command.
//!
//! Computes a digest combining the contents of a slot, the OTP, or the
//! config zone with the current `TempKey` and stores the result back in
//! `TempKey`. The result is what subsequent commands like an encrypted
//! `Write` or `PrivWrite` use as the shared secret with the host.
//!
//! In this project's provisioning flow:
//!
//! 1. The host calls [`crate::command::nonce::Atecc::nonce_random`] to
//!    establish a shared `TempKey` value between host and chip.
//! 2. The host calls [`Atecc::gendig`] with the I/O Protection Key slot
//!    (slot 8). The chip computes
//!    `SHA256(IOKey || OpCode || Mode || KeyId || SN || padding || TempKey)`
//!    and replaces `TempKey` with the result. The host computes the same
//!    digest off-chip.
//! 3. The host XORs the new `TempKey` with the plaintext to write,
//!    appends a MAC, and sends an encrypted `Write` or `PrivWrite`.
//!
//! The driver does not orchestrate the host-side digest derivation: that is
//! a service-layer concern.
//!
//! Reference: CryptoAuthLib `lib/calib/calib_gendig.c`, constants
//! `GENDIG_ZONE_CONFIG` (0x00), `GENDIG_ZONE_OTP` (0x01),
//! `GENDIG_ZONE_DATA` (0x02).

use crate::driver::Atecc;
use crate::error::AteccError;
use crate::hal::AteccHal;
use crate::opcodes::{EXEC_TIME_GENDIG_MS, OP_GENDIG};

/// `param1` zone bits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum GenDigZone
{
    /// Pull source data from the config zone.
    Config,
    /// Pull source data from the OTP zone.
    Otp,
    /// Pull source data from a data slot.
    Data,
}

impl GenDigZone
{
    /// Encode the zone as the low bits of `param1`.
    const fn as_param1(self) -> u8
    {
        match self
        {
            GenDigZone::Config => 0x00,
            GenDigZone::Otp    => 0x01,
            GenDigZone::Data   => 0x02,
        }
    }
}

impl<H> Atecc<H>
where
    H: AteccHal,
{
    /// Run a basic `GenDig` against a zone and key id, with no extra data.
    ///
    /// Mostly used to derive a shared digest from the I/O Protection Key
    /// (slot 8 in this project) for subsequent encrypted writes.
    ///
    /// The chip responds with a status-only frame on success.
    ///
    /// # Errors
    /// See [`Atecc::execute_command_status`].
    pub async fn gendig(
        &mut self,
        zone: GenDigZone,
        key_id: u16,
    ) -> Result<(), AteccError<H::Error>>
    {
        self.execute_command_status(
            OP_GENDIG,
            zone.as_param1(),
            key_id,
            &[],
            EXEC_TIME_GENDIG_MS,
        )
        .await
    }
}

#[cfg(test)]
mod tests
{
    use super::*;

    #[test]
    fn zone_encoding_matches_cryptoauthlib_constants()
    {
        assert_eq!(GenDigZone::Config.as_param1(), 0x00);
        assert_eq!(GenDigZone::Otp.as_param1(),    0x01);
        assert_eq!(GenDigZone::Data.as_param1(),   0x02);
    }
}