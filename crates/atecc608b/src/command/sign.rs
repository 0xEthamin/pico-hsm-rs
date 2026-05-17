//! `Sign` command.
//!
//! Produces an ECDSA P-256 signature using a private key stored in a slot.
//! Most flows pair this with a preceding `Nonce` command that loads the
//! message digest into the chip's MsgDigBuf register.
//!
//! Reference: CryptoAuthLib `lib/calib/calib_sign.c`.
