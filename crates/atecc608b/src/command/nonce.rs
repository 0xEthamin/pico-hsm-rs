//! `Nonce` command.
//!
//! Loads bytes into the chip's TempKey or MsgDigBuf register. Several modes
//! are available depending on whether the chip should mix in its internal
//! RNG before storing the value.
//!
//! Reference: CryptoAuthLib `lib/calib/calib_nonce.c`.
