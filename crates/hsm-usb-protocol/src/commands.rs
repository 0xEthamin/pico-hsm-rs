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

//! Commands sent from the host to the token.
//!
//! See [`crate::frame::Frame`] for the wire layout. The opcode byte is
//! [`CommandOpcode`]; the payload layout is documented per-opcode below
//! (in the variant doc-comments) and parsed via the helpers in this module.

/// Opcode byte for each command.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum CommandOpcode
{
    /// `0x01` - `Info`: read firmware version, chip serial, provisioning state.
    /// Payload: empty.
    Info               = 0x01,
    /// `0x02` - `GetPubkey(slot)`: read a slot's public key (64 bytes).
    /// Payload: `[slot: u8]`.
    GetPubkey          = 0x02,
    /// `0x03` - `Sign(slot, digest)`: produce an ECDSA P-256 signature.
    /// Requires an active PIN session and a touch.
    /// Payload: `[slot: u8, digest: [u8; 32]]`.
    Sign               = 0x03,
    /// `0x04` - `GenKey(slot)`: regenerate a P-256 key pair.
    /// Requires an active PIN session.
    /// Payload: `[slot: u8]`.
    GenKey             = 0x04,
    /// `0x05` - Read the 128 bytes of the chip's config zone.
    /// Payload: `[block: u8]` where `block` is in `0..=3`. The 128-byte
    /// config zone is returned one 32-byte block at a time so the response
    /// fits in a single report. The host issues this command four times,
    /// once per block, to assemble the full image.
    ReadConfigZone     = 0x05,
    /// `0x06` - Read the 4-byte `SlotConfig` + `KeyConfig` for one slot.
    /// Payload: `[slot: u8]`.
    ReadConfigSlot     = 0x06,
    /// `0x07` - `VerifyPin(pin)`: open a PIN session (30 s window).
    /// Payload: `[pin: [u8; 4]]` (each byte holds an ASCII digit `'0'..'9'`).
    VerifyPin          = 0x07,
    /// `0x08` - `SetPin(old, new)`: change PIN within an active session.
    /// Payload: `[old: [u8; 4], new: [u8; 4]]`.
    SetPin             = 0x08,
    /// `0x09` - `UnblockPin(puk, new_pin)`: reset PIN counter via PUK.
    /// Payload: `[puk: [u8; 8], new_pin: [u8; 4]]`.
    UnblockPin         = 0x09,
    /// `0x0A` - Read current PIN / PUK retry counters.
    /// Payload: empty.
    GetPinStatus       = 0x0A,
    /// `0x0B` - `SetPuk(old_puk, new_puk, io_key)`: change the PUK.
    /// Requires an active PIN session (proves the caller knows the
    /// current PIN). Rewrites slot 6 via the encrypted-write protocol.
    /// Payload: `[old_puk: [u8; 8], new_puk: [u8; 8], io_key: [u8; 32]]`.
    SetPuk             = 0x0B,
    /// `0x0D` - `EmergencyReset(magic, io_key)`: last-chance reset.
    /// Requires that **both** PIN and PUK batches are exhausted. The
    /// firmware refuses to run otherwise with the
    /// `EmergencyResetNotPermitted` status (which carries the actual
    /// tries-remaining figures in its payload).
    ///
    /// Regenerates the ECC private keys in slots 0..=4 and 7 (the
    /// user's secrets are lost), resets PIN to `"0000"`, generates and
    /// stores a fresh random PUK (returned in the response payload).
    /// The user is granted one fresh batch of PIN attempts and one
    /// fresh batch of PUK attempts.
    ///
    /// Protected against accidental invocation by a magic word
    /// (`0xBADC0FFE`, little-endian on the wire). The CLI also
    /// requires an interactive double-confirm before sending.
    ///
    /// Payload: `[magic: [u8; 4], io_key: [u8; 32]]` (36 bytes).
    /// Response payload on success: `[new_puk: [u8; 8]]`.
    EmergencyReset     = 0x0D,

    // Provisioning (reversible while zones are unlocked).
    /// `0x10` - `WriteConfigZone(blob)`: replace the writable part of the
    /// config zone. Payload: `[blob: [u8; 32]]` for one block at a time
    /// (this command is issued 4 times, once per block index 0..=3).
    /// Payload first byte is the block index, followed by the 32 bytes.
    WriteConfigZone    = 0x10,
    /// `0x11` - `ProvisionSlot(slot, value)`: write a 32-byte cleartext
    /// value into one of the data slots. Only accepted by the firmware
    /// for the three policy-allowed slots (5, 6, 8). Used at
    /// provisioning to install the initial PIN hash, PUK hash, and IO
    /// key, before `LockDataZone`. Returns `InvalidSlot` for other
    /// slots and chip-error after data lock.
    /// Payload: `[slot: u8, value: [u8; 32]]`.
    ProvisionSlot      = 0x11,
    /// `0x12` - `ProvisionInitialPin`: write `SHA256("0000" || pin_salt)`
    /// into slot 5 in cleartext, where `pin_salt` is derived from the
    /// chip's serial. No payload. Used at provisioning instead of
    /// `ProvisionSlot --slot 5` so that the host does not need to
    /// reimplement the PIN-hash derivation. Returns `Ok` (empty
    /// payload) on success.
    ProvisionInitialPin = 0x12,
    /// `0x13` - `ProvisionInitialPuk`: generate a fresh random 8-digit
    /// PUK from the chip's RNG, compute its hash with the per-chip
    /// salt, write the hash into slot 6 in cleartext, and return the
    /// PUK in the response payload so the operator can record it.
    /// **This is the only opportunity to learn the PUK.** No payload
    /// from the host. Response: `[puk: [u8; 8]]`.
    ProvisionInitialPuk = 0x13,
    /// `0x14` - `ProvisionIoKey`: generate a fresh random 32-byte I/O
    /// Protection Key from the chip's RNG, write it into slot 8 in
    /// cleartext, and return it in the response payload so the host
    /// can store it for later encrypted writes. **This is the only
    /// opportunity to learn the IO key.** No payload from the host.
    /// Response: `[io_key: [u8; 32]]`.
    ProvisionIoKey      = 0x14,

    // Lock - isolated, protected by a magic word and a CRC. Never called
    // from automated flows: see crates/atecc608b/src/command/lock.rs and
    // the project's design decisions.
    /// `0xF0` - Lock the config zone permanently.
    /// Payload: `[magic: [u8; 4], expected_crc: [u8; 2]]`.
    LockConfigZone     = 0xF0,
    /// `0xF1` - Lock the data zone permanently.
    /// Payload: `[magic: [u8; 4], expected_crc: [u8; 2]]`.
    LockDataZone       = 0xF1,
    /// `0xF2` - Lock a single slot permanently.
    /// Payload: `[magic: [u8; 4], slot: u8]`.
    LockSlot           = 0xF2,
}

impl CommandOpcode
{
    /// Map a raw byte to a [`CommandOpcode`], if it is a recognized value.
    ///
    /// Returns `None` for any opcode the firmware does not implement,
    /// including reserved-for-future-use values.
    #[must_use]
    pub const fn from_byte(byte: u8) -> Option<Self>
    {
        match byte
        {
            0x01 => Some(Self::Info),
            0x02 => Some(Self::GetPubkey),
            0x03 => Some(Self::Sign),
            0x04 => Some(Self::GenKey),
            0x05 => Some(Self::ReadConfigZone),
            0x06 => Some(Self::ReadConfigSlot),
            0x07 => Some(Self::VerifyPin),
            0x08 => Some(Self::SetPin),
            0x09 => Some(Self::UnblockPin),
            0x0A => Some(Self::GetPinStatus),
            0x0B => Some(Self::SetPuk),
            0x0D => Some(Self::EmergencyReset),
            0x10 => Some(Self::WriteConfigZone),
            0x11 => Some(Self::ProvisionSlot),
            0x12 => Some(Self::ProvisionInitialPin),
            0x13 => Some(Self::ProvisionInitialPuk),
            0x14 => Some(Self::ProvisionIoKey),
            0xF0 => Some(Self::LockConfigZone),
            0xF1 => Some(Self::LockDataZone),
            0xF2 => Some(Self::LockSlot),
            _    => None,
        }
    }

    /// The raw opcode byte that goes on the wire.
    #[must_use]
    pub const fn as_u8(self) -> u8
    {
        self as u8
    }
}

impl TryFrom<u8> for CommandOpcode
{
    type Error = UnknownOpcode;

    fn try_from(byte: u8) -> Result<Self, Self::Error>
    {
        Self::from_byte(byte).ok_or(UnknownOpcode { byte })
    }
}

/// Returned when a byte cannot be mapped to a known [`CommandOpcode`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct UnknownOpcode
{
    /// The raw byte that was not recognized.
    pub byte: u8,
}

// ---------------------------------------------------------------------------
// Payload shape helpers.
//
// These are tiny stateless functions that parse / build the payload bytes
// for each command. They keep the wire layout in one well-tested place and
// avoid scattering "byte 0 is the slot, bytes 1..33 are the digest" comments
// across the firmware code.
// ---------------------------------------------------------------------------

/// PIN length in bytes (4 digits).
pub const PIN_LEN: usize = 4;

/// PUK length in bytes (8 digits).
pub const PUK_LEN: usize = 8;

/// Digest length used for [`CommandOpcode::Sign`] (SHA-256 output).
pub const DIGEST_LEN: usize = 32;

/// Length of the magic word protecting [`CommandOpcode::LockConfigZone`],
/// [`CommandOpcode::LockDataZone`], and [`CommandOpcode::LockSlot`].
pub const LOCK_MAGIC_LEN: usize = 4;

/// Length of the I/O Protection Key (slot 8 content), in bytes.
pub const IO_KEY_LEN: usize = 32;

/// Result of [`parse_set_pin`]: `(old_pin, new_pin, io_key)`.
pub type SetPinParts = ([u8; PIN_LEN], [u8; PIN_LEN], [u8; IO_KEY_LEN]);

/// Result of [`parse_unblock_pin`]: `(puk, new_pin, io_key)`.
pub type UnblockPinParts = ([u8; PUK_LEN], [u8; PIN_LEN], [u8; IO_KEY_LEN]);

/// Result of [`parse_set_puk`]: `(old_puk, new_puk, io_key)`.
pub type SetPukParts = ([u8; PUK_LEN], [u8; PUK_LEN], [u8; IO_KEY_LEN]);

/// Errors returned when a payload does not match the expected shape.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum PayloadError
{
    /// Payload was the wrong size for the command.
    WrongLen
    {
        /// Number of bytes that were expected.
        expected: usize,
        /// Number of bytes the caller actually provided.
        actual:   usize,
    },
    /// A magic-word check failed. Used by commands that require an
    /// explicit confirmation byte sequence in their payload to guard
    /// against accidental invocation.
    MagicMismatch,
}

/// Parse the payload of [`CommandOpcode::GetPubkey`] / `GenKey` / `ReadConfigSlot`.
///
/// # Errors
/// See [`PayloadError`].
pub fn parse_slot_only(payload: &[u8]) -> Result<u8, PayloadError>
{
    require_len(payload, 1)?;
    Ok(payload[0])
}

/// Parse the payload of [`CommandOpcode::Sign`].
///
/// Returns `(slot, digest)`.
///
/// # Errors
/// See [`PayloadError`].
pub fn parse_sign(payload: &[u8]) -> Result<(u8, [u8; DIGEST_LEN]), PayloadError>
{
    require_len(payload, 1 + DIGEST_LEN)?;
    let mut digest = [0u8; DIGEST_LEN];
    digest.copy_from_slice(&payload[1..=DIGEST_LEN]);
    Ok((payload[0], digest))
}

/// Parse the payload of [`CommandOpcode::VerifyPin`].
///
/// # Errors
/// See [`PayloadError`].
pub fn parse_verify_pin(payload: &[u8]) -> Result<[u8; PIN_LEN], PayloadError>
{
    require_len(payload, PIN_LEN)?;
    let mut pin = [0u8; PIN_LEN];
    pin.copy_from_slice(payload);
    Ok(pin)
}

/// Parse the payload of [`CommandOpcode::SetPin`].
///
/// Layout: `old_pin (4) || new_pin (4) || io_key (32)`. The IO key is
/// the 32-byte I/O Protection Key stored in slot 8, provided by the host
/// from its local provisioning config. The firmware uses it to perform
/// the encrypted write of the new PIN hash into slot 5; it is not stored.
///
/// Returns `(old_pin, new_pin, io_key)`.
///
/// # Errors
/// See [`PayloadError`].
pub fn parse_set_pin(payload: &[u8]) -> Result<SetPinParts, PayloadError>
{
    require_len(payload, PIN_LEN * 2 + 32)?;
    let mut old = [0u8; PIN_LEN];
    let mut new = [0u8; PIN_LEN];
    let mut io_key = [0u8; 32];
    old.copy_from_slice(&payload[..PIN_LEN]);
    new.copy_from_slice(&payload[PIN_LEN..PIN_LEN * 2]);
    io_key.copy_from_slice(&payload[PIN_LEN * 2..PIN_LEN * 2 + 32]);
    Ok((old, new, io_key))
}

/// Parse the payload of [`CommandOpcode::UnblockPin`].
///
/// Layout: `puk (8) || new_pin (4) || io_key (32)`. The IO key is
/// the 32-byte I/O Protection Key stored in slot 8, provided by the host
/// from its local provisioning config. The firmware uses it to perform
/// the encrypted write of the new PIN hash into slot 5; it is not stored.
///
/// Returns `(puk, new_pin, io_key)`.
///
/// # Errors
/// See [`PayloadError`].
pub fn parse_unblock_pin(payload: &[u8]) -> Result<UnblockPinParts, PayloadError>
{
    require_len(payload, PUK_LEN + PIN_LEN + 32)?;
    let mut puk = [0u8; PUK_LEN];
    let mut new = [0u8; PIN_LEN];
    let mut io_key = [0u8; 32];
    puk.copy_from_slice(&payload[..PUK_LEN]);
    new.copy_from_slice(&payload[PUK_LEN..PUK_LEN + PIN_LEN]);
    io_key.copy_from_slice(&payload[PUK_LEN + PIN_LEN..PUK_LEN + PIN_LEN + 32]);
    Ok((puk, new, io_key))
}

/// Parse the payload of [`CommandOpcode::SetPuk`].
///
/// Layout: `old_puk (8) || new_puk (8) || io_key (32)`. Authentication
/// is via the PIN session (the caller proved knowledge of the current
/// PIN earlier); `old_puk` is kept in the payload for forward
/// compatibility with a defence-in-depth pass that would re-verify the
/// old PUK on the chip before accepting the new one.
///
/// Returns `(old_puk, new_puk, io_key)`.
///
/// # Errors
/// See [`PayloadError`].
pub fn parse_set_puk(payload: &[u8]) -> Result<SetPukParts, PayloadError>
{
    require_len(payload, PUK_LEN * 2 + 32)?;
    let mut old = [0u8; PUK_LEN];
    let mut new = [0u8; PUK_LEN];
    let mut io_key = [0u8; 32];
    old.copy_from_slice(&payload[..PUK_LEN]);
    new.copy_from_slice(&payload[PUK_LEN..PUK_LEN * 2]);
    io_key.copy_from_slice(&payload[PUK_LEN * 2..PUK_LEN * 2 + 32]);
    Ok((old, new, io_key))
}

/// Magic word required in the payload of
/// [`CommandOpcode::EmergencyReset`] to confirm the caller's intent.
/// Picked to be improbable for any byte sequence arising from a typo
/// or a buggy host. Same role as [`LOCK_CONFIG_MAGIC`] in the lock
/// commands.
pub const EMERGENCY_RESET_MAGIC: [u8; 4] = [0xBA, 0xDC, 0x0F, 0xFE];

/// Parse the payload of [`CommandOpcode::EmergencyReset`].
///
/// Layout: `magic (4) || io_key (32)`. The magic must match
/// [`EMERGENCY_RESET_MAGIC`]. No PIN is required since the use case
/// is "PIN and PUK both forgotten / exhausted".
///
/// Returns `io_key` once the magic is validated.
///
/// # Errors
/// - [`PayloadError::WrongLen`] if the payload is not exactly 36 bytes.
/// - [`PayloadError::MagicMismatch`] if the first 4 bytes are not
///   `EMERGENCY_RESET_MAGIC`.
pub fn parse_emergency_reset(payload: &[u8]) -> Result<[u8; 32], PayloadError>
{
    require_len(payload, 4 + 32)?;
    if payload[0..4] != EMERGENCY_RESET_MAGIC
    {
        return Err(PayloadError::MagicMismatch);
    }
    let mut io_key = [0u8; 32];
    io_key.copy_from_slice(&payload[4..4 + 32]);
    Ok(io_key)
}

/// Magic word for [`CommandOpcode::LockConfigZone`]. Picked to be a
/// distinctive 32-bit value (`DE AD BE EF`).
pub const LOCK_CONFIG_MAGIC: [u8; 4] = [0xDE, 0xAD, 0xBE, 0xEF];

/// Magic word for [`CommandOpcode::LockDataZone`] (`CA FE BA BE`).
pub const LOCK_DATA_MAGIC: [u8; 4] = [0xCA, 0xFE, 0xBA, 0xBE];

/// Magic word for [`CommandOpcode::LockSlot`] (`F0 0D CA FE`).
pub const LOCK_SLOT_MAGIC: [u8; 4] = [0xF0, 0x0D, 0xCA, 0xFE];

/// Parse the payload of [`CommandOpcode::LockConfigZone`].
///
/// Layout: `magic (4) || expected_crc (2 LE)`. Returns the CRC if the
/// magic matches.
///
/// # Errors
/// - [`PayloadError::WrongLen`] if the payload is not exactly 6 bytes.
/// - [`PayloadError::MagicMismatch`] if the first 4 bytes are not
///   `LOCK_CONFIG_MAGIC`.
pub fn parse_lock_config_zone(payload: &[u8]) -> Result<u16, PayloadError>
{
    require_len(payload, 4 + 2)?;
    if payload[0..4] != LOCK_CONFIG_MAGIC
    {
        return Err(PayloadError::MagicMismatch);
    }
    Ok(u16::from_le_bytes([payload[4], payload[5]]))
}

/// Parse the payload of [`CommandOpcode::LockDataZone`].
///
/// Layout: `magic (4) || expected_crc (2 LE)`.
///
/// # Errors
/// As for [`parse_lock_config_zone`] with `LOCK_DATA_MAGIC`.
pub fn parse_lock_data_zone(payload: &[u8]) -> Result<u16, PayloadError>
{
    require_len(payload, 4 + 2)?;
    if payload[0..4] != LOCK_DATA_MAGIC
    {
        return Err(PayloadError::MagicMismatch);
    }
    Ok(u16::from_le_bytes([payload[4], payload[5]]))
}

/// Parse the payload of [`CommandOpcode::LockSlot`].
///
/// Layout: `magic (4) || slot (1)`.
///
/// # Errors
/// - [`PayloadError::WrongLen`] if the payload is not exactly 5 bytes.
/// - [`PayloadError::MagicMismatch`] if the first 4 bytes are not
///   `LOCK_SLOT_MAGIC`.
pub fn parse_lock_slot(payload: &[u8]) -> Result<u8, PayloadError>
{
    require_len(payload, 4 + 1)?;
    if payload[0..4] != LOCK_SLOT_MAGIC
    {
        return Err(PayloadError::MagicMismatch);
    }
    Ok(payload[4])
}

/// Parse the payload of [`CommandOpcode::WriteConfigZone`].
///
/// Returns `(block_index, block_data)`.
///
/// # Errors
/// See [`PayloadError`].
pub fn parse_write_config_zone(payload: &[u8]) 
-> Result<(u8, [u8; 32]), PayloadError>
{
    require_len(payload, 1 + 32)?;
    let mut block = [0u8; 32];
    block.copy_from_slice(&payload[1..=32]);
    Ok((payload[0], block))
}

/// Parse the payload of [`CommandOpcode::ProvisionSlot`].
///
/// Layout: `slot (1) || value (32)`. Returns the pair.
///
/// # Errors
/// - [`PayloadError::WrongLen`] if the payload is not exactly 33 bytes.
pub fn parse_provision_slot(payload: &[u8]) 
-> Result<(u8, [u8; 32]), PayloadError>
{
    require_len(payload, 1 + 32)?;
    let mut value = [0u8; 32];
    value.copy_from_slice(&payload[1..=32]);
    Ok((payload[0], value))
}

fn require_len(payload: &[u8], expected: usize) -> Result<(), PayloadError>
{
    if payload.len() == expected
    {
        Ok(())
    }
    else
    {
        Err(PayloadError::WrongLen
        {
            expected,
            actual: payload.len(),
        })
    }
}

#[cfg(test)]
mod tests
{
    use super::*;

    #[test]
    fn from_byte_round_trips()
    {
        for op in [
            CommandOpcode::Info,
            CommandOpcode::GetPubkey,
            CommandOpcode::Sign,
            CommandOpcode::GenKey,
            CommandOpcode::ReadConfigZone,
            CommandOpcode::ReadConfigSlot,
            CommandOpcode::VerifyPin,
            CommandOpcode::SetPin,
            CommandOpcode::UnblockPin,
            CommandOpcode::GetPinStatus,
            CommandOpcode::SetPuk,
            CommandOpcode::EmergencyReset,
            CommandOpcode::WriteConfigZone,
            CommandOpcode::ProvisionSlot,
            CommandOpcode::ProvisionInitialPin,
            CommandOpcode::ProvisionInitialPuk,
            CommandOpcode::ProvisionIoKey,
            CommandOpcode::LockConfigZone,
            CommandOpcode::LockDataZone,
            CommandOpcode::LockSlot,
        ]
        {
            assert_eq!(CommandOpcode::from_byte(op.as_u8()), Some(op));
        }
    }

    #[test]
    fn from_byte_returns_none_for_unknown()
    {
        assert!(CommandOpcode::from_byte(0x00).is_none());
        assert!(CommandOpcode::from_byte(0xFF).is_none());
        assert!(CommandOpcode::from_byte(0x42).is_none());
    }

    #[test]
    fn try_from_returns_error_with_byte()
    {
        let err = CommandOpcode::try_from(0x42u8).unwrap_err();
        assert_eq!(err.byte, 0x42);
    }

    #[test]
    fn parse_slot_only_accepts_one_byte()
    {
        assert_eq!(parse_slot_only(&[5]).unwrap(), 5);
        assert!(parse_slot_only(&[]).is_err());
        assert!(parse_slot_only(&[1, 2]).is_err());
    }

    #[test]
    fn parse_sign_extracts_slot_and_digest()
    {
        let expected_digest: [u8; DIGEST_LEN] = core::array::from_fn(|i| u8::try_from(i).unwrap());
        let mut payload = [0u8; 1 + DIGEST_LEN];
        payload[0] = 7;
        payload[1..].copy_from_slice(&expected_digest);
        let (slot, digest) = parse_sign(&payload).unwrap();
        assert_eq!(slot, 7);
        assert_eq!(digest, expected_digest);
    }

    #[test]
    fn parse_sign_rejects_short_payload()
    {
        let err = parse_sign(&[0u8; 10]).unwrap_err();
        assert_eq!(err, PayloadError::WrongLen { expected: 33, actual: 10 });
    }

    #[test]
    fn parse_verify_pin_extracts_4_bytes()
    {
        let pin = parse_verify_pin(b"1234").unwrap();
        assert_eq!(&pin, b"1234");
    }

    #[test]
    fn parse_set_pin_extracts_old_new_and_io_key()
    {
        let mut payload = [0u8; PIN_LEN * 2 + 32];
        payload[..4].copy_from_slice(b"0000");
        payload[4..8].copy_from_slice(b"1234");
        for i in 0u8..32
        {
            payload[8 + usize::from(i)] = 0xA0 + i;
        }
        let (old, new, io_key) = parse_set_pin(&payload).unwrap();
        assert_eq!(&old, b"0000");
        assert_eq!(&new, b"1234");
        for i in 0u8..32
        {
            assert_eq!(io_key[usize::from(i)], 0xA0 + i); 
        }
    }

    #[test]
    fn parse_set_pin_rejects_short_payload()
    {
        let err = parse_set_pin(b"0000123").unwrap_err();
        assert_eq!(err, PayloadError::WrongLen { expected: 40, actual: 7 });
    }

    #[test]
    fn parse_unblock_pin_extracts_puk_new_pin_and_io_key()
    {
        let mut payload = [0u8; PUK_LEN + PIN_LEN + 32];
        payload[..8].copy_from_slice(b"01234567");
        payload[8..12].copy_from_slice(b"1234");
        for i in 0u8..32
        {
            payload[12 + usize::from(i)] = 0xB0 + i;
        }
        let (puk, new, io_key) = parse_unblock_pin(&payload).unwrap();
        assert_eq!(&puk, b"01234567");
        assert_eq!(&new, b"1234");
        for i in 0u8..32
        {
            assert_eq!(io_key[usize::from(i)], 0xB0 + i);
        }
    }

    #[test]
    fn parse_unblock_pin_rejects_short_payload()
    {
        let err = parse_unblock_pin(b"01234567").unwrap_err();
        assert_eq!(err, PayloadError::WrongLen { expected: 44, actual: 8 });
    }

    #[test]
    fn parse_set_puk_extracts_old_new_and_io_key()
    {
        let mut payload = [0u8; PUK_LEN * 2 + 32];
        payload[..8].copy_from_slice(b"00000000");
        payload[8..16].copy_from_slice(b"99999999");
        for i in 0u8..32
        {
            payload[16 + usize::from(i)] = 0xC0 + i;
        }
        let (old, new, io_key) = parse_set_puk(&payload).unwrap();
        assert_eq!(&old, b"00000000");
        assert_eq!(&new, b"99999999");
        for i in 0u8..32
        {
            assert_eq!(io_key[usize::from(i)], 0xC0 + i);
        }
    }

    #[test]
    fn parse_set_puk_rejects_short_payload()
    {
        let err = parse_set_puk(b"012345670000").unwrap_err();
        assert_eq!(err, PayloadError::WrongLen { expected: 48, actual: 12 });
    }

    #[test]
    fn parse_emergency_reset_accepts_valid_magic_and_extracts_io_key()
    {
        let mut payload = [0u8; 4 + 32];
        payload[..4].copy_from_slice(&EMERGENCY_RESET_MAGIC);
        for i in 0u8..32
        {
            payload[4 + usize::from(i)] = 0xE0u8.wrapping_add(i);
        }
        let io_key = parse_emergency_reset(&payload).unwrap();
        for i in 0u8..32
        {
            assert_eq!(io_key[usize::from(i)], 0xE0u8.wrapping_add(i));
        }
    }

    #[test]
    fn parse_emergency_reset_rejects_wrong_magic()
    {
        let mut payload = [0u8; 4 + 32];
        payload[..4].copy_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
        let err = parse_emergency_reset(&payload).unwrap_err();
        assert_eq!(err, PayloadError::MagicMismatch);
    }

    #[test]
    fn parse_emergency_reset_rejects_short_payload()
    {
        let err = parse_emergency_reset(&[0u8; 8]).unwrap_err();
        assert_eq!(err, PayloadError::WrongLen { expected: 36, actual: 8 });
    }

    #[test]
    fn parse_write_config_zone_extracts_block_index_and_data()
    {
        let mut payload = [0u8; 1 + 32];
        payload[0] = 2;
        for i in 0u8..32
        {
            payload[1 + usize::from(i)] = 0x10 + i;
        }
        let (block, data) = parse_write_config_zone(&payload).unwrap();
        assert_eq!(block, 2);
        for i in 0u8..32
        {
            assert_eq!(data[usize::from(i)], 0x10 + i);
        }
    }
}