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
    /// `0x06` - Read the 4-byte SlotConfig + KeyConfig for one slot.
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

    // Provisioning (reversible while zones are unlocked).
    /// `0x10` - `WriteConfigZone(blob)`: replace the writable part of the
    /// config zone. Payload: `[blob: [u8; 32]]` for one block at a time
    /// (this command is issued 4 times, once per block index 0..=3).
    /// Payload first byte is the block index, followed by the 32 bytes.
    WriteConfigZone    = 0x10,

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
            0x10 => Some(Self::WriteConfigZone),
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
    digest.copy_from_slice(&payload[1..1 + DIGEST_LEN]);
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
/// Returns `(old_pin, new_pin)`.
///
/// # Errors
/// See [`PayloadError`].
pub fn parse_set_pin(payload: &[u8]) -> Result<([u8; PIN_LEN], [u8; PIN_LEN]), PayloadError>
{
    require_len(payload, PIN_LEN * 2)?;
    let mut old = [0u8; PIN_LEN];
    let mut new = [0u8; PIN_LEN];
    old.copy_from_slice(&payload[..PIN_LEN]);
    new.copy_from_slice(&payload[PIN_LEN..]);
    Ok((old, new))
}

/// Parse the payload of [`CommandOpcode::UnblockPin`].
///
/// Returns `(puk, new_pin)`.
///
/// # Errors
/// See [`PayloadError`].
pub fn parse_unblock_pin(
    payload: &[u8],
) -> Result<([u8; PUK_LEN], [u8; PIN_LEN]), PayloadError>
{
    require_len(payload, PUK_LEN + PIN_LEN)?;
    let mut puk = [0u8; PUK_LEN];
    let mut new = [0u8; PIN_LEN];
    puk.copy_from_slice(&payload[..PUK_LEN]);
    new.copy_from_slice(&payload[PUK_LEN..]);
    Ok((puk, new))
}

/// Parse the payload of [`CommandOpcode::WriteConfigZone`].
///
/// Returns `(block_index, block_data)`.
///
/// # Errors
/// See [`PayloadError`].
pub fn parse_write_config_zone(
    payload: &[u8],
) -> Result<(u8, [u8; 32]), PayloadError>
{
    require_len(payload, 1 + 32)?;
    let mut block = [0u8; 32];
    block.copy_from_slice(&payload[1..1 + 32]);
    Ok((payload[0], block))
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
            CommandOpcode::WriteConfigZone,
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
        let mut payload = [0u8; 1 + DIGEST_LEN];
        payload[0] = 7;
        for i in 0..DIGEST_LEN
        {
            payload[1 + i] = i as u8;
        }
        let (slot, digest) = parse_sign(&payload).unwrap();
        assert_eq!(slot, 7);
        for i in 0..DIGEST_LEN
        {
            assert_eq!(digest[i], i as u8);
        }
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
    fn parse_set_pin_extracts_old_and_new()
    {
        let payload = b"00001234";
        let (old, new) = parse_set_pin(payload).unwrap();
        assert_eq!(&old, b"0000");
        assert_eq!(&new, b"1234");
    }

    #[test]
    fn parse_unblock_pin_extracts_puk_and_new_pin()
    {
        let payload = b"012345671234";
        let (puk, new) = parse_unblock_pin(payload).unwrap();
        assert_eq!(&puk, b"01234567");
        assert_eq!(&new, b"1234");
    }

    #[test]
    fn parse_write_config_zone_extracts_block_index_and_data()
    {
        let mut payload = [0u8; 1 + 32];
        payload[0] = 2;
        for i in 0..32
        {
            payload[1 + i] = 0x10 + i as u8;
        }
        let (block, data) = parse_write_config_zone(&payload).unwrap();
        assert_eq!(block, 2);
        for i in 0..32
        {
            assert_eq!(data[i], 0x10 + i as u8);
        }
    }
}