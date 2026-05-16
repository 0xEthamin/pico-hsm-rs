//! Commands sent from the host to the token.
//!
//! The wire format of each command is a single 64-byte HID report:
//!
//! ```text
//! [ opcode | len_lo | len_hi | payload… | padding (zeros) ]
//! ```

/// Opcode byte for each command.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommandOpcode
{
    /// `0x01` - `Info`: read firmware version, chip serial, provisioning state.
    Info               = 0x01,
    /// `0x02` - `GetPubkey(slot)`: read a slot's public key (64 bytes).
    GetPubkey          = 0x02,
    /// `0x03` - `Sign(slot, digest)`: produce an ECDSA P-256 signature.
    /// Requires an active PIN session and a touch.
    Sign               = 0x03,
    /// `0x04` - `GenKey(slot)`: (re)generate a P-256 key pair.
    /// Requires an active PIN session.
    GenKey             = 0x04,
    /// `0x05` - Read the 128 bytes of the chip's config zone.
    ReadConfigZone     = 0x05,
    /// `0x06` - Read the 4-byte SlotConfig + KeyConfig for one slot.
    ReadConfigSlot     = 0x06,
    /// `0x07` - `VerifyPin(pin)`: open a PIN session (30 s window).
    VerifyPin          = 0x07,
    /// `0x08` - `SetPin(old, new)`: change PIN within an active session.
    SetPin             = 0x08,
    /// `0x09` - `UnblockPin(puk, new_pin)`: reset PIN counter via PUK.
    UnblockPin         = 0x09,
    /// `0x0A` - Read current PIN / PUK retry counters.
    GetPinStatus       = 0x0A,

    // Provisioning (reversible while zones are unlocked).
    /// `0x10` - `WriteConfigZone(blob)`: replace the writable part of the
    /// config zone.
    WriteConfigZone    = 0x10,

    // Lock - isolated, protected by a magic word and a CRC.
    /// `0xF0` - Lock the config zone permanently.
    LockConfigZone     = 0xF0,
    /// `0xF1` - Lock the data zone permanently.
    LockDataZone       = 0xF1,
    /// `0xF2` - Lock a single slot permanently.
    LockSlot           = 0xF2,
}
