//! Status bytes returned by the token in every response report.

/// First byte of every HID response.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResponseStatus
{
    /// `0x00` - Operation succeeded.
    Ok                       = 0x00,
    /// `0x01` - Command opcode unknown.
    InvalidCommand           = 0x01,
    /// `0x02` - Payload size or shape is invalid.
    InvalidPayload           = 0x02,
    /// `0x03` - Slot index out of range.
    InvalidSlot              = 0x03,
    /// `0x04` - I2C / wake error talking to the ATECC.
    AteccCommunicationError  = 0x04,
    /// `0x05` - Chip returned an error status. The chip code is in
    /// `payload[0]`.
    AteccChipError           = 0x05,
    /// `0x06` - The user did not press the button within the 30 s window.
    TouchTimeout             = 0x06,
    /// `0x07` - Token has not been provisioned yet.
    NotProvisioned           = 0x07,
    /// `0x08` - Magic word for a `Lock*` command did not match.
    LockMagicMismatch        = 0x08,
    /// `0x09` - CRC of the expected config does not match what's on chip.
    LockCrcMismatch          = 0x09,
    /// `0x0A` - Another operation is in progress.
    Busy                     = 0x0A,
    /// `0x0B` - PIN was wrong. Tries remaining in `payload[0]`.
    WrongPin                 = 0x0B,
    /// `0x0C` - A PIN session is required before signing.
    PinRequired              = 0x0C,
    /// `0x0D` - PIN slot is blocked. Only PUK unblock can recover.
    PinBlocked               = 0x0D,
    /// `0x0E` - PUK was wrong. Tries remaining in `payload[0]`.
    WrongPuk                 = 0x0E,
    /// `0x0F` - PUK retries exhausted. Chip is bricked.
    Bricked                  = 0x0F,
}
