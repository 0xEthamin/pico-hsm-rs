//! Slot-mapping convention used by this firmware.
//!
//! Slot allocation is *project policy*, not a chip primitive: the same chip
//! could be programmed differently. Putting the convention in one place keeps
//! it visible and reviewable.
//!
//! | Slot  | Purpose                                | Type            | Policy summary                                                |
//! |-------|----------------------------------------|-----------------|---------------------------------------------------------------|
//! | 0     | Primary P-256 identity                 | ECC P-256       | `ReqAuth`=1, `AuthKey`=5 -> PIN-gated. `GenKey` allowed.       |
//! | 1–4   | P-256 reserve / rotation               | ECC P-256       | Same as slot 0.                                               |
//! | 5     | PIN hash `SHA256(PIN \|\| salt)`       | 32 bytes data   | `EncryptWrite` via slot 8. `LimitedUse` via Counter0 (cap 5). |
//! | 6     | PUK hash `SHA256(PUK \|\| salt2)`      | 32 bytes data   | `EncryptWrite` via slot 8. `LimitedUse` via Counter1 (cap 10).|
//! | 7     | Reserved (future attestation)          | TBD             | `Never` write before any decision is taken.                   |
//! | 8     | I/O Protection master key              | 32 bytes data   | Written once before lock(data); never modifiable after.       |
//! | 9–15  | Reserved (V3)                          | TBD             | `Never` write.                                                |

use atecc608b::Slot;

/// Primary identity slot. Used for the daily sign challenge / response.
pub const SLOT_PRIMARY: Slot = Slot::const_new(0);
/// First reserve slot for key rotation.
pub const SLOT_RESERVE_1: Slot = Slot::const_new(1);
/// Second reserve slot.
pub const SLOT_RESERVE_2: Slot = Slot::const_new(2);
/// Third reserve slot.
pub const SLOT_RESERVE_3: Slot = Slot::const_new(3);
/// Fourth reserve slot.
pub const SLOT_RESERVE_4: Slot = Slot::const_new(4);
/// Slot holding the SHA-256 hash of the PIN.
pub const SLOT_PIN_HASH: Slot = Slot::const_new(5);
/// Slot holding the SHA-256 hash of the PUK.
pub const SLOT_PUK_HASH: Slot = Slot::const_new(6);
/// Slot holding the I/O protection master key.
pub const SLOT_IO_KEY: Slot = Slot::const_new(8);

/// Maximum PIN tries before the slot is hardware-locked by Counter0.
pub const PIN_MAX_RETRIES: u8 = 5;

/// Maximum PUK tries before the chip is bricked.
pub const PUK_MAX_RETRIES: u8 = 10;

/// PIN length in digits.
pub const PIN_LENGTH: usize = 4;

/// PUK length in digits.
pub const PUK_LENGTH: usize = 8;

/// Default PIN at factory provisioning. Must be changed on first use.
pub const PIN_DEFAULT: [u8; PIN_LENGTH] = *b"0000";
