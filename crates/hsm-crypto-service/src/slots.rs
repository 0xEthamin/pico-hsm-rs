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

//! Slot-mapping convention used by this firmware.
//!
//! Slot allocation is *project policy*, not a chip primitive. The same chip
//! could be programmed differently. Putting the convention in one place keeps
//! it visible and reviewable.
//!
//! The authoritative reference is [`docs/config-zone-layout.md`]. This module
//! exposes named constants for the slots the service code references; it
//! must stay in sync with the configuration zone the chip is provisioned
//! with.
//!
//! | Slot  | Type        | Purpose                                | Policy summary                                                |
//! |-------|-------------|----------------------------------------|---------------------------------------------------------------|
//! | 0     | ECC P-256   | Primary identity, GenKey-only          | `ReqAuth`=1, `AuthKey`=5 (PIN-gated). `PrivWrite` forbidden.    |
//! | 1     | ECC P-256   | Secondary identity, GenKey-only        | Same as slot 0.                                               |
//! | 2-4   | ECC P-256   | User keys, `GenKey` + encrypted import   | PIN-gated. Lockable individually.                             |
//! | 5     | Data 32 B   | PIN hash `SHA256(PIN \|\| salt)`       | `EncryptWrite` via slot 8. `LimitedUse` via Counter0 (cap 5).     |
//! | 6     | Data 32 B   | PUK hash `SHA256(PUK \|\| salt)`       | `EncryptWrite` via slot 8. `LimitedUse` via Counter1 (cap 10).    |
//! | 7     | ECC P-256   | User key, `GenKey` + encrypted import    | Same as slots 2-4.                                            |
//! | 8     | Data 32 B   | I/O Protection master key              | Written pre-data-lock, immutable after. Never written again.  |
//! | 9-15  | ECC P-256   | Reserve for V2                         | Same configuration as slots 2-4/7, kept unused for now.       |
//!
//! Notes
//! -----
//!
//! - Slots **2-4 and 7** all share the same configuration as user-rotatable
//!   ECC keys with PIN gating. They are interchangeable from the policy
//!   point of view. Project conventions may earmark them for specific
//!   roles in the future.
//! - **Slots 9-15** are configured exactly like user slots so they can be
//!   used in a later iteration without re-provisioning. Treat them as
//!   reserve, do not rely on their contents until a future revision
//!   explicitly assigns them.

use atecc608b::Slot;

use crate::pin::PIN_LEN;

/// Slot holding the SHA-256 hash of the PIN.
pub(crate) const SLOT_PIN_HASH: Slot = Slot::const_new(5);
/// Slot holding the SHA-256 hash of the PUK.
pub(crate) const SLOT_PUK_HASH: Slot = Slot::const_new(6);
/// Slot holding the I/O protection master key.
pub(crate) const SLOT_IO_KEY: Slot = Slot::const_new(8);

/// Size of one PIN batch on Counter0. The "effective tries" available
/// to the user inside a batch is `PIN_MAX_RETRIES - 1` (= 4), because
/// `refresh_counter_batch` lands `count` one past the next multiple so
/// that `count % PIN_MAX_RETRIES == 0` is an unambiguous saturation
/// signal usable by `emergency_reset`. See `service::retries_remaining`.
pub(crate) const PIN_MAX_RETRIES: u8 = 5;

/// Size of one PUK batch on Counter1. Effective tries inside a batch
/// is `PUK_MAX_RETRIES - 1` (= 9), for the same reason as
/// [`PIN_MAX_RETRIES`].
pub(crate) const PUK_MAX_RETRIES: u8 = 10;

/// Default PIN at factory provisioning. Must be changed on first use.
pub(crate) const PIN_DEFAULT: [u8; PIN_LEN] = *b"0000";