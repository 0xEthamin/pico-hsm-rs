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

//! Slot identifiers.
//!
//! The ATECC608B exposes 16 slots, numbered 0 to 15. This module provides a
//! type-safe wrapper to avoid passing arbitrary `u8` values around.

/// Total number of slots on the chip.
pub(crate) const SLOT_COUNT: u8 = 16;

/// A validated slot identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Slot(u8);

impl Slot
{
    /// Try to build a slot from a raw `u8`. Returns `None` if `index >= 16`.
    #[must_use]
    pub const fn new(index: u8) -> Option<Self>
    {
        if index < SLOT_COUNT
        {
            Some(Self(index))
        }
        else
        {
            None
        }
    }

    /// Build a slot from a known-valid constant.
    ///
    /// # Panics
    /// Panics at compile time if `index >= 16`.
    #[must_use]
    pub const fn const_new(index: u8) -> Self
    {
        assert!(index < SLOT_COUNT, "slot index out of range");
        Self(index)
    }

    /// Return the raw slot index.
    #[must_use]
    pub const fn as_u8(self) -> u8
    {
        self.0
    }
}
