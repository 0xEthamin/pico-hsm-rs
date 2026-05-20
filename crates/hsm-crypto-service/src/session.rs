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

//! PIN session bookkeeping.
//!
//! A PIN session is opened by a successful [`crate::CryptoService::verify_pin`]
//! call and expires after [`SESSION_TIMEOUT_MS`] of inactivity. Each
//! authenticated operation (signing, key generation) refreshes the session.
//!
//! The session uses a [`Clock`] abstraction so that tests can drive time
//! deterministically. In firmware the implementation is backed by
//! `embassy_time::Instant`. In tests it is a hand-rolled `Cell<u64>`.

/// Session inactivity timeout in milliseconds.
pub const SESSION_TIMEOUT_MS: u64 = 30_000;

/// Source of monotonic time used by the session.
///
/// The returned value is in milliseconds since some fixed epoch chosen by
/// the implementation. The crypto service only ever compares values, so
/// the epoch does not matter as long as it is monotonic.
pub trait Clock
{
    /// Current monotonic time in milliseconds.
    fn now_ms(&self) -> u64;
}

/// PIN session state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Session
{
    /// Timestamp (`Clock::now_ms`) of the last activity. `None` means no
    /// session is open.
    last_activity_ms: Option<u64>,
}

impl Session
{
    /// Build a fresh session, closed.
    #[must_use]
    pub const fn new() -> Self
    {
        Self { last_activity_ms: None }
    }

    /// Open the session at the given time.
    pub fn open(&mut self, now_ms: u64)
    {
        self.last_activity_ms = Some(now_ms);
    }

    /// Close the session immediately.
    pub fn close(&mut self)
    {
        self.last_activity_ms = None;
    }

    /// Refresh the activity timestamp. No-op if the session is closed.
    pub fn touch(&mut self, now_ms: u64)
    {
        if self.last_activity_ms.is_some()
        {
            self.last_activity_ms = Some(now_ms);
        }
    }

    /// Returns `true` if the session is open and not yet timed out at the
    /// given current time.
    #[must_use]
    pub fn is_active(&self, now_ms: u64) -> bool
    {
        match self.last_activity_ms
        {
            None => false,
            Some(last) => now_ms.saturating_sub(last) < SESSION_TIMEOUT_MS,
        }
    }
}

impl Default for Session
{
    fn default() -> Self
    {
        Self::new()
    }
}

#[cfg(test)]
mod tests
{
    use super::*;

    #[test]
    fn fresh_session_is_inactive()
    {
        let s = Session::new();
        assert!(!s.is_active(0));
        assert!(!s.is_active(1_000_000));
    }

    #[test]
    fn opened_session_is_active_at_open_time()
    {
        let mut s = Session::new();
        s.open(100);
        assert!(s.is_active(100));
    }

    #[test]
    fn session_active_within_timeout()
    {
        let mut s = Session::new();
        s.open(0);
        assert!(s.is_active(SESSION_TIMEOUT_MS - 1));
    }

    #[test]
    fn session_expires_at_timeout()
    {
        let mut s = Session::new();
        s.open(0);
        assert!(!s.is_active(SESSION_TIMEOUT_MS));
    }

    #[test]
    fn touch_extends_session()
    {
        let mut s = Session::new();
        s.open(0);
        // Halfway to expiry.
        s.touch(15_000);
        // 15 s after the touch, still less than the full timeout from the
        // touch's own timestamp.
        assert!(s.is_active(30_000));
        assert!(!s.is_active(45_000));
    }

    #[test]
    fn touch_on_closed_session_is_noop()
    {
        let mut s = Session::new();
        s.touch(100);
        assert!(!s.is_active(100));
    }

    #[test]
    fn close_drops_active_session()
    {
        let mut s = Session::new();
        s.open(0);
        s.close();
        assert!(!s.is_active(0));
    }
}