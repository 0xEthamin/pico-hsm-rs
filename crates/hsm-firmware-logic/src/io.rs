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

//! GPIO abstractions: LEDs and the touch button.
//!
//! The hardware-facing implementations on the RP2040 use `embassy_rp::gpio`.
//! For testing, drop-in mocks live in this same module behind a `cfg(test)`
//! gate. Code that wants to be testable in host context depends on the
//! [`Led`] and [`Button`] traits, never on the embassy types directly.
//!
//! # Debouncing
//!
//! The button on the dongle has an RC low-pass filter in hardware
//! (see schematic) plus a software debouncer here. The software step
//! requires the input to remain stable for at least
//! [`DEBOUNCE_STABLE_SAMPLES`] consecutive samples before the state is
//! considered settled. Sampling is the caller's responsibility (this module
//! is just the debouncer state machine), typically driven by a 1 ms timer
//! task in the firmware.

/// LED control trait.
///
/// Two methods only: turn on, turn off. Everything fancier (blink, pulse,
/// fade) is composed on top by reading the LED pattern out of the
/// [`crate::state_machine::TokenState`] and toggling at the right cadence.
pub(crate) trait Led
{
    /// Turn the LED on (drive the GPIO high on active-high wiring).
    fn on(&mut self);

    /// Turn the LED off.
    fn off(&mut self);
}

/// Button input trait.
///
/// Active-low on this hardware: the GPIO reads `false` when the button is
/// pressed and `true` when released, because of the pull-up to 3V3. The
/// trait abstracts that away and returns a boolean in the user-friendly
/// direction: `true` means "user is pressing the button right now".
pub(crate) trait Button
{
    /// `true` if the button is currently pressed at the GPIO level (raw,
    /// not yet debounced).
    fn is_pressed_raw(&self) -> bool;
}

/// Number of consecutive identical samples required for the debouncer to
/// accept a new stable state.
///
/// At a 1 ms sampling rate this gives a 5 ms minimum settling time, well
/// above the typical 1 ms of switch bounce we expect from the tactile
/// switches we use.
pub(crate) const DEBOUNCE_STABLE_SAMPLES: u8 = 5;

/// Software debouncer state.
///
/// Holds the last stable level and a running counter that increments while
/// the raw input matches the candidate new level and resets when it does
/// not. Once the counter reaches [`DEBOUNCE_STABLE_SAMPLES`] the candidate
/// becomes the new stable level.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Debouncer
{
    /// Currently-accepted stable level.
    stable:    bool,
    /// Candidate level being observed.
    candidate: bool,
    /// Consecutive samples matching `candidate`.
    count:     u8,
}

impl Debouncer
{
    /// Build a fresh debouncer assuming the initial level is `initial`.
    #[must_use]
    pub const fn new(initial: bool) -> Self
    {
        Self
        {
            stable:    initial,
            candidate: initial,
            count:     0,
        }
    }

    /// Feed one new sample.
    ///
    /// Returns `Some(level)` when the stable level just changed as a
    /// result of this sample, `None` otherwise. The caller can use this
    /// as a trigger to issue a press/release event.
    pub fn sample(&mut self, level: bool) -> Option<bool>
    {
        if level == self.stable
        {
            // Same as currently accepted. Reset any in-progress candidate.
            self.candidate = self.stable;
            self.count = 0;
            return None;
        }

        if level == self.candidate
        {
            // Candidate confirmed for another sample.
            self.count = self.count.saturating_add(1);
            if self.count >= DEBOUNCE_STABLE_SAMPLES
            {
                self.stable = self.candidate;
                self.count = 0;
                return Some(self.stable);
            }
            None
        }
        else
        {
            // New candidate, restart the counter.
            self.candidate = level;
            self.count = 1;
            None
        }
    }

    /// Current stable level (without consuming a sample).
    #[must_use]
    pub(crate) const fn stable(&self) -> bool
    {
        self.stable
    }
}


#[cfg(test)]
mod test_mocks
{
    use super::{Button, Led};

    /// Mock LED that records every state change in a tiny log.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub(crate) struct MockLed
    {
        pub(crate) state: bool,
        pub(crate) transitions: u32,
    }

    impl MockLed
    {
        pub(crate) const fn new() -> Self
        {
            Self { state: false, transitions: 0 }
        }
    }

    impl Led for MockLed
    {
        fn on(&mut self)
        {
            if !self.state
            {
                self.transitions += 1;
            }
            self.state = true;
        }

        fn off(&mut self)
        {
            if self.state
            {
                self.transitions += 1;
            }
            self.state = false;
        }
    }

    /// Mock button whose state is set by the test.
    pub(crate) struct MockButton
    {
        pub(crate) pressed: bool,
    }

    impl MockButton
    {
        pub(crate) const fn new(pressed: bool) -> Self
        {
            Self { pressed }
        }
    }

    impl Button for MockButton
    {
        fn is_pressed_raw(&self) -> bool
        {
            self.pressed
        }
    }
}

#[cfg(test)]
mod tests
{
    use super::*;
    use super::test_mocks::{MockButton, MockLed};

    #[test]
    fn debouncer_holds_initial_state_until_threshold()
    {
        let mut d = Debouncer::new(false);
        // Four samples of the opposite level should not flip yet
        // (threshold is 5).
        for _ in 0..4
        {
            assert_eq!(d.sample(true), None);
        }
        // The fifth flips it.
        assert_eq!(d.sample(true), Some(true));
        assert!(d.stable());
    }

    #[test]
    fn debouncer_ignores_brief_noise()
    {
        let mut d = Debouncer::new(false);
        // Bounce: a single true, then back to false, repeated.
        for _ in 0..10
        {
            assert_eq!(d.sample(true), None);
            assert_eq!(d.sample(false), None);
        }
        assert!(!d.stable());
    }

    #[test]
    fn debouncer_resets_counter_on_revert()
    {
        let mut d = Debouncer::new(false);
        // Three samples of true (almost there).
        for _ in 0..3
        {
            assert_eq!(d.sample(true), None);
        }
        // One sample of false: counter reset.
        assert_eq!(d.sample(false), None);
        // Now four samples of true are needed again from scratch.
        for _ in 0..4
        {
            assert_eq!(d.sample(true), None);
        }
        assert_eq!(d.sample(true), Some(true));
    }

    #[test]
    fn debouncer_handles_release_after_press()
    {
        let mut d = Debouncer::new(false);
        // Establish a press.
        for _ in 0..4
        {
            d.sample(true);
        }
        assert_eq!(d.sample(true), Some(true));

        // Now release: same threshold for the reverse direction.
        for _ in 0..4
        {
            assert_eq!(d.sample(false), None);
        }
        assert_eq!(d.sample(false), Some(false));
    }

    #[test]
    fn mock_led_tracks_transitions()
    {
        let mut led = MockLed::new();
        led.on();
        led.on(); // no-op transition count-wise
        led.off();
        assert_eq!(led.transitions, 2);
        assert!(!led.state);
    }

    #[test]
    fn mock_button_returns_configured_state()
    {
        let pressed = MockButton::new(true);
        let released = MockButton::new(false);
        assert!(pressed.is_pressed_raw());
        assert!(!released.is_pressed_raw());
    }
}