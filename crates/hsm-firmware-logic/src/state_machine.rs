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

//! Token operating state machine.
//!
//! The token transitions between a small set of named states based on
//! external events: USB boot complete, PIN verified, sign request received,
//! touch detected, timer elapsed, error reported. Each state has an
//! associated LED pattern that drives the visual indicator at the right
//! cadence.
//!
//! The state machine is pure logic. It consumes events and returns the
//! new state plus the new LED pattern. It does not perform I/O. The
//! firmware's main task drives the I/O around it (sampling the button,
//! toggling the LEDs, waking on timeouts). This separation makes the
//! machine fully testable in a host context.

/// All the operating states the token can be in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum TokenState
{
    /// Just powered on, peripherals coming up. Yellow LED blinks.
    Booting,
    /// Idle, waiting for a host command. Green solid.
    Idle,
    /// PIN session is active and the user can request a signature. Green
    /// slow pulse.
    Authenticated,
    /// A Sign request is pending and the user must press the touch button
    /// within [`TOUCH_TIMEOUT_MS`]. Yellow solid.
    WaitingForTouch,
    /// Touch confirmed, signing in progress. Both LEDs alternate briefly.
    Signing,
    /// An error occurred. Green LED fast-blinks for [`ERROR_DISPLAY_MS`]
    /// then returns to [`TokenState::Idle`].
    Error,
}

/// How long the token displays the error pattern before returning to idle.
pub const ERROR_DISPLAY_MS: u64 = 5_000;

/// How long the user has to touch the button before the signing request
/// is cancelled.
pub const TOUCH_TIMEOUT_MS: u64 = 30_000;

// Compile-time invariant: the error display window must be shorter than
// the touch window, otherwise an error raised during signing could hide
// the pending signature for longer than the touch deadline. Catching
// this at compile time means a misedit of the constants above is
// rejected by `cargo check`, before any test ever runs.
const _: () = assert!(ERROR_DISPLAY_MS < TOUCH_TIMEOUT_MS);

/// Events that drive transitions.
///
/// Events come from three sources: the dispatch loop (PIN verified, sign
/// requested), the touch sampler (touch pressed), and the timer task
/// (timeout elapsed). Each variant maps onto a single transition in
/// [`TokenState::on_event`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Event
{
    /// Peripherals are ready, USB has enumerated.
    BootComplete,
    /// A PIN session has just been opened.
    PinVerified,
    /// The PIN session timed out or was closed.
    SessionEnded,
    /// A `Sign` request just landed; user must touch.
    SignRequested,
    /// The touch button was pressed (debounced).
    TouchPressed,
    /// The touch-waiting period ran out without a press.
    TouchTimeout,
    /// The signing operation finished (signature returned to host).
    SignComplete,
    /// An error happened. Display the error pattern then return to idle.
    ErrorRaised,
    /// The error display window ran out.
    ErrorDisplayElapsed,
}

/// Visual LED pattern associated with each state.
///
/// The firmware's animation task reads this from the current state and
/// toggles the LEDs accordingly. Patterns are expressed in human terms
/// (solid, pulse, alternate) rather than as raw on/off booleans so the
/// animation task can vary its cadence without the state machine knowing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum LedPattern
{
    /// Both LEDs off.
    AllOff,
    /// Green LED solid on.
    GreenSolid,
    /// Green LED pulsing slowly (about 1 Hz, smooth).
    GreenSlowPulse,
    /// Green LED fast-blinking (about 5 Hz).
    GreenFastBlink,
    /// Yellow LED solid on.
    YellowSolid,
    /// Yellow LED blinking (about 2 Hz).
    YellowBlink,
    /// Green and yellow alternate (about 5 Hz).
    AlternateBoth,
}

impl TokenState
{
    /// Initial state at power-on.
    #[must_use]
    pub const fn initial() -> Self
    {
        TokenState::Booting
    }

    /// LED pattern associated with this state.
    #[must_use]
    pub const fn led_pattern(self) -> LedPattern
    {
        match self
        {
            TokenState::Booting         => LedPattern::YellowBlink,
            TokenState::Idle            => LedPattern::GreenSolid,
            TokenState::Authenticated   => LedPattern::GreenSlowPulse,
            TokenState::WaitingForTouch => LedPattern::YellowSolid,
            TokenState::Signing         => LedPattern::AlternateBoth,
            TokenState::Error           => LedPattern::GreenFastBlink,
        }
    }

    /// Apply an event and return the next state.
    ///
    /// Events that do not match any transition for the current state are
    /// ignored. The function returns the state unchanged. This is the
    /// conservative behaviour, equivalent to a `default: do nothing` arm.
    /// The dispatch loop is free to fire `SessionEnded` repeatedly without
    /// risking pathological transitions for example.
    #[must_use]
    pub const fn on_event(self, event: Event) -> Self
    {
        use Event as E;
        use TokenState as S;
        match (self, event)
        {
            // Transitions to Idle: boot completion, session timeout (from either
            // authenticated or waiting-for-touch), and the end of the error
            // display window.
            (S::Booting,           E::BootComplete)
            | (S::Authenticated | S::WaitingForTouch, E::SessionEnded)
            | (S::Error,           E::ErrorDisplayElapsed) => S::Idle,

            // Transitions to Authenticated: PIN verify (Idle or refresh existing),
            // touch timeout cancelling a pending sign without dropping session,
            // and a completed signing.
            (S::Idle | S::Authenticated, E::PinVerified)
            | (S::WaitingForTouch, E::TouchTimeout)
            | (S::Signing,         E::SignComplete) => S::Authenticated,

            // Sign requires authentication.
            (S::Authenticated, E::SignRequested) => S::WaitingForTouch,

            // Touch confirms the pending signature.
            (S::WaitingForTouch, E::TouchPressed) => S::Signing,

            // Errors override any state.
            (_, E::ErrorRaised) => S::Error,

            // Anything else is a no-op.
            _ => self,
        }
    }
}

#[cfg(test)]
mod tests
{
    use super::*;

    #[test]
    fn led_pattern_per_state()
    {
        assert_eq!(TokenState::Booting.led_pattern(), LedPattern::YellowBlink);
        assert_eq!(TokenState::Idle.led_pattern(), LedPattern::GreenSolid);
        assert_eq!(TokenState::Authenticated.led_pattern(), LedPattern::GreenSlowPulse);
        assert_eq!(TokenState::WaitingForTouch.led_pattern(), LedPattern::YellowSolid);
        assert_eq!(TokenState::Signing.led_pattern(), LedPattern::AlternateBoth);
        assert_eq!(TokenState::Error.led_pattern(), LedPattern::GreenFastBlink);
    }

    #[test]
    fn happy_path_boot_to_signed()
    {
        let s = TokenState::initial();
        assert_eq!(s, TokenState::Booting);

        let s = s.on_event(Event::BootComplete);
        assert_eq!(s, TokenState::Idle);

        let s = s.on_event(Event::PinVerified);
        assert_eq!(s, TokenState::Authenticated);

        let s = s.on_event(Event::SignRequested);
        assert_eq!(s, TokenState::WaitingForTouch);

        let s = s.on_event(Event::TouchPressed);
        assert_eq!(s, TokenState::Signing);

        let s = s.on_event(Event::SignComplete);
        assert_eq!(s, TokenState::Authenticated);
    }

    #[test]
    fn touch_timeout_returns_to_authenticated()
    {
        let s = TokenState::Authenticated
            .on_event(Event::SignRequested)
            .on_event(Event::TouchTimeout);
        assert_eq!(s, TokenState::Authenticated);
    }

    #[test]
    fn session_expiry_returns_to_idle_from_authenticated()
    {
        let s = TokenState::Authenticated.on_event(Event::SessionEnded);
        assert_eq!(s, TokenState::Idle);
    }

    #[test]
    fn session_expiry_returns_to_idle_from_waiting_for_touch()
    {
        let s = TokenState::WaitingForTouch.on_event(Event::SessionEnded);
        assert_eq!(s, TokenState::Idle);
    }

    #[test]
    fn sign_request_ignored_outside_authenticated()
    {
        for s in [
            TokenState::Booting,
            TokenState::Idle,
            TokenState::WaitingForTouch,
            TokenState::Signing,
            TokenState::Error,
        ]
        {
            assert_eq!(s.on_event(Event::SignRequested), s,
                "sign request from {s:?} should be a no-op");
        }
    }

    #[test]
    fn touch_press_ignored_outside_waiting()
    {
        for s in [
            TokenState::Booting,
            TokenState::Idle,
            TokenState::Authenticated,
            TokenState::Signing,
            TokenState::Error,
        ]
        {
            assert_eq!(s.on_event(Event::TouchPressed), s,
                "touch press from {s:?} should be a no-op");
        }
    }

    #[test]
    fn error_event_overrides_any_state()
    {
        for s in [
            TokenState::Booting,
            TokenState::Idle,
            TokenState::Authenticated,
            TokenState::WaitingForTouch,
            TokenState::Signing,
            TokenState::Error,
        ]
        {
            assert_eq!(s.on_event(Event::ErrorRaised), TokenState::Error,
                "{s:?} should transition to Error on ErrorRaised");
        }
    }

    #[test]
    fn error_display_elapsed_returns_to_idle()
    {
        let s = TokenState::Error.on_event(Event::ErrorDisplayElapsed);
        assert_eq!(s, TokenState::Idle);
    }

    #[test]
    fn error_display_elapsed_outside_error_is_noop()
    {
        for s in [
            TokenState::Booting,
            TokenState::Idle,
            TokenState::Authenticated,
            TokenState::WaitingForTouch,
            TokenState::Signing,
        ]
        {
            assert_eq!(s.on_event(Event::ErrorDisplayElapsed), s,
                "ErrorDisplayElapsed from {s:?} should be a no-op");
        }
    }

    #[test]
    fn repeated_pin_verified_stays_authenticated()
    {
        let s = TokenState::Idle
            .on_event(Event::PinVerified)
            .on_event(Event::PinVerified)
            .on_event(Event::PinVerified);
        assert_eq!(s, TokenState::Authenticated);
    }

    #[test]
    fn repeated_session_ended_stays_idle()
    {
        let s = TokenState::Idle
            .on_event(Event::SessionEnded)
            .on_event(Event::SessionEnded);
        assert_eq!(s, TokenState::Idle);
    }

    #[test]
    fn timeout_constants_are_reasonable()
    {
        // Touch window matches the user-facing spec.
        assert_eq!(TOUCH_TIMEOUT_MS, 30_000);
    }
}