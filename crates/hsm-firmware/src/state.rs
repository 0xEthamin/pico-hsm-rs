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

//! State machine task.
//!
//! Owns the single instance of [`TokenState`] and applies transitions in
//! response to events posted on [`crate::channels::EVENT_CHANNEL`]. After
//! each transition it republishes the new state on
//! [`crate::channels::TOKEN_STATE`] so the animation task can update the
//! LEDs, and pulses [`crate::channels::TOUCH_CONFIRMED`] when it enters
//! the [`TokenState::Signing`] state so the dispatch loop can resume.
//!
//! # Internal timers
//!
//! The state task races [`EVENT_CHANNEL`] against two optional deadlines:
//!
//! - **Session timeout**: armed when entering [`TokenState::Authenticated`].
//!   Re-armed on every event that proves the user is still active (a
//!   successful `SignComplete`, or a fresh `PinVerified`). If the deadline
//!   fires first, the task posts [`Event::SessionEnded`] internally, which
//!   drops the SM back to [`TokenState::Idle`].
//! - **Error display window**: armed when entering [`TokenState::Error`].
//!   When the deadline elapses, posts [`Event::ErrorDisplayElapsed`] which
//!   returns the SM to [`TokenState::Idle`].
//!
//! Both deadlines share the same race future via `select3`; whichever
//! fires first wins. The non-armed case uses a far-future deadline so it
//! cannot interrupt the channel receive.

use defmt::info;
use embassy_futures::select::{select, Either};
use embassy_time::{Duration, Instant, Timer};

use hsm_crypto_service::SESSION_TIMEOUT_MS;
use hsm_firmware_logic::{Event, TokenState, ERROR_DISPLAY_MS};

use crate::channels::{EVENT_CHANNEL, TOKEN_STATE, TOUCH_CONFIRMED};

/// Drive the token state machine. Spawn once at boot.
#[embassy_executor::task]
pub async fn state_task() -> !
{
    let mut state = TokenState::initial();
    // Publish initial state immediately so the animation task does not
    // have to wait for the first event to know what to display.
    TOKEN_STATE.signal(state);

    // Deadlines for the two timers. `None` means the timer is disarmed.
    let mut session_deadline: Option<Instant> = None;
    let mut error_deadline:   Option<Instant> = None;

    loop
    {
        // Compute the earliest pending deadline. If both timers are
        // disarmed, pick a deadline far in the future so the select
        // effectively waits on the channel only.
        let deadline = earliest(session_deadline, error_deadline);
        let now = Instant::now();
        let wait = if deadline > now
        {
            deadline - now
        }
        else
        {
            // Deadline already in the past: fire the timer arm
            // immediately by waiting zero. This handles the case where
            // the channel was busy when the deadline passed.
            Duration::from_ticks(0)
        };

        let next_event = match select(EVENT_CHANNEL.receive(), Timer::after(wait)).await
        {
            Either::First(event) => event,
            Either::Second(()) =>
            {
                // A timer expired. Figure out which one and translate it
                // to the appropriate internal event.
                derive_timer_event(&mut session_deadline, &mut error_deadline)
            }
        };

        let next = state.on_event(next_event);

        if next != state
        {
            info!("state {:?} -> {:?} on event {:?}", state, next, next_event);
            state = next;
            TOKEN_STATE.signal(state);

            if state == TokenState::Signing
            {
                // Wake the dispatch loop so it can perform the actual
                // signing operation now that the user has touched.
                TOUCH_CONFIRMED.signal(());
            }
        }

        // Arm or refresh the relevant timer based on the new (or unchanged)
        // state and the event we just consumed.
        update_timers(state, next_event, &mut session_deadline, &mut error_deadline);
    }
}

/// Return the earlier of two optional deadlines, or a far-future deadline
/// if neither is armed.
fn earliest(a: Option<Instant>, b: Option<Instant>) -> Instant
{
    match (a, b)
    {
        (Some(x), Some(y)) => if x < y { x } else { y },
        (Some(x), None)    => x,
        (None,    Some(y)) => y,
        // 1 hour from now: any future tick is fine, the timer will be
        // re-armed before then by the normal event flow.
        (None,    None)    => Instant::now() + Duration::from_secs(3600),
    }
}

/// Translate a timer expiration into the corresponding internal event.
///
/// Inspects which deadline is in the past (relative to now) and clears
/// it, returning the matching `Event`. If both are simultaneously in the
/// past, the session timeout wins (it is the more semantically meaningful
/// of the two).
fn derive_timer_event(
    session_deadline: &mut Option<Instant>,
    error_deadline:   &mut Option<Instant>,
) -> Event
{
    let now = Instant::now();
    if let Some(d) = *session_deadline
    {
        if d <= now
        {
            *session_deadline = None;
            return Event::SessionEnded;
        }
    }
    if let Some(d) = *error_deadline
    {
        if d <= now
        {
            *error_deadline = None;
            return Event::ErrorDisplayElapsed;
        }
    }
    // Should not happen: the select's timer branch fired but no deadline
    // matched. Most likely a logic bug. Fall back to a no-op event.
    defmt::warn!("timer fired but no deadline matched");
    Event::SessionEnded
}

/// Re-arm or clear the timers based on the SM state and the latest event.
///
/// - Entering [`TokenState::Authenticated`] arms the session timer.
/// - Each `PinVerified` event refreshes the session timer (the user is
///   active).
/// - A successful `SignComplete` also refreshes the session timer.
/// - Leaving `Authenticated` (or its children: `WaitingForTouch`, `Signing`)
///   for `Idle` or `Error` clears the session timer.
/// - Entering `Error` arms the error display timer.
/// - Leaving `Error` clears the error display timer.
fn update_timers(
    state:            TokenState,
    last_event:       Event,
    session_deadline: &mut Option<Instant>,
    error_deadline:   &mut Option<Instant>,
)
{
    // Session timer: any of the three "user is active" states.
    let user_active_state = matches!
    (
        state,
        TokenState::Authenticated | TokenState::WaitingForTouch | TokenState::Signing
    );

    if user_active_state
    {
        // Refresh on activity events.
        let refresh = matches!
        (
            last_event,
            Event::PinVerified | Event::SignComplete | Event::SignRequested | Event::TouchPressed
        );
        if refresh || session_deadline.is_none()
        {
            *session_deadline =
                Some(Instant::now() + Duration::from_millis(SESSION_TIMEOUT_MS));
        }
    }
    else
    {
        *session_deadline = None;
    }

    // Error display timer.
    if state == TokenState::Error
    {
        if error_deadline.is_none()
        {
            *error_deadline =
                Some(Instant::now() + Duration::from_millis(ERROR_DISPLAY_MS));
        }
    }
    else
    {
        *error_deadline = None;
    }
}