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

//! LED animation task.
//!
//! Reads the current [`TokenState`] off [`crate::channels::TOKEN_STATE`] and
//! drives the green (GP16) and yellow (GP17) LEDs at the cadence dictated
//! by the state's [`LedPattern`].
//!
//! The task runs an infinite loop with two interleaved concerns:
//!
//! 1. **Apply the current pattern.** Each pattern has a tick interval and
//!    a per-tick action (toggle green, toggle yellow, alternate, etc).
//!    The task sleeps for the tick interval, then performs the action.
//! 2. **React to state changes promptly.** Sleeping for a 500 ms tick
//!    would make a transition into `Error` invisible for half a second.
//!    To avoid that, the task races the tick timer against
//!    [`crate::channels::TOKEN_STATE`] using `embassy_futures::select`.
//!    Whichever fires first wins.
//!
//! Active-high LEDs assumed: `set_high` lights up, `set_low` turns off.

use defmt::info;
use embassy_futures::select::{select, Either};
use embassy_rp::gpio::Output;
use embassy_time::{Duration, Timer};

use hsm_firmware_logic::LedPattern;

use crate::channels::TOKEN_STATE;

/// Tick interval for the slow pulse pattern (green, 1 Hz).
const SLOW_PULSE_INTERVAL: Duration = Duration::from_millis(500);

/// Tick interval for the fast blink pattern (5 Hz).
const FAST_BLINK_INTERVAL: Duration = Duration::from_millis(100);

/// Tick interval for the yellow blink pattern (2 Hz).
const YELLOW_BLINK_INTERVAL: Duration = Duration::from_millis(250);

/// Tick interval for the alternate-both pattern (5 Hz).
const ALTERNATE_INTERVAL: Duration = Duration::from_millis(100);

/// Drive the LEDs based on the current operating state. Spawn once at boot.
///
/// Both LEDs are owned by this task for the lifetime of the firmware.
#[embassy_executor::task]
pub(crate) async fn animation_task
(
    mut led_green: Output<'static>,
    mut led_yellow: Output<'static>,
) -> !
{
    // Wait for the first state publication. The state task always emits
    // the initial state at startup, so this returns promptly.
    let mut state = TOKEN_STATE.wait().await;
    info!("animation task started, initial state {:?}", state);

    // Tick phase: toggles every iteration to drive blink/pulse patterns.
    let mut tick_high = false;

    loop
    {
        // Apply the current pattern.
        let interval = apply_pattern
        (
            state.led_pattern(),
            tick_high,
            &mut led_green,
            &mut led_yellow,
        );
        tick_high = !tick_high;

        // Race the tick timer against a state change.
        match select(Timer::after(interval), TOKEN_STATE.wait()).await
        {
            Either::First(()) =>
            {
                // Tick elapsed, continue with the same pattern.
            }
            Either::Second(new_state) =>
            {
                // State changed: reset the tick phase and switch pattern
                // immediately.
                info!("animation: state {:?} -> {:?}", state, new_state);
                state = new_state;
                tick_high = false;
            }
        }
    }
}

/// Apply one tick of `pattern` to the LEDs and return the duration to wait
/// before the next tick.
///
/// `tick_high` alternates `false`/`true` each iteration. For static
/// patterns (solid, all-off) the value is ignored.
fn apply_pattern
(
    pattern: LedPattern,
    tick_high: bool,
    led_green: &mut Output<'static>,
    led_yellow: &mut Output<'static>,
) -> Duration
{
    match pattern
    {
        LedPattern::AllOff =>
        {
            led_green.set_low();
            led_yellow.set_low();
            // No animation: long wait, the select will wake us on the
            // next state change.
            Duration::from_secs(60)
        }
        LedPattern::GreenSolid =>
        {
            led_green.set_high();
            led_yellow.set_low();
            Duration::from_secs(60)
        }
        LedPattern::GreenSlowPulse =>
        {
            led_yellow.set_low();
            if tick_high
            {
                led_green.set_high();
            }
            else
            {
                led_green.set_low();
            }
            SLOW_PULSE_INTERVAL
        }
        LedPattern::GreenFastBlink =>
        {
            led_yellow.set_low();
            if tick_high
            {
                led_green.set_high();
            }
            else
            {
                led_green.set_low();
            }
            FAST_BLINK_INTERVAL
        }
        LedPattern::YellowSolid =>
        {
            led_green.set_low();
            led_yellow.set_high();
            Duration::from_secs(60)
        }
        LedPattern::YellowBlink =>
        {
            led_green.set_low();
            if tick_high
            {
                led_yellow.set_high();
            }
            else
            {
                led_yellow.set_low();
            }
            YELLOW_BLINK_INTERVAL
        }
        LedPattern::AlternateBoth =>
        {
            if tick_high
            {
                led_green.set_high();
                led_yellow.set_low();
            }
            else
            {
                led_green.set_low();
                led_yellow.set_high();
            }
            ALTERNATE_INTERVAL
        }
    }
}