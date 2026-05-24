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

//! Touch button sampling task.
//!
//! Samples the button GPIO at 1 ms intervals, runs the signal through a
//! [`Debouncer`], and posts [`Event::TouchPressed`] on every confirmed
//! press (low -> high transition of the user-facing "pressed" boolean).
//!
//! The button is active-low on this hardware (pull-up to 3V3, switch to
//! ground); the [`Button`] trait abstracts that away, so
//! [`Button::is_pressed_raw`] returns `true` when the user is pressing.
//!
//! # Testability
//!
//! The driving logic is implemented as the generic helper
//! [`sample_once`], which takes any `Button` impl. The embassy task
//! [`touch_task`] is a thin shell that owns a real `Input<'static>`
//! and forwards to the helper; tests in this module exercise the
//! helper directly with a `MockButton`.

use defmt::info;
use embassy_time::{Duration, Timer};

use hsm_firmware_logic::{Button, Debouncer, Event};

use crate::channels::post_event;
use crate::hal_rp2040::Rp2040Button;

/// Sampling period for the button GPIO.
const SAMPLE_INTERVAL: Duration = Duration::from_millis(1);

/// Drive the touch button sampler. Spawn once at boot.
///
/// `button` is a wrapped `Input` configured with an internal pull-up. The
/// pin is owned by this task for the lifetime of the firmware.
#[embassy_executor::task]
pub(crate) async fn touch_task(button: Rp2040Button) -> !
{
    // Initialise the debouncer to the current raw state so we don't post
    // a spurious "press" if the user is already holding the button at
    // boot.
    let initial = button.is_pressed_raw();
    let mut debouncer = Debouncer::new(initial);
    info!
    (
        "touch task started, initial stable state = {}",
        debouncer.stable(),
    );

    loop
    {
        Timer::after(SAMPLE_INTERVAL).await;
        sample_once(&button, &mut debouncer);
    }
}

/// Sample the button once and post a [`Event::TouchPressed`] event if
/// the debouncer accepts a low->high transition (release -> press).
///
/// Generic over [`Button`] so it can be exercised in host-side tests
/// with a mock button.
fn sample_once<B: Button>(button: &B, debouncer: &mut Debouncer)
{
    let pressed = button.is_pressed_raw();

    if let Some(new_stable) = debouncer.sample(pressed)
    {
        if new_stable
        {
            info!("touch pressed");
            post_event(Event::TouchPressed);
        }
        else
        {
            // Release: no event in the current state machine. Logged
            // for debug only.
            info!("touch released");
        }
    }
}

#[cfg(test)]
mod tests
{
    use super::*;
    use hsm_firmware_logic::DEBOUNCE_STABLE_SAMPLES;

    /// Mock button whose raw state is mutable from the test.
    struct MockButton
    {
        pressed: bool,
    }

    impl Button for MockButton
    {
        fn is_pressed_raw(&self) -> bool
        {
            self.pressed
        }
    }

    #[test]
    fn sample_once_does_not_post_on_no_transition()
    {
        // Both the button and the debouncer are already at "not
        // pressed". A sample of the same state should not produce a
        // transition.
        let button = MockButton { pressed: false };
        let mut debouncer = Debouncer::new(false);
        // No assertion possible on `post_event` here (it writes to a
        // global channel), so we assert on the debouncer's own state
        // staying put. If `sample` returned `Some`, the debouncer
        // would have committed.
        for _ in 0..(DEBOUNCE_STABLE_SAMPLES + 2)
        {
            sample_once(&button, &mut debouncer);
        }
        assert!(!debouncer.stable());
    }

    #[test]
    fn sample_once_promotes_after_stable_count()
    {
        // Simulate the bouncer phase where every sample is `pressed=true`
        // and the debouncer needs `DEBOUNCE_STABLE_SAMPLES` of them to
        // commit.
        let button = MockButton { pressed: true };
        let mut debouncer = Debouncer::new(false);
        for _ in 0..(DEBOUNCE_STABLE_SAMPLES - 1)
        {
            sample_once(&button, &mut debouncer);
            assert!(!debouncer.stable());
        }
        // The N-th sample commits.
        sample_once(&button, &mut debouncer);
        assert!(debouncer.stable());
    }
}
