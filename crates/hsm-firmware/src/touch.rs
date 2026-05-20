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
//! ground), so the GPIO reads `false` when the button is pressed. The
//! conversion to user-facing "pressed = true" is done at the sample site.

use defmt::info;
use embassy_rp::gpio::Input;
use embassy_time::{Duration, Timer};

use hsm_firmware_logic::{Debouncer, Event};

use crate::channels::post_event;

/// Sampling period for the button GPIO.
const SAMPLE_INTERVAL: Duration = Duration::from_millis(1);

/// Drive the touch button sampler. Spawn once at boot.
///
/// `button` is an `Input` configured with an internal pull-up. The pin is
/// owned by this task for the lifetime of the firmware.
#[embassy_executor::task]
pub async fn touch_task(button: Input<'static>) -> !
{
    // Initial state: button assumed released. The first few samples
    // confirm or correct this.
    let mut debouncer = Debouncer::new(false);

    loop
    {
        Timer::after(SAMPLE_INTERVAL).await;

        // Active-low: GPIO `false` = button pressed.
        let pressed = button.is_low();

        if let Some(new_stable) = debouncer.sample(pressed)
        {
            if new_stable
            {
                info!("touch pressed");
                post_event(Event::TouchPressed);
            }
            else
            {
                // Release: no event in the current state machine.
                // Logged for debug only.
                info!("touch released");
            }
        }
    }
}