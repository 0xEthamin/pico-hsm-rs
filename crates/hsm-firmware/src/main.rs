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

//! Mini-HSM firmware entry point.
//!
//! Boot sequence:
//!
//! 1. Initialise embassy-rp peripherals.
//! 2. Configure GPIOs:
//!    - GP15 input with pull-up : touch button (active-low).
//!    - GP16 output : green status LED.
//!    - GP17 output : yellow touch-awaiting LED.
//! 3. Build the USB-HID stack and split it into reader/writer.
//! 4. Build the ATECC HAL on I2C0 (SCL=GP5, SDA=GP4).
//! 5. Spawn the auxiliary tasks: USB run, state machine, animation, touch.
//! 6. Fire `Event::BootComplete` so the state machine leaves the boot state.
//! 7. Enter the dispatch loop in the main task.
//!
//! # `static_cell` instead of `static mut`
//!
//! Two pieces of state need to live in `static` storage so the embassy
//! USB stack can borrow them with a `'static` lifetime: the descriptor
//! buffers and the HID class state. The idiomatic way to allocate these
//! without `unsafe` is [`static_cell::StaticCell`], which lets the runtime
//! check at boot that the storage is initialised exactly once. The price
//! paid is a one-shot `init` call returning `&'static mut T`; the runtime
//! cost is a single atomic flag flip.

#![no_std]
#![no_main]

use defmt::info;
use defmt_rtt as _;
use embassy_executor::Spawner;
use embassy_rp::gpio::{Input, Level, Output, Pull};
use embassy_time::Instant;
use embassy_usb::class::hid::State;
use panic_probe as _;
use static_cell::StaticCell;

use atecc608b::Atecc;
use hsm_crypto_service::{Clock, CryptoService};
use hsm_firmware_logic::Event;

mod animation;
mod channels;
mod hal_rp2040;
mod state;
mod tasks;
mod touch;
mod usb;

use crate::channels::post_event;
use crate::usb::{build_usb, UsbBuffers};

/// Storage for the USB descriptor / control buffers. The contents are
/// borrowed by the USB device for the rest of the program. Initialised
/// once at boot via `init`.
static USB_BUFFERS: StaticCell<UsbBuffers> = StaticCell::new();

/// Storage for the HID class state. Kept separate from `USB_BUFFERS`
/// because `State` is invariant over its lifetime parameter, which
/// forces it to share a single named lifetime with the device borrow.
static HID_STATE: StaticCell<State<'static>> = StaticCell::new();

/// Clock backed by `embassy_time::Instant`. Provides milliseconds since
/// boot, monotonic, used by the PIN session timeout.
pub(crate) struct EmbassyClock;

impl Clock for EmbassyClock
{
    fn now_ms(&self) -> u64
    {
        Instant::now().as_millis()
    }
}

#[embassy_executor::main]
async fn main(spawner: Spawner)
{
    let peripherals = embassy_rp::init(Default::default());

    // GPIOs.
    // GP15 : touch button. Active-low: switch to ground, internal pull-up
    // to 3V3. Reads low when pressed.
    let button = Input::new(peripherals.PIN_15, Pull::Up);
    // GP16 : green status LED, active-high.
    let led_green = Output::new(peripherals.PIN_16, Level::Low);
    // GP17 : yellow touch-awaiting LED, active-high.
    let led_yellow = Output::new(peripherals.PIN_17, Level::Low);

    info!("mini-hsm firmware booted");

    // Initialise the static storage exactly once. `init` returns a
    // `&'static mut T` borrowed from the cell.
    let buffers = USB_BUFFERS.init(UsbBuffers::new());
    let hid_state = HID_STATE.init(State::new());

    let (usb_device, rx, tx) = build_usb(peripherals.USB, buffers, hid_state);

    // Build the ATECC handle on I2C0 (SCL=GP5, SDA=GP4 per the project
    // schematic). The Peri singletons are moved into the HAL, which
    // re-borrows them on every transaction or wake pulse.
    let hal = hal_rp2040::Rp2040Hal::new
    (
        peripherals.I2C0,
        peripherals.PIN_5,
        peripherals.PIN_4,
    );
    let atecc = Atecc::new(hal);

    let service = CryptoService::new(atecc, EmbassyClock);

    // Spawn the auxiliary tasks. `spawner.spawn` returns `()`; the
    // `#[embassy_executor::task]` macro wraps the task body in a function
    // returning `Result<SpawnToken, SpawnError>` which we expect here.
    // `SpawnError` only fires when the task pool is full, which cannot
    // happen at boot with the queue empty.
    spawner.spawn
    (
        tasks::usb_run_task(usb_device).expect("failed to spawn USB run task"),
    );
    spawner.spawn
    (
        state::state_task().expect("failed to spawn state machine task"),
    );
    spawner.spawn
    (
        animation::animation_task(led_green, led_yellow)
            .expect("failed to spawn animation task"),
    );
    spawner.spawn
    (
        touch::touch_task(button).expect("failed to spawn touch task"),
    );

    // Now that every auxiliary task is up, tell the state machine that
    // boot is complete so it leaves the Booting state.
    post_event(Event::BootComplete);

    // Enter the dispatch loop. Never returns.
    tasks::dispatch_loop(rx, tx, service).await
}