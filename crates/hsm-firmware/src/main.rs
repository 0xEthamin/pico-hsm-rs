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
//! 4. Build the (stub) ATECC HAL on I2C0.
//! 5. Spawn the auxiliary tasks: USB run, state machine, animation, touch.
//! 6. Fire `Event::BootComplete` so the state machine leaves the boot state.
//! 7. Enter the dispatch loop in the main task.
//!
//! The HAL implementation against the real RP2040 I2C peripheral lives in
//! [`crate::hal_rp2040`] and is currently a stub. Until it is filled in,
//! every ATECC call returns an error; the USB stack itself still
//! enumerates and responds with the appropriate `AteccCommunicationError`
//! status.

#![no_std]
#![no_main]

use defmt::info;
use defmt_rtt as _;
use embassy_executor::Spawner;
use embassy_rp::gpio::{Input, Level, Output, Pull};
use embassy_time::Instant;
use embassy_usb::class::hid::State;
use panic_probe as _;

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

/// Static descriptor / control buffers. embassy-usb borrows these for the
/// lifetime of the device.
static mut USB_BUFFERS: UsbBuffers = UsbBuffers::new();

/// Static HID class state. Separate from [`USB_BUFFERS`] because `State`
/// is invariant over its lifetime parameter, which forces it to share a
/// single named lifetime with the device borrow.
static mut HID_STATE: State<'static> = State::new();

/// Clock backed by `embassy_time::Instant`. Provides milliseconds since
/// boot, monotonic, used by the PIN session timeout.
pub struct EmbassyClock;

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
    // GP15 - touch button. Active-low: switch to ground, internal pull-up
    // to 3V3. Reads low when pressed.
    let button = Input::new(peripherals.PIN_15, Pull::Up);
    // GP16 - green status LED, active-high.
    let led_green = Output::new(peripherals.PIN_16, Level::Low);
    // GP17 - yellow touch-awaiting LED, active-high.
    let led_yellow = Output::new(peripherals.PIN_17, Level::Low);

    info!("mini-hsm firmware booted");

    // Take 'static mutable references to the USB statics. Done once at
    // boot, before any other task can touch them, so a single thread of
    // execution holds the references. After this point the references are
    // moved into the USB stack and live there for the rest of the program.
    //
    // SAFETY: see the comment above.
    let buffers: &'static mut UsbBuffers = unsafe
    {
        #[allow(static_mut_refs)]
        &mut USB_BUFFERS
    };
    let hid_state: &'static mut State<'static> = unsafe
    {
        #[allow(static_mut_refs)]
        &mut HID_STATE
    };

    let (usb_device, rx, tx) = build_usb(peripherals.USB, buffers, hid_state);

    // Build the ATECC handle on I2C0 (SCL=GP5, SDA=GP4 per the project
    // schematic). The Peri singletons are moved into the HAL, which
    // re-borrows them on every transaction or wake pulse.
    let hal = hal_rp2040::Rp2040Hal::new(
        peripherals.I2C0,
        peripherals.PIN_5,
        peripherals.PIN_4,
    );
    let atecc = Atecc::new(hal);

    let service = CryptoService::new(atecc, EmbassyClock);

    // Spawn the auxiliary tasks. Each `spawner.spawn(...)` call returns
    // `()`; the `#[embassy_executor::task]` macro wraps the task body in
    // a function that returns `Result<SpawnToken, SpawnError>`. The
    // unwrap on the inner result cannot fail at boot because the task
    // queue is empty.
    spawner.spawn(tasks::usb_run_task(usb_device).unwrap());
    spawner.spawn(state::state_task().unwrap());
    spawner.spawn(animation::animation_task(led_green, led_yellow).unwrap());
    spawner.spawn(touch::touch_task(button).unwrap());

    // Now that every auxiliary task is up, tell the state machine that
    // boot is complete so it leaves the Booting state.
    post_event(Event::BootComplete);

    // Enter the dispatch loop. Never returns.
    tasks::dispatch_loop(rx, tx, service).await
}