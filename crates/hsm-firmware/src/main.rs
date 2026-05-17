//! Mini-HSM firmware entry point.
//!
//! Boot sequence:
//!
//! 1. Initialise embassy-rp peripherals.
//! 2. Configure status / touch-awaiting LEDs (GP16, GP17).
//! 3. Build the USB-HID stack and split it into reader/writer.
//! 4. Build the (stub) ATECC HAL on I2C0.
//! 5. Spawn the USB run task.
//! 6. Enter the dispatch loop in the main task.
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
use embassy_rp::gpio::{Level, Output};
use embassy_time::Instant;
use embassy_usb::class::hid::State;
use panic_probe as _;

use atecc608b::Atecc;
use hsm_crypto_service::{Clock, CryptoService};

mod hal_rp2040;
mod tasks;
mod usb;

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

    // GP16 - green status LED.
    let _led_status = Output::new(peripherals.PIN_16, Level::Low);
    // GP17 - yellow touch-awaiting LED.
    let _led_touch = Output::new(peripherals.PIN_17, Level::Low);

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

    // Build the (stub) ATECC handle. The HAL implementation against the
    // real I2C peripheral is filled in in a later iteration.
    let hal = hal_rp2040::StubHal::new();
    let atecc = Atecc::new(hal);

    let service = CryptoService::new(atecc, EmbassyClock);

    // Spawn the USB run task. Required to keep the USB stack alive.
    //
    // `#[embassy_executor::task]` wraps the task body in a function that
    // returns `Result<SpawnToken, SpawnError>`. We unwrap that here
    // because spawning at boot, before anything else is queued, cannot
    // fail (the queue is empty). `spawner.spawn` itself returns `()` on
    // this version of embassy-executor.
    spawner.spawn(tasks::usb_run_task(usb_device).unwrap());

    // Enter the dispatch loop. Never returns.
    tasks::dispatch_loop(rx, tx, service).await
}