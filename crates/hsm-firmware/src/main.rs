//! Mini-HSM firmware entry point.
#![no_std]
#![no_main]

use defmt::info;
use defmt_rtt as _;
use embassy_executor::Spawner;
use embassy_rp::gpio::{Level, Output};
use embassy_time::{Duration, Timer};
use panic_probe as _;

mod hal_rp2040;
mod io;
mod state_machine;
mod tasks;
mod usb;

#[embassy_executor::main]
async fn main(_spawner: Spawner)
{
    let peripherals = embassy_rp::init(Default::default());

    // GP16 - green status LED.
    let mut led_status = Output::new(peripherals.PIN_16, Level::Low);

    info!("mini-hsm firmware booted");

    loop
    {
        led_status.set_high();
        Timer::after(Duration::from_millis(500)).await;
        led_status.set_low();
        Timer::after(Duration::from_millis(500)).await;
    }
}
