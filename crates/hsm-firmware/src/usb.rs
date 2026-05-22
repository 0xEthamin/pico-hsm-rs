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

//! USB-HID device stack.
//!
//! Initialises an embassy-usb device that exposes one vendor-defined HID
//! interface, per the project's USB protocol (see crate `hsm-usb-protocol`).
//!
//! The two endpoints are split into a [`HidReader`] (host -> token) and a
//! [`HidWriter`] (token -> host). They are owned by separate async tasks
//! in [`crate::tasks`] so reads and writes proceed independently.
//!
//! # Lifetime model
//!
//! [`embassy_usb::class::hid::State`] is invariant over its lifetime
//! parameter, which means the `'d` lifetime tag of the [`HidReaderWriter`]
//! must match exactly the lifetime tag of the `State` it borrows. We
//! therefore take the `State` as a separate parameter to [`build_usb`]
//! with its own borrow, and the device lifetime `'d` is derived from
//! whichever borrow is shortest. In practice both borrows come from
//! `static` storage at the call site, so `'d = 'static`.

use embassy_rp::peripherals::USB;
use embassy_rp::usb::{Driver, InterruptHandler};
use embassy_rp::{bind_interrupts, Peri};
use embassy_usb::class::hid::{
    Config as HidConfig, HidBootProtocol, HidReaderWriter, HidSubclass, State,
};
use embassy_usb::{Builder, Config, UsbDevice};

use hsm_usb_protocol::{HID_REPORT_DESCRIPTOR, HID_REPORT_SIZE, USB_PID, USB_VID};

bind_interrupts!(pub(crate) struct Irqs
{
    USBCTRL_IRQ => InterruptHandler<USB>;
});

/// Size of the HID report in bytes (matches `HID_REPORT_SIZE`).
pub(crate) const REPORT_SIZE: usize = HID_REPORT_SIZE;

/// HID reader half: receives host -> token reports.
pub(crate) type HidRx<'d> = embassy_usb::class::hid::HidReader<'d, Driver<'d, USB>, REPORT_SIZE>;

/// HID writer half: sends token -> host reports.
pub(crate) type HidTx<'d> = embassy_usb::class::hid::HidWriter<'d, Driver<'d, USB>, REPORT_SIZE>;

/// embassy-usb device handle. Spawn its `run` future to keep the USB stack
/// alive.
pub(crate) type UsbStack<'d> = UsbDevice<'d, Driver<'d, USB>>;

/// Descriptor and control-transfer buffers borrowed by the embassy-usb
/// builder for the lifetime of the device.
///
/// Held in a separate struct so the borrow checker sees one stable address
/// for each buffer. Storing them as fields of a single `static mut` value
/// is the idiomatic embassy-rp pattern for systems without an allocator.
pub(crate) struct UsbBuffers
{
    /// USB configuration descriptor buffer.
    pub(crate) config_descriptor: [u8; 256],
    /// USB BOS descriptor buffer.
    pub(crate) bos_descriptor:    [u8; 256],
    /// USB MSOS descriptor buffer (unused, kept for the Builder API).
    pub(crate) msos_descriptor:   [u8; 256],
    /// Control transfer scratch buffer.
    pub(crate) control_buf:       [u8; 64],
}

impl UsbBuffers
{
    /// Build an empty set of buffers.
    #[must_use]
    pub(crate) const fn new() -> Self
    {
        Self
        {
            config_descriptor: [0; 256],
            bos_descriptor:    [0; 256],
            msos_descriptor:   [0; 256],
            control_buf:       [0; 64],
        }
    }
}

impl Default for UsbBuffers
{
    fn default() -> Self
    {
        Self::new()
    }
}

/// Build the USB device with one HID interface.
///
/// `buffers` holds the descriptor and control buffers; `hid_state` holds the
/// HID class internal state. Both must outlive the returned device,
/// reader, and writer, so the caller typically allocates them in `static`
/// storage and passes mutable references with `'static` lifetime.
///
/// Returns the device (whose `run` future must be polled forever by a task)
/// and the split HID reader/writer.
pub(crate) fn build_usb<'d>
(
    usb: Peri<'d, USB>,
    buffers: &'d mut UsbBuffers,
    hid_state: &'d mut State<'d>,
) -> (UsbStack<'d>, HidRx<'d>, HidTx<'d>)
{
    let driver = Driver::new(usb, Irqs);

    let mut config = Config::new(USB_VID, USB_PID);
    config.manufacturer  = Some("Ethamin");
    config.product       = Some("mini-HSM");
    config.serial_number = Some("0001");
    config.max_power     = 100;
    // 64 bytes is the max for USB full-speed; a 128-byte HID report is sent
    // as two 64-byte transactions automatically by the stack.
    config.max_packet_size_0 = 64;

    let mut builder = Builder::new
    (
        driver,
        config,
        &mut buffers.config_descriptor,
        &mut buffers.bos_descriptor,
        &mut buffers.msos_descriptor,
        &mut buffers.control_buf,
    );

    let hid_config = HidConfig
    {
        report_descriptor: HID_REPORT_DESCRIPTOR,
        request_handler:   None,
        poll_ms:           10,
        max_packet_size:   64,
        hid_subclass:      HidSubclass::No,
        hid_boot_protocol: HidBootProtocol::None,
    };

    let hid = HidReaderWriter::<_, REPORT_SIZE, REPORT_SIZE>::new
    (
        &mut builder,
        hid_state,
        hid_config,
    );

    let device = builder.build();
    let (reader, writer) = hid.split();
    (device, reader, writer)
}