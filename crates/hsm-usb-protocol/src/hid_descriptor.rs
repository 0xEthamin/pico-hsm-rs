//! HID report descriptor for the mini-HSM.
//!
//! The descriptor declares a vendor-defined usage page (`0xFF00`) with one
//! 64-byte IN report and one 64-byte OUT report. This is the same shape as a
//! FIDO/U2F device, which keeps host-side support universal.
//!
//! Will be fleshed out in future with the actual byte sequence parsed by Linux /
//! Windows / macOS.
