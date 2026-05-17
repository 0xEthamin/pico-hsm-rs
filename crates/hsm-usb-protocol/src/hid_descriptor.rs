//! HID report descriptor for the mini-HSM.
//!
//! The descriptor declares a vendor-defined usage page (`0xFF00`) with one
//! 128-byte IN report and one 128-byte OUT report. This is the same shape
//! as a FIDO/U2F device (just with a larger report size), which keeps
//! host-side support universal across Linux, macOS, and Windows: no
//! kernel driver, no admin privileges, just `hidapi` or equivalent.
//!
//! Byte breakdown:
//!
//! ```text
//! 06 00 FF       Usage Page (Vendor Defined 0xFF00)
//! 09 01          Usage (Vendor Usage 1)
//! A1 01          Collection (Application)
//! 09 20            Usage (Vendor Usage 0x20)         [for IN reports]
//! 15 00            Logical Minimum (0)
//! 26 FF 00         Logical Maximum (255)
//! 75 08            Report Size (8 bits)
//! 95 80            Report Count (128)
//! 81 02            Input (Data, Variable, Absolute)
//! 09 21            Usage (Vendor Usage 0x21)         [for OUT reports]
//! 15 00            Logical Minimum (0)
//! 26 FF 00         Logical Maximum (255)
//! 75 08            Report Size (8 bits)
//! 95 80            Report Count (128)
//! 91 02            Output (Data, Variable, Absolute)
//! C0             End Collection
//! ```
//!
//! Reference: the FIDO U2F HID descriptor in
//! `https://fidoalliance.org/specs/fido-u2f-v1.2-ps-20170411/fido-u2f-hid-protocol-v1.2-ps-20170411.html`,
//! section "HID Report Descriptor and Device Identification". The U2F spec
//! uses 64-byte reports; we bump that to 128 so a single ECDSA P-256
//! signature or public key fits in one report.

/// HID report descriptor, exactly as sent to the host during USB enumeration.
pub const HID_REPORT_DESCRIPTOR: &[u8] = &[
    0x06, 0x00, 0xFF,       // Usage Page (Vendor Defined 0xFF00)
    0x09, 0x01,             // Usage (Vendor Usage 1)
    0xA1, 0x01,             // Collection (Application)

    // Input report: token -> host
    0x09, 0x20,             //   Usage (Vendor Usage 0x20)
    0x15, 0x00,             //   Logical Minimum (0)
    0x26, 0xFF, 0x00,       //   Logical Maximum (255)
    0x75, 0x08,             //   Report Size (8 bits)
    0x95, 0x80,             //   Report Count (128)
    0x81, 0x02,             //   Input (Data, Variable, Absolute)

    // Output report: host -> token
    0x09, 0x21,             //   Usage (Vendor Usage 0x21)
    0x15, 0x00,             //   Logical Minimum (0)
    0x26, 0xFF, 0x00,       //   Logical Maximum (255)
    0x75, 0x08,             //   Report Size (8 bits)
    0x95, 0x80,             //   Report Count (128)
    0x91, 0x02,             //   Output (Data, Variable, Absolute)

    0xC0,                   // End Collection
];

#[cfg(test)]
mod tests
{
    use super::*;

    #[test]
    fn descriptor_length_is_34()
    {
        // 3 (usage page) + 2 (usage) + 2 (collection)
        // + 2 * (2 + 2 + 3 + 2 + 2 + 2)  per direction (in + out)
        // + 1 (end collection)
        // = 7 + 26 + 1 = 34.
        assert_eq!(HID_REPORT_DESCRIPTOR.len(), 34);
    }

    #[test]
    fn descriptor_starts_with_vendor_usage_page_ff00()
    {
        // 06 00 FF = Usage Page (Vendor 0xFF00)
        assert_eq!(&HID_REPORT_DESCRIPTOR[..3], &[0x06, 0x00, 0xFF]);
    }

    #[test]
    fn descriptor_ends_with_end_collection()
    {
        assert_eq!(*HID_REPORT_DESCRIPTOR.last().unwrap(), 0xC0);
    }

    #[test]
    fn descriptor_declares_128_byte_reports()
    {
        // Report Count is 0x95 0x80 (= 128). It appears twice (IN and OUT).
        let mut occurrences = 0;
        let mut i = 0;
        while i + 1 < HID_REPORT_DESCRIPTOR.len()
        {
            if HID_REPORT_DESCRIPTOR[i] == 0x95 && HID_REPORT_DESCRIPTOR[i + 1] == 0x80
            {
                occurrences += 1;
            }
            i += 1;
        }
        assert_eq!(occurrences, 2);
    }

    #[test]
    fn descriptor_declares_8_bit_report_size()
    {
        // Report Size is 0x75 0x08 (= 8 bits). It appears twice.
        let mut occurrences = 0;
        let mut i = 0;
        while i + 1 < HID_REPORT_DESCRIPTOR.len()
        {
            if HID_REPORT_DESCRIPTOR[i] == 0x75 && HID_REPORT_DESCRIPTOR[i + 1] == 0x08
            {
                occurrences += 1;
            }
            i += 1;
        }
        assert_eq!(occurrences, 2);
    }
}