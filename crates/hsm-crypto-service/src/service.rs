//! High-level crypto service exposed to the USB layer.

use atecc608b::{Atecc, AteccHal};

/// Orchestrates crypto operations on top of the driver.
pub struct CryptoService<H>
where
    H: AteccHal,
{
    // Held for ownership and future use by the service methods. Will be
    // exercised as soon as the first business-logic method (sign, get_pubkey,
    // verify_pin, etc.) is added.
    #[allow(dead_code)]
    atecc: Atecc<H>,
}

impl<H> CryptoService<H>
where
    H: AteccHal,
{
    /// Wrap an existing [`Atecc`] handle.
    pub fn new(atecc: Atecc<H>) -> Self
    {
        Self { atecc }
    }
}
