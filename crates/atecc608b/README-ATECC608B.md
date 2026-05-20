# atecc608b

`no_std` async driver for the [Microchip ATECC608B](https://www.microchip.com/en-us/product/ATECC608B)
secure element, built on a generic HAL trait so it works with any embedded
platform (RP2040 + Embassy, STM32, or a host-side mock for tests).

## Features

- **`no_std`, no heap** : stack buffers only, compatible with bare-metal firmware.
- **Async** : non-blocking polling via `async fn`. Works with Embassy or any
  executor that supports `core::future::Future`.
- **Generic HAL** : implement [`AteccHal`] for your platform. The driver itself
  has zero platform-specific code.
- **Optional `defmt`** : enable the `defmt` feature to get structured debug
  output of internal driver states.

## Supported commands

`Info`, `Random`, `Read`, `Write`, `Lock`, `Nonce`, `GenKey`, `Sign`,
`Verify`, `PrivWrite`, `Counter`, `CheckMac`, `GenDig`.

## Usage

```rust
use atecc608b::{Atecc, AteccHal, AteccError};

// Implement AteccHal for your platform:
struct MyHal { /* ... */ }
impl AteccHal for MyHal { /* ... */ }

async fn example(hal: MyHal) -> Result<(), AteccError</* your error type */>> 
{
    let mut atecc = Atecc::new(hal);
    let revision = atecc.info_revision().await?;
    atecc.idle().await?;
    Ok(())
}
```

## HAL trait

Your platform must implement [`hal::AteccHal`], which requires:
- `i2c_write` / `i2c_read` : I2C transfers to the chip
- `pulse_sda_low` : the wake pulse (temporarily drive SDA as GPIO)
- `delay_us` / `delay_ms` : time delays

## License

GPL-3.0-or-later. See [LICENSE](LICENSE) for details.
