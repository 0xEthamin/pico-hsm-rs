# Config zone layout (128 bytes)

This document will describe, byte by byte, the contents of the ATECC608B
config zone as written by `tools/config-generator/` and verified by
`hsm-host read-config`.

The high-level slot policy is summarized in
[`crates/hsm-crypto-service/src/slots.rs`](../crates/hsm-crypto-service/src/slots.rs).

## Layout overview

| Byte range | Content                       | Editable before lock(config)? |
|------------|-------------------------------|-------------------------------|
| 0-15       | Factory data (SN, RevNum...)    | No (read-only from factory)   |
| 16         | I2C address                   | Yes                           |
| 17         | Reserved (must stay 0x00)     | Yes                           |
| 18         | OTP mode                      | Yes                           |
| 19         | ChipMode                      | Yes                           |
| 20-51      | SlotConfig[0..15] (2 B each)  | Yes                           |
| 52-67      | Counter0 / Counter1           | Yes (until lock)              |
| 68-83      | UseLock, VolatileKey...         | Yes                           |
| 84-85      | UserExtra, Selector           | Yes (until lock)              |
| 86         | LockValue (data zone)         | **Read-only after lock**      |
| 87         | LockConfig (config zone)      | **Read-only after lock**      |
| 88-89      | SlotLocked bitmap             | Yes (until each slot lock)    |
| 90-91      | X509 format                   | Yes                           |
| 92-95      | ChipOptions                   | Yes                           |
| 96-127     | KeyConfig[0..15] (2 B each)   | Yes                           |

## Per-slot decision table

(Fields to be filled after I converge on the exact bits for `ReqAuth`,
`AuthKey`, `WriteConfig`, etc.)

| Slot | SlotConfig (hex) | KeyConfig (hex) | Comment                             |
|------|------------------|-----------------|-------------------------------------|
| 0    | TBD              | TBD             | Primary P-256, PIN-gated            |
| 1-4  | TBD              | TBD             | Same as slot 0                      |
| 5    | TBD              | TBD             | PIN hash                            |
| 6    | TBD              | TBD             | PUK hash                            |
| 7    | TBD              | TBD             | Reserved, write=Never               |
| 8    | TBD              | TBD             | I/O Protection master key           |
| 9-15 | TBD              | TBD             | Reserved, write=Never               |
