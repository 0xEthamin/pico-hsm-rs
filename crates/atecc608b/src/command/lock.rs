//! /!\ IRREVERSIBLE LOCK OPERATIONS - HANDLE WITH EXTREME CARE.
//!
//! The functions in this module mutate the chip's lock state. Once a zone
//! is locked, it cannot be unlocked. There is no factory reset. A misissued
//! `Lock` command turns the chip into permanent silicon.
//!
//! ## Project rules
//!
//! 1. **No automatic flow calls Lock.** Provisioning, initialization, tests,
//!    setup scripts: none of them call any function in this module
//!    implicitly. The user invokes Lock manually through a dedicated USB-HID
//!    command, with a magic word and a CRC of the expected state.
//!
//! 2. **Every function is marked `unsafe`.** Not because it violates Rust
//!    memory safety, but to force the caller to write `unsafe { ... }`. That
//!    syntactic barrier is the only Rust-level mechanism we have to flag
//!    operational danger.
//!
//! 3. **Every function takes an explicit confirmation parameter.** The caller
//!    must reproduce a precise value (CRC of the config zone, expected
//!    SlotLocked bitmap, etc.). A mismatch aborts before any byte is sent.
//!
//! ## Workflow expectation
//!
//! - Lock config zone: only after `WriteConfigZone` has been replayed,
//!   read back, and bit-compared against the expected blob. The CLI tool
//!   `hsm-host provision-lock-config-DANGEROUS --expected-crc <hex>` computes
//!   the CRC of what's currently on the chip and refuses to send the Lock if
//!   it doesn't match what the user typed on the command line.
//!
//! - Lock data zone: only after at least one round-trip of
//!   `GenKey(slot=0)` + `Sign(slot=0, challenge)` + `Verify(software)` has
//!   succeeded with the chip's config-locked state.
//!
//! No function bodies live in this file yet. When they are added, they will
//! be stubbed with `unimplemented!()` first, so that any accidental
//! invocation panics rather than silently bricking a chip.
