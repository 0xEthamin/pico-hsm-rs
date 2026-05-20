//! Global communication primitives between firmware tasks.
//!
//! The firmware uses three async tasks (USB run loop, dispatch loop,
//! animation loop) plus the touch and state tasks. They communicate
//! through three lock-free primitives, all backed by
//! [`CriticalSectionRawMutex`].
//!
//! # Why `CriticalSectionRawMutex` and not `NoopRawMutex`
//!
//! The embassy executor used here is single-threaded, so the "no-op" mutex
//! would be sufficient in terms of actual synchronisation. Unfortunately
//! `NoopRawMutex` is explicitly not `Sync` (so it cannot be placed in a
//! `static`), because it cannot guarantee correctness when shared across
//! threads. `CriticalSectionRawMutex` is `Sync` and pays only the cost of
//! a brief critical section (interrupts off) per lock, which is fine on
//! the RP2040.
//!
//! - [`EVENT_CHANNEL`] : fan-in queue of [`Event`]s. Every task that wants
//!   to drive a state transition (dispatch_loop on PIN verified, touch_task
//!   on press, timer_task on timeout) posts here. The state_task is the
//!   sole consumer.
//! - [`TOKEN_STATE`] : last-write-wins signal carrying the current
//!   [`TokenState`]. The state_task publishes; the animation_task reads.
//! - [`TOUCH_CONFIRMED`] : pulsed by the state_task each time the SM
//!   transitions into [`TokenState::Signing`]. The dispatch_loop awaits it
//!   to know its `Sign` request has been authorised by the user.

use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::channel::Channel;
use embassy_sync::signal::Signal;

use hsm_firmware_logic::{Event, TokenState};

/// Capacity of the event channel. 16 is generous: in practice the channel
/// holds 0 or 1 event most of the time. The producer tasks all use
/// non-blocking `try_send` so an unexpected backlog drops events rather
/// than stalling the firmware.
pub const EVENT_QUEUE_DEPTH: usize = 16;

/// Fan-in queue of state machine events.
pub static EVENT_CHANNEL: Channel<CriticalSectionRawMutex, Event, EVENT_QUEUE_DEPTH> =
    Channel::new();

/// Last-write-wins signal of the current operating state. The animation
/// task reads this on every frame; the state task republishes on every
/// transition.
pub static TOKEN_STATE: Signal<CriticalSectionRawMutex, TokenState> = Signal::new();

/// Pulsed by the state task when the SM enters [`TokenState::Signing`].
/// The dispatch loop blocks on it after firing
/// [`hsm_firmware_logic::Event::SignRequested`] so it can resume signing
/// only after the user has physically touched the button.
pub static TOUCH_CONFIRMED: Signal<CriticalSectionRawMutex, ()> = Signal::new();

/// Fire an event without blocking.
///
/// If the channel is somehow full, drops the event. State machine events
/// are advisory: the SM is conservative on unknown transitions, so a
/// dropped event at worst delays a transition by one cycle. We log it so
/// it does not go unnoticed.
pub fn post_event(event: Event)
{
    if EVENT_CHANNEL.try_send(event).is_err()
    {
        defmt::warn!("event channel full, dropping event");
    }
}