//! Experimental TLS 1.3 foundations, not a TLS endpoint or secure channel.
//!
//! This library implements bounded wire/handshake framing, segmentation, counter
//! bookkeeping, an abstract authentication model, and protected records through
//! a maintained cryptographic provider. It does not perform a complete handshake
//! or certificate verification and owns no transport. A linked arithmetic proof
//! covers the functions named in the proof ledger under translation trust.
//! Record authentication does not establish peer identity. No external security
//! audit is claimed; an actual endpoint must enforce the authentication policy.
#![no_std]

pub mod auth;
pub mod client_policy;
pub mod counter;
pub mod framing;
pub mod handshake;
pub mod hello;
pub mod key_schedule;
pub mod protected;
pub mod schedule;
pub mod transcript;
pub mod wire;

/// Errors are explicit; malformed input never produces a successful frame.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    InvalidLimit,
    RecordOverflow,
    UnexpectedType,
    InvalidVersion,
    InvalidLength,
    BufferTooSmall,
    Failed,
    UnexpectedEvent,
    Exhausted,
    IncompleteRecord,
}
