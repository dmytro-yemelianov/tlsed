//! Abstract client authentication evidence model, not a TLS handshake FSM.
//!
//! Events assert successful external checks; this module does not perform them.
//! A real endpoint must create evidence through verified transcript/PKI/provider
//! operations, not accept these events directly from network or application code.
use crate::Error;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum State {
    Start = 0,
    HelloAccepted = 1,
    IdentityVerified = 2,
    SignatureVerified = 3,
    Established = 4,
    Failed = 5,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Event {
    HelloAccepted = 0,
    CertificateAndIdentityVerified = 1,
    CertificateVerifyVerified = 2,
    FinishedVerified = 3,
    Abort = 4,
    AeadFailed = 5,
}

/// Illegal events return error without changing state. Abort/AEAD failure are
/// terminal, even after establishment. No PSK, HRR, mTLS, or full message order
/// is modeled here.
pub fn transition(state: State, event: Event) -> Result<State, Error> {
    match (state, event) {
        (_, Event::Abort | Event::AeadFailed) => Ok(State::Failed),
        (State::Start, Event::HelloAccepted) => Ok(State::HelloAccepted),
        (State::HelloAccepted, Event::CertificateAndIdentityVerified) => {
            Ok(State::IdentityVerified)
        }
        (State::IdentityVerified, Event::CertificateVerifyVerified) => Ok(State::SignatureVerified),
        (State::SignatureVerified, Event::FinishedVerified) => Ok(State::Established),
        _ => Err(Error::UnexpectedEvent),
    }
}

pub fn may_release(state: State, aead_verified: bool) -> bool {
    state == State::Established && aead_verified
}

/// Mutable model driver; never exposes bytes or acts as a connection API.
#[derive(Debug)]
pub struct ClientAuthModel {
    state: State,
}

impl Default for ClientAuthModel {
    fn default() -> Self {
        Self {
            state: State::Start,
        }
    }
}

impl ClientAuthModel {
    pub const fn state(&self) -> State {
        self.state
    }
    pub fn apply(&mut self, event: Event) -> Result<(), Error> {
        self.state = transition(self.state, event)?;
        Ok(())
    }
    pub fn may_release(&self, aead_verified: bool) -> bool {
        may_release(self.state, aead_verified)
    }
}
