//! Streaming transcript hashing with bounded encoded-message input and guarded
//! HelloRetryRequest rewriting. Complete hello/message-body/FSM validation is
//! an endpoint responsibility; this component owns no network or message history.
use tls_crypto::{CryptoError, HashAlgorithm, HashContext};
use zeroize::Zeroize;

use crate::handshake::checked_handshake_total;

pub const HELLO_RETRY_REQUEST_RANDOM: [u8; 32] = [
    0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
    0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c,
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TranscriptError {
    InvalidLimit,
    InvalidMessage,
    UnexpectedStage,
    RetryRequiresRewrite,
    ResourceLimit,
    ProviderAlgorithm,
    Crypto(CryptoError),
    Frozen,
    Failed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Phase {
    BeforeClientHello,
    AwaitServerHello,
    AwaitRetryClientHello,
    AwaitFinalServerHello,
    Handshake,
    Frozen,
    Failed,
}

/// Algorithm-tagged, owned snapshot. It omits Debug/Clone and wipes its buffer on
/// Drop; it does not assert certificate/Finished authentication or a protocol stage.
pub struct TranscriptDigest {
    algorithm: HashAlgorithm,
    bytes: [u8; 48],
}

impl TranscriptDigest {
    pub const fn algorithm(&self) -> HashAlgorithm {
        self.algorithm
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.algorithm.output_len()]
    }
}

impl Drop for TranscriptDigest {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

/// Retains a provider hash context and fixed metadata, never transcript bytes.
/// Byte budget counts all input hashing work plus synthetic HRR bytes, rather
/// than pretending that rewriting erases the cost of processing ClientHello1.
pub struct Transcript<H: HashContext> {
    context: Option<H>,
    algorithm: HashAlgorithm,
    max_body: usize,
    max_bytes: u64,
    max_messages: u64,
    hashed_bytes: u64,
    messages: u64,
    retried: bool,
    phase: Phase,
}

impl<H: HashContext> Transcript<H> {
    pub fn new(
        mut context: H,
        max_body: usize,
        max_bytes: u64,
        max_messages: u64,
    ) -> Result<Self, TranscriptError> {
        if checked_handshake_total(max_body, max_body).is_none()
            || max_bytes < 4
            || max_messages == 0
        {
            return Err(TranscriptError::InvalidLimit);
        }
        let algorithm = context.algorithm();
        // A supplied context may already contain bytes. Start with an empty
        // transcript so its hash history agrees with the zeroed work counters.
        context.reset().map_err(TranscriptError::Crypto)?;
        if context.algorithm() != algorithm {
            return Err(TranscriptError::ProviderAlgorithm);
        }
        Ok(Self {
            context: Some(context),
            algorithm,
            max_body,
            max_bytes,
            max_messages,
            hashed_bytes: 0,
            messages: 0,
            retried: false,
            phase: Phase::BeforeClientHello,
        })
    }

    pub const fn algorithm(&self) -> HashAlgorithm {
        self.algorithm
    }
    pub const fn phase(&self) -> Phase {
        self.phase
    }
    pub const fn hashed_bytes(&self) -> u64 {
        self.hashed_bytes
    }
    pub const fn message_count(&self) -> u64 {
        self.messages
    }
    pub const fn retried(&self) -> bool {
        self.retried
    }

    fn fail<T>(&mut self, error: TranscriptError) -> Result<T, TranscriptError> {
        self.phase = Phase::Failed;
        self.context.take();
        Err(error)
    }

    fn active(&self) -> Result<(), TranscriptError> {
        match self.phase {
            Phase::Failed => Err(TranscriptError::Failed),
            Phase::Frozen => Err(TranscriptError::Frozen),
            _ => Ok(()),
        }
    }

    fn validate_encoded(&self, encoded: &[u8]) -> Result<u8, TranscriptError> {
        let Some(header) = encoded.get(..4) else {
            return Err(TranscriptError::InvalidMessage);
        };
        let body =
            (usize::from(header[1]) << 16) | (usize::from(header[2]) << 8) | usize::from(header[3]);
        if checked_handshake_total(body, self.max_body) != Some(encoded.len())
            || !matches!(header[0], 1 | 2 | 8 | 11 | 13 | 15 | 20)
        {
            return Err(TranscriptError::InvalidMessage);
        }
        Ok(header[0])
    }

    fn next_budget(&self, bytes: usize) -> Result<(u64, u64), TranscriptError> {
        let bytes = u64::try_from(bytes).map_err(|_| TranscriptError::ResourceLimit)?;
        let total = self
            .hashed_bytes
            .checked_add(bytes)
            .filter(|total| *total <= self.max_bytes)
            .ok_or(TranscriptError::ResourceLimit)?;
        let messages = self
            .messages
            .checked_add(1)
            .filter(|messages| *messages <= self.max_messages)
            .ok_or(TranscriptError::ResourceLimit)?;
        Ok((total, messages))
    }

    /// Append exactly one encoded handshake message, including its four-byte
    /// handshake header. Record headers and post-handshake messages are excluded.
    /// HelloRetryRequest must use `apply_hello_retry_request` instead.
    pub fn append(&mut self, encoded: &[u8]) -> Result<(), TranscriptError> {
        self.active()?;
        let kind = match self.validate_encoded(encoded) {
            Ok(kind) => kind,
            Err(error) => return self.fail(error),
        };
        if kind == 2 && encoded.get(6..38) == Some(HELLO_RETRY_REQUEST_RANDOM.as_slice()) {
            return self.fail(TranscriptError::RetryRequiresRewrite);
        }
        let next_phase = match (self.phase, kind) {
            (Phase::BeforeClientHello, 1) => Phase::AwaitServerHello,
            (Phase::AwaitServerHello, 2) | (Phase::AwaitFinalServerHello, 2) => Phase::Handshake,
            (Phase::AwaitRetryClientHello, 1) => Phase::AwaitFinalServerHello,
            (Phase::Handshake, 8 | 11 | 13 | 15 | 20) => Phase::Handshake,
            _ => return self.fail(TranscriptError::UnexpectedStage),
        };
        let (total, messages) = match self.next_budget(encoded.len()) {
            Ok(next) => next,
            Err(error) => return self.fail(error),
        };
        let Some(context) = self.context.as_mut() else {
            return self.fail(TranscriptError::Failed);
        };
        if context.algorithm() != self.algorithm {
            return self.fail(TranscriptError::ProviderAlgorithm);
        }
        if let Err(error) = context.update(encoded) {
            return self.fail(TranscriptError::Crypto(error));
        }
        self.hashed_bytes = total;
        self.messages = messages;
        self.phase = next_phase;
        Ok(())
    }

    pub fn snapshot(&mut self) -> Result<TranscriptDigest, TranscriptError> {
        self.active()?;
        let mut digest = TranscriptDigest {
            algorithm: self.algorithm,
            bytes: [0; 48],
        };
        let Some(context) = self.context.as_ref() else {
            return self.fail(TranscriptError::Failed);
        };
        if context.algorithm() != self.algorithm {
            return self.fail(TranscriptError::ProviderAlgorithm);
        }
        if let Err(error) = context.snapshot(&mut digest.bytes[..self.algorithm.output_len()]) {
            return self.fail(TranscriptError::Crypto(error));
        }
        Ok(digest)
    }

    /// Rewrite Hash(ClientHello1) as an encoded synthetic message_hash, then
    /// append a complete ServerHello with the HRR random sentinel. The endpoint
    /// must first validate its hello fields, cipher consistency and extensions.
    pub fn apply_hello_retry_request(&mut self, encoded: &[u8]) -> Result<(), TranscriptError> {
        self.active()?;
        if self.phase != Phase::AwaitServerHello || self.messages != 1 || self.retried {
            return self.fail(TranscriptError::UnexpectedStage);
        }
        if self.validate_encoded(encoded) != Ok(2)
            || encoded.get(6..38) != Some(HELLO_RETRY_REQUEST_RANDOM.as_slice())
        {
            return self.fail(TranscriptError::InvalidMessage);
        }
        let digest_len = self.algorithm.output_len();
        let work = encoded.len() + 4 + digest_len;
        let (total, messages) = match self.next_budget(work) {
            Ok(next) => next,
            Err(error) => return self.fail(error),
        };
        let first_hello_hash = self.snapshot()?;
        let Some(context) = self.context.as_mut() else {
            return self.fail(TranscriptError::Failed);
        };
        let result = (|| {
            context.reset()?;
            if context.algorithm() != self.algorithm {
                return Err(CryptoError::UnsupportedAlgorithm);
            }
            context.update(&[254, 0, 0, digest_len as u8])?;
            context.update(first_hello_hash.as_bytes())?;
            context.update(encoded)
        })();
        if let Err(error) = result {
            return self.fail(TranscriptError::Crypto(error));
        }
        self.hashed_bytes = total;
        self.messages = messages;
        self.retried = true;
        self.phase = Phase::AwaitRetryClientHello;
        Ok(())
    }

    /// Caller chooses the completed-handshake transcript boundary. This does
    /// not verify Finished. Freeze retires the provider context after snapshot.
    pub fn freeze(&mut self) -> Result<TranscriptDigest, TranscriptError> {
        if self.phase != Phase::Handshake {
            self.active()?;
            return self.fail(TranscriptError::UnexpectedStage);
        }
        let digest = self.snapshot()?;
        self.phase = Phase::Frozen;
        self.context.take();
        Ok(digest)
    }
}
