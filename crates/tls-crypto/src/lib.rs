//! Backend-neutral cryptographic operations. Implementations must use maintained
//! cryptography; this crate contains no cryptographic primitive implementation.
#![no_std]

pub const NONCE_LEN: usize = 12;
pub const TAG_LEN: usize = 16;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CipherSuite {
    Aes128GcmSha256,
    Aes256GcmSha384,
    Chacha20Poly1305Sha256,
}

impl CipherSuite {
    pub const fn key_len(self) -> usize {
        match self {
            Self::Aes128GcmSha256 => 16,
            Self::Aes256GcmSha384 | Self::Chacha20Poly1305Sha256 => 32,
        }
    }

    pub const fn hash(self) -> HashAlgorithm {
        match self {
            Self::Aes256GcmSha384 => HashAlgorithm::Sha384,
            Self::Aes128GcmSha256 | Self::Chacha20Poly1305Sha256 => HashAlgorithm::Sha256,
        }
    }

    /// Conservative sending budget below RFC 9846 section 5.5's full-size GCM
    /// limit. Receivers must not enforce this sender-specific cryptographic cap.
    pub const fn sending_record_limit(self) -> u64 {
        match self {
            Self::Aes128GcmSha256 | Self::Aes256GcmSha384 => 1 << 24,
            Self::Chacha20Poly1305Sha256 => u64::MAX,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HashAlgorithm {
    Sha256,
    Sha384,
}

impl HashAlgorithm {
    pub const fn output_len(self) -> usize {
        match self {
            Self::Sha256 => 32,
            Self::Sha384 => 48,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CryptoError {
    InvalidKey,
    InvalidLength,
    UnsupportedAlgorithm,
    AuthenticationFailed,
    BackendFailure,
    EntropyUnavailable,
}

/// A connection-owned traffic key; implementors must restrict secret logging
/// and ownership. Calls use caller storage and must not allocate per record.
/// Provider internals and erasure guarantees remain trusted and documented.
pub trait AeadKey {
    fn suite(&self) -> CipherSuite;

    /// Encrypt `buffer[..plaintext_len]`, append the authentication tag, and
    /// return `plaintext_len + TAG_LEN`. The buffer must have room for the tag.
    /// The caller reserves a nonce before this call and never rolls it back.
    fn seal_in_place(
        &self,
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        buffer: &mut [u8],
        plaintext_len: usize,
    ) -> Result<usize, CryptoError>;

    /// Authenticate/decrypt exactly this ciphertext and tag; return plaintext
    /// length. On EVERY error, wipe the supplied buffer before returning, so
    /// unauthenticated partial plaintext cannot escape through caller storage.
    fn open_in_place(
        &self,
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        buffer: &mut [u8],
    ) -> Result<usize, CryptoError>;
}

/// Provider calls outside the deterministic, formally modeled protocol subset.
/// Output buffers for hash/extract must have exactly the selected digest length.
pub trait CryptoProvider {
    type Key: AeadKey;

    fn supports(&self, suite: CipherSuite) -> bool;
    fn aead_key(&self, suite: CipherSuite, key: &[u8]) -> Result<Self::Key, CryptoError>;
    fn fill_random(&self, output: &mut [u8]) -> Result<(), CryptoError>;
    fn hash(
        &self,
        algorithm: HashAlgorithm,
        input: &[u8],
        output: &mut [u8],
    ) -> Result<(), CryptoError>;
    fn hkdf_extract(
        &self,
        algorithm: HashAlgorithm,
        salt: &[u8],
        input_key_material: &[u8],
        output: &mut [u8],
    ) -> Result<(), CryptoError>;
    fn hkdf_expand(
        &self,
        algorithm: HashAlgorithm,
        pseudorandom_key: &[u8],
        info: &[u8],
        output: &mut [u8],
    ) -> Result<(), CryptoError>;
}

/// Streaming handshake hashing; implementations must keep bounded state rather
/// than accumulating the transcript. Provider allocation/panic behavior is trusted.
pub trait HashContext {
    fn algorithm(&self) -> HashAlgorithm;
    fn update(&mut self, input: &[u8]) -> Result<(), CryptoError>;
    fn snapshot(&self, output: &mut [u8]) -> Result<(), CryptoError>;
    fn reset(&mut self) -> Result<(), CryptoError>;
}

/// Additional maintained operations for TLS transcript and Finished processing.
/// Verification must use the provider's authentication API, not a timing-sensitive
/// byte comparison in protocol code. Returned-error output wiping is required.
pub trait HandshakeCryptoProvider: CryptoProvider {
    type Hasher: HashContext;

    fn hash_context(&self, algorithm: HashAlgorithm) -> Result<Self::Hasher, CryptoError>;
    fn hmac_sign(
        &self,
        algorithm: HashAlgorithm,
        key: &[u8],
        input: &[u8],
        output: &mut [u8],
    ) -> Result<(), CryptoError>;
    fn hmac_verify(
        &self,
        algorithm: HashAlgorithm,
        key: &[u8],
        input: &[u8],
        tag: &[u8],
    ) -> Result<(), CryptoError>;
}

/// Initially supported classical TLS 1.3 key exchange groups.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NamedGroup {
    X25519,
    Secp256r1,
}
impl NamedGroup {
    pub const fn wire_code(self) -> u16 {
        match self {
            Self::X25519 => 0x001d,
            Self::Secp256r1 => 0x0017,
        }
    }
    pub const fn public_key_len(self) -> usize {
        match self {
            Self::X25519 => 32,
            Self::Secp256r1 => 65,
        }
    }
    pub const fn shared_secret_len(self) -> usize {
        32
    }
}

/// One connection-owned ephemeral private key, consumed on every completion
/// attempt, including preflight failures. No reuse across connections/retries.
/// Native key generation, validation and erasure remain provider assumptions.
pub trait EphemeralKeyExchange {
    fn group(&self) -> NamedGroup;
    fn public_key(&self) -> &[u8];
    /// Output must have exactly shared_secret_len bytes. On EVERY returned
    /// error wipe the entire supplied output, including invalid buffer lengths.
    fn complete(self, peer_share: &[u8], output: &mut [u8]) -> Result<(), CryptoError>;
}

pub trait KeyExchangeProvider: HandshakeCryptoProvider {
    type Ephemeral: EphemeralKeyExchange;
    /// Generate fresh secure ephemeral material for this one connection.
    fn start_key_exchange(&self, group: NamedGroup) -> Result<Self::Ephemeral, CryptoError>;
}
