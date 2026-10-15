//! TLS 1.3 no-PSK key schedule orchestration over a maintained provider.
//! Caller transcript binding, authentic fresh shared secrets, release policy,
//! old-key KeyUpdate ordering and atomic record-key installation remain trusted
//! endpoint responsibilities. This module performs no handshake or identity check.
use crate::counter::MAX_SEND_EPOCH;
use core::marker::PhantomData;
use tls_crypto::{
    CipherSuite, CryptoError, CryptoProvider, HandshakeCryptoProvider, HashAlgorithm, NONCE_LEN,
};
use zeroize::Zeroize;

pub const MAX_SECRET_LEN: usize = 48;
pub const MAX_HKDF_LABEL: usize = 514;
pub const MAX_SHARED_SECRET: usize = 256;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KeyScheduleError {
    InvalidLabel,
    InvalidHashLength,
    InvalidSharedSecret,
    BufferTooSmall,
    UnsupportedSuite,
    EpochExhausted,
    Crypto(CryptoError),
}

/// Exact TLS HKDF label size; guards make both additions native-overflow safe.
pub fn hkdf_label_encoded_len(
    output_len: usize,
    label_len: usize,
    context_len: usize,
) -> Option<usize> {
    if output_len > 65535 || label_len == 0 || label_len > 249 || context_len > 255 {
        None
    } else {
        Some(10 + label_len + context_len)
    }
}

/// Encode TLS HkdfLabel into caller storage. On error erase supplied output;
/// success leaves its tail untouched. The six-byte TLS prefix is mandatory.
pub fn encode_hkdf_label(
    output_len: usize,
    label: &[u8],
    context: &[u8],
    output: &mut [u8],
) -> Result<usize, KeyScheduleError> {
    let Some(length) = hkdf_label_encoded_len(output_len, label.len(), context.len()) else {
        output.zeroize();
        return Err(KeyScheduleError::InvalidLabel);
    };
    if output.len() < length {
        output.zeroize();
        return Err(KeyScheduleError::BufferTooSmall);
    }
    output[..2].copy_from_slice(&(output_len as u16).to_be_bytes());
    output[2] = (6 + label.len()) as u8;
    output[3..9].copy_from_slice(b"tls13 ");
    output[9..9 + label.len()].copy_from_slice(label);
    output[9 + label.len()] = context.len() as u8;
    output[10 + label.len()..length].copy_from_slice(context);
    Ok(length)
}

/// HKDF-Expand-Label. PRKs have exactly the selected hash length; failed
/// preflight/provider calls erase the entire caller's secret output.
pub fn expand_label<P: CryptoProvider>(
    provider: &P,
    algorithm: HashAlgorithm,
    secret: &[u8],
    label: &[u8],
    context: &[u8],
    output: &mut [u8],
) -> Result<(), KeyScheduleError> {
    if secret.len() != algorithm.output_len() {
        output.zeroize();
        return Err(KeyScheduleError::InvalidHashLength);
    }
    let mut info = [0; MAX_HKDF_LABEL];
    let length = match encode_hkdf_label(output.len(), label, context, &mut info) {
        Ok(length) => length,
        Err(error) => {
            output.zeroize();
            return Err(error);
        }
    };
    let result = provider.hkdf_expand(algorithm, secret, &info[..length], output);
    info.zeroize();
    match result {
        Ok(()) => Ok(()),
        Err(error) => {
            output.zeroize();
            Err(KeyScheduleError::Crypto(error))
        }
    }
}

/// Owned secret with bounded storage; intentionally neither Debug nor Clone.
/// Explicit byte access can expose secrets: callers must not log or retain copies.
/// Drop erases this owner's entire buffer, not compiler/provider/caller copies.
///
/// ```compile_fail
/// use tls_core::key_schedule::BoundedSecret;
/// fn duplicate(secret: BoundedSecret) { let copy = secret.clone(); }
/// ```
/// ```compile_fail
/// use tls_core::key_schedule::BoundedSecret;
/// fn log(secret: BoundedSecret) { println!("{secret:?}"); }
/// ```
pub struct BoundedSecret {
    bytes: [u8; MAX_SECRET_LEN],
    len: usize,
}
impl BoundedSecret {
    fn zeroed(len: usize) -> Self {
        Self {
            bytes: [0; MAX_SECRET_LEN],
            len,
        }
    }
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
    fn as_mut_bytes(&mut self) -> &mut [u8] {
        &mut self.bytes[..self.len]
    }
}
impl Drop for BoundedSecret {
    fn drop(&mut self) {
        self.bytes.zeroize();
        self.len = 0;
    }
}

fn hash_empty<P: CryptoProvider>(
    provider: &P,
    algorithm: HashAlgorithm,
) -> Result<BoundedSecret, KeyScheduleError> {
    let mut hash = BoundedSecret::zeroed(algorithm.output_len());
    provider
        .hash(algorithm, b"", hash.as_mut_bytes())
        .map_err(KeyScheduleError::Crypto)?;
    Ok(hash)
}
fn extract<P: CryptoProvider>(
    provider: &P,
    algorithm: HashAlgorithm,
    salt: &[u8],
    input: &[u8],
) -> Result<BoundedSecret, KeyScheduleError> {
    let mut secret = BoundedSecret::zeroed(algorithm.output_len());
    provider
        .hkdf_extract(algorithm, salt, input, secret.as_mut_bytes())
        .map_err(KeyScheduleError::Crypto)?;
    Ok(secret)
}
fn derive<P: CryptoProvider>(
    provider: &P,
    algorithm: HashAlgorithm,
    secret: &[u8],
    label: &[u8],
    hash: &[u8],
) -> Result<BoundedSecret, KeyScheduleError> {
    if hash.len() != algorithm.output_len() {
        return Err(KeyScheduleError::InvalidHashLength);
    }
    let mut output = BoundedSecret::zeroed(algorithm.output_len());
    expand_label(
        provider,
        algorithm,
        secret,
        label,
        hash,
        output.as_mut_bytes(),
    )?;
    Ok(output)
}

pub struct Client;
pub struct Server;
pub struct Handshake;
pub struct Application;

/// Origin direction and key stage are static types; construction is private.
/// Neither Clone nor Debug. Raw transcript hashes must correspond to the exact
/// caller's authenticated message ordering, including HRR rewriting.
///
/// ```compile_fail
/// use tls_core::key_schedule::{Client, Server, Handshake, TrafficSecret};
/// fn server_secret(_: TrafficSecret<Server, Handshake>) {}
/// fn wrong_direction(secret: TrafficSecret<Client, Handshake>) { server_secret(secret); }
/// ```
/// ```compile_fail
/// use tls_core::key_schedule::{Client, Application, TrafficSecret};
/// use tls_crypto_awslc::AwsLcProvider;
/// fn wrong_stage(secret: TrafficSecret<Client, Application>) {
///     secret.sign_finished(&AwsLcProvider, &[0;32], &mut [0;32]);
/// }
/// ```
pub struct TrafficSecret<D, S> {
    secret: BoundedSecret,
    suite: CipherSuite,
    epoch: u64,
    marker: PhantomData<(D, S)>,
}
impl<D, S> TrafficSecret<D, S> {
    fn new(secret: BoundedSecret, suite: CipherSuite, epoch: u64) -> Self {
        Self {
            secret,
            suite,
            epoch,
            marker: PhantomData,
        }
    }
    pub const fn suite(&self) -> CipherSuite {
        self.suite
    }
    pub const fn epoch(&self) -> u64 {
        self.epoch
    }
    /// Derivation is deterministic, not evidence of a freshly installed key.
    /// Never reset a record counter by reimporting this same key/IV pair.
    pub fn key_material<P: CryptoProvider>(
        &self,
        provider: &P,
    ) -> Result<TrafficKeyMaterial<D, S>, KeyScheduleError> {
        let mut key = BoundedSecret::zeroed(self.suite.key_len());
        expand_label(
            provider,
            self.suite.hash(),
            self.secret.as_bytes(),
            b"key",
            b"",
            key.as_mut_bytes(),
        )?;
        let mut iv = BoundedSecret::zeroed(NONCE_LEN);
        expand_label(
            provider,
            self.suite.hash(),
            self.secret.as_bytes(),
            b"iv",
            b"",
            iv.as_mut_bytes(),
        )?;
        Ok(TrafficKeyMaterial {
            key,
            iv,
            suite: self.suite,
            epoch: self.epoch,
            marker: PhantomData,
        })
    }
}

/// Direction/stage-specific key and IV bytes, erased on drop. Explicit raw
/// access supports provider import; no automatic installation/reset is performed.
pub struct TrafficKeyMaterial<D, S> {
    key: BoundedSecret,
    iv: BoundedSecret,
    suite: CipherSuite,
    epoch: u64,
    marker: PhantomData<(D, S)>,
}
impl<D, S> TrafficKeyMaterial<D, S> {
    pub fn key_bytes(&self) -> &[u8] {
        self.key.as_bytes()
    }
    pub fn iv_bytes(&self) -> &[u8] {
        self.iv.as_bytes()
    }
    pub const fn suite(&self) -> CipherSuite {
        self.suite
    }
    pub const fn epoch(&self) -> u64 {
        self.epoch
    }
}

impl<D> TrafficSecret<D, Handshake> {
    fn finished_key<P: CryptoProvider>(
        &self,
        provider: &P,
    ) -> Result<BoundedSecret, KeyScheduleError> {
        let mut key = BoundedSecret::zeroed(self.suite.hash().output_len());
        expand_label(
            provider,
            self.suite.hash(),
            self.secret.as_bytes(),
            b"finished",
            b"",
            key.as_mut_bytes(),
        )?;
        Ok(key)
    }
    /// Generate Finished over the caller's pre-Finished transcript hash. Returned
    /// errors erase output. This does not advance or authenticate an endpoint.
    pub fn sign_finished<P: HandshakeCryptoProvider>(
        &self,
        provider: &P,
        transcript_hash: &[u8],
        output: &mut [u8],
    ) -> Result<(), KeyScheduleError> {
        let algorithm = self.suite.hash();
        if transcript_hash.len() != algorithm.output_len() || output.len() != algorithm.output_len()
        {
            output.zeroize();
            return Err(KeyScheduleError::InvalidHashLength);
        }
        let key = match self.finished_key(provider) {
            Ok(key) => key,
            Err(error) => {
                output.zeroize();
                return Err(error);
            }
        };
        match provider.hmac_sign(algorithm, key.as_bytes(), transcript_hash, output) {
            Ok(()) => Ok(()),
            Err(error) => {
                output.zeroize();
                Err(KeyScheduleError::Crypto(error))
            }
        }
    }
    /// Provider authentication API performs tag comparison. A real endpoint
    /// must terminate and retire its owners on failure; this borrowed low-level
    /// operation returns no authentication status or state advancement.
    pub fn verify_finished<P: HandshakeCryptoProvider>(
        &self,
        provider: &P,
        transcript_hash: &[u8],
        tag: &[u8],
    ) -> Result<(), KeyScheduleError> {
        let algorithm = self.suite.hash();
        if transcript_hash.len() != algorithm.output_len() || tag.len() != algorithm.output_len() {
            return Err(KeyScheduleError::InvalidHashLength);
        }
        let key = self.finished_key(provider)?;
        provider
            .hmac_verify(algorithm, key.as_bytes(), transcript_hash, tag)
            .map_err(KeyScheduleError::Crypto)
    }
}

/// No-PSK handshake derivation. Ephemeral shared-secret validity/freshness and
/// CH-through-SH transcript authenticity are caller/provider responsibilities.
pub struct HandshakeSecrets {
    handshake: BoundedSecret,
    suite: CipherSuite,
    pub client: TrafficSecret<Client, Handshake>,
    pub server: TrafficSecret<Server, Handshake>,
}
impl HandshakeSecrets {
    pub fn derive<P: CryptoProvider>(
        provider: &P,
        suite: CipherSuite,
        shared_secret: &[u8],
        hello_hash: &[u8],
    ) -> Result<Self, KeyScheduleError> {
        if !provider.supports(suite) {
            return Err(KeyScheduleError::UnsupportedSuite);
        }
        if shared_secret.is_empty() || shared_secret.len() > MAX_SHARED_SECRET {
            return Err(KeyScheduleError::InvalidSharedSecret);
        }
        let algorithm = suite.hash();
        if hello_hash.len() != algorithm.output_len() {
            return Err(KeyScheduleError::InvalidHashLength);
        }
        let zeros = BoundedSecret::zeroed(algorithm.output_len());
        let early = extract(provider, algorithm, zeros.as_bytes(), zeros.as_bytes())?;
        let empty_hash = hash_empty(provider, algorithm)?;
        let derived = derive(
            provider,
            algorithm,
            early.as_bytes(),
            b"derived",
            empty_hash.as_bytes(),
        )?;
        let handshake = extract(provider, algorithm, derived.as_bytes(), shared_secret)?;
        let client = TrafficSecret::new(
            derive(
                provider,
                algorithm,
                handshake.as_bytes(),
                b"c hs traffic",
                hello_hash,
            )?,
            suite,
            0,
        );
        let server = TrafficSecret::new(
            derive(
                provider,
                algorithm,
                handshake.as_bytes(),
                b"s hs traffic",
                hello_hash,
            )?,
            suite,
            0,
        );
        Ok(Self {
            handshake,
            suite,
            client,
            server,
        })
    }
    /// Consume the base handshake secret, deriving no-PSK main/application and
    /// exporter secrets at the server-Finished transcript boundary. Handshake
    /// traffic owners are returned for client Finished/protected handshake use;
    /// the endpoint must explicitly retire them once no longer needed.
    pub fn into_application<P: CryptoProvider>(
        self,
        provider: &P,
        server_finished_hash: &[u8],
    ) -> Result<ApplicationTransition, KeyScheduleError> {
        let algorithm = self.suite.hash();
        if server_finished_hash.len() != algorithm.output_len() {
            return Err(KeyScheduleError::InvalidHashLength);
        }
        let empty_hash = hash_empty(provider, algorithm)?;
        let derived = derive(
            provider,
            algorithm,
            self.handshake.as_bytes(),
            b"derived",
            empty_hash.as_bytes(),
        )?;
        let zeros = BoundedSecret::zeroed(algorithm.output_len());
        let main = extract(provider, algorithm, derived.as_bytes(), zeros.as_bytes())?;
        let client = TrafficSecret::new(
            derive(
                provider,
                algorithm,
                main.as_bytes(),
                b"c ap traffic",
                server_finished_hash,
            )?,
            self.suite,
            0,
        );
        let server = TrafficSecret::new(
            derive(
                provider,
                algorithm,
                main.as_bytes(),
                b"s ap traffic",
                server_finished_hash,
            )?,
            self.suite,
            0,
        );
        let exporter = derive(
            provider,
            algorithm,
            main.as_bytes(),
            b"exp master",
            server_finished_hash,
        )?;
        Ok(ApplicationTransition {
            client_handshake: self.client,
            server_handshake: self.server,
            application: ApplicationSecrets {
                client,
                server,
                exporter,
            },
        })
    }
}
pub struct ApplicationTransition {
    pub client_handshake: TrafficSecret<Client, Handshake>,
    pub server_handshake: TrafficSecret<Server, Handshake>,
    pub application: ApplicationSecrets,
}
pub struct ApplicationSecrets {
    pub client: TrafficSecret<Client, Application>,
    pub server: TrafficSecret<Server, Application>,
    /// Retained for future exporter orchestration; no exporter API is provided.
    pub exporter: BoundedSecret,
}

impl<D> TrafficSecret<D, Application> {
    pub fn into_sending(self) -> SendingTraffic<D> {
        SendingTraffic(self)
    }
    pub fn into_receiving(self) -> ReceivingTraffic<D> {
        ReceivingTraffic(self)
    }
    fn update<P: CryptoProvider>(
        self,
        provider: &P,
        maximum: u64,
    ) -> Result<Self, KeyScheduleError> {
        if self.epoch >= maximum {
            return Err(KeyScheduleError::EpochExhausted);
        }
        let Some(epoch) = self.epoch.checked_add(1) else {
            return Err(KeyScheduleError::EpochExhausted);
        };
        let mut secret = BoundedSecret::zeroed(self.suite.hash().output_len());
        expand_label(
            provider,
            self.suite.hash(),
            self.secret.as_bytes(),
            b"traffic upd",
            b"",
            secret.as_mut_bytes(),
        )?;
        Ok(Self::new(secret, self.suite, epoch))
    }
}
/// Application traffic owner selected for local sending; consumes the old secret
/// on update. Old-key KeyUpdate emission must precede record-key installation.
///
/// ```compile_fail
/// use tls_core::key_schedule::{Client, SendingTraffic};
/// use tls_crypto_awslc::AwsLcProvider;
/// fn reuse_after_update(secret: SendingTraffic<Client>) {
///     let updated = secret.update(&AwsLcProvider);
///     let old_epoch = secret.epoch();
/// }
/// ```
pub struct SendingTraffic<D>(TrafficSecret<D, Application>);
impl<D> SendingTraffic<D> {
    pub const fn epoch(&self) -> u64 {
        self.0.epoch
    }
    pub fn key_material<P: CryptoProvider>(
        &self,
        provider: &P,
    ) -> Result<TrafficKeyMaterial<D, Application>, KeyScheduleError> {
        self.0.key_material(provider)
    }
    pub fn update<P: CryptoProvider>(self, provider: &P) -> Result<Self, KeyScheduleError> {
        Ok(Self(self.0.update(provider, MAX_SEND_EPOCH)?))
    }
}
/// Receiving application owner does not enforce the sending epoch cap. Actual
/// authenticated old-key KeyUpdate acceptance is an endpoint responsibility.
pub struct ReceivingTraffic<D>(TrafficSecret<D, Application>);
impl<D> ReceivingTraffic<D> {
    pub const fn epoch(&self) -> u64 {
        self.0.epoch
    }
    pub fn key_material<P: CryptoProvider>(
        &self,
        provider: &P,
    ) -> Result<TrafficKeyMaterial<D, Application>, KeyScheduleError> {
        self.0.key_material(provider)
    }
    pub fn update<P: CryptoProvider>(self, provider: &P) -> Result<Self, KeyScheduleError> {
        Ok(Self(self.0.update(provider, u64::MAX)?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tls_crypto_awslc::AwsLcProvider;

    fn at_epoch(epoch: u64) -> TrafficSecret<Client, Application> {
        let mut secret = BoundedSecret::zeroed(32);
        secret.bytes[..32].fill(0x37); // isolated deterministic test fixture
        TrafficSecret::new(secret, CipherSuite::Aes128GcmSha256, epoch)
    }

    #[test]
    fn direction_epoch_caps_and_checked_overflow() {
        assert!(matches!(
            SendingTraffic(at_epoch(MAX_SEND_EPOCH)).update(&AwsLcProvider),
            Err(KeyScheduleError::EpochExhausted)
        ));
        let next = ReceivingTraffic(at_epoch(MAX_SEND_EPOCH))
            .update(&AwsLcProvider)
            .unwrap();
        assert_eq!(next.epoch(), MAX_SEND_EPOCH + 1);
        assert!(matches!(
            ReceivingTraffic(at_epoch(u64::MAX)).update(&AwsLcProvider),
            Err(KeyScheduleError::EpochExhausted)
        ));
        let last = ReceivingTraffic(at_epoch(u64::MAX - 1))
            .update(&AwsLcProvider)
            .unwrap();
        assert_eq!(last.epoch(), u64::MAX);
    }
}
