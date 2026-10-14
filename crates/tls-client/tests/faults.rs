//! Test-only provider failures over actual authenticated rustls connections.
use std::io::{Cursor, Read};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tls_client::{
    ClientBuffers, ClientConfig, ClientConnection, ClientError, ClientLimits,
    PLAINTEXT_BUFFER_SIZE, RECORD_BUFFER_SIZE, Status,
};
use tls_crypto::{
    AeadKey, CipherSuite, CryptoError, CryptoProvider, HandshakeCryptoProvider, HashAlgorithm,
    KeyExchangeProvider, NONCE_LEN, NamedGroup,
};
use tls_crypto_awslc::{AwsLcEphemeral, AwsLcHashContext, AwsLcKey, AwsLcProvider};
use tls_pki::{CertificateDer, ServerName, UnixTime};

#[derive(Default)]
struct Counts {
    imports: usize,
    created: usize,
    dropped: usize,
    fail_import: Option<usize>,
    fail_finished: bool,
}
#[derive(Clone, Default)]
struct CountingProvider(Arc<Mutex<Counts>>);
struct CountedKey {
    native: AwsLcKey,
    counts: Arc<Mutex<Counts>>,
}
impl Drop for CountedKey {
    fn drop(&mut self) {
        self.counts.lock().unwrap().dropped += 1;
    }
}
impl AeadKey for CountedKey {
    fn suite(&self) -> CipherSuite {
        self.native.suite()
    }
    fn seal_in_place(
        &self,
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        buffer: &mut [u8],
        length: usize,
    ) -> Result<usize, CryptoError> {
        self.native.seal_in_place(nonce, aad, buffer, length)
    }
    fn open_in_place(
        &self,
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        buffer: &mut [u8],
    ) -> Result<usize, CryptoError> {
        self.native.open_in_place(nonce, aad, buffer)
    }
}
impl CryptoProvider for CountingProvider {
    type Key = CountedKey;
    fn supports(&self, suite: CipherSuite) -> bool {
        AwsLcProvider.supports(suite)
    }
    fn aead_key(&self, suite: CipherSuite, bytes: &[u8]) -> Result<Self::Key, CryptoError> {
        let mut counts = self.0.lock().unwrap();
        counts.imports += 1;
        if counts.fail_import == Some(counts.imports) {
            return Err(CryptoError::BackendFailure);
        }
        let native = AwsLcProvider.aead_key(suite, bytes)?;
        counts.created += 1;
        Ok(CountedKey {
            native,
            counts: self.0.clone(),
        })
    }
    fn fill_random(&self, out: &mut [u8]) -> Result<(), CryptoError> {
        AwsLcProvider.fill_random(out)
    }
    fn hash(
        &self,
        algorithm: HashAlgorithm,
        input: &[u8],
        out: &mut [u8],
    ) -> Result<(), CryptoError> {
        AwsLcProvider.hash(algorithm, input, out)
    }
    fn hkdf_extract(
        &self,
        algorithm: HashAlgorithm,
        salt: &[u8],
        input: &[u8],
        out: &mut [u8],
    ) -> Result<(), CryptoError> {
        AwsLcProvider.hkdf_extract(algorithm, salt, input, out)
    }
    fn hkdf_expand(
        &self,
        algorithm: HashAlgorithm,
        key: &[u8],
        info: &[u8],
        out: &mut [u8],
    ) -> Result<(), CryptoError> {
        AwsLcProvider.hkdf_expand(algorithm, key, info, out)
    }
}
impl HandshakeCryptoProvider for CountingProvider {
    type Hasher = AwsLcHashContext;
    fn hash_context(&self, algorithm: HashAlgorithm) -> Result<Self::Hasher, CryptoError> {
        AwsLcProvider.hash_context(algorithm)
    }
    fn hmac_sign(
        &self,
        algorithm: HashAlgorithm,
        key: &[u8],
        input: &[u8],
        out: &mut [u8],
    ) -> Result<(), CryptoError> {
        AwsLcProvider.hmac_sign(algorithm, key, input, out)
    }
    fn hmac_verify(
        &self,
        algorithm: HashAlgorithm,
        key: &[u8],
        input: &[u8],
        tag: &[u8],
    ) -> Result<(), CryptoError> {
        if self.0.lock().unwrap().fail_finished {
            Err(CryptoError::AuthenticationFailed)
        } else {
            AwsLcProvider.hmac_verify(algorithm, key, input, tag)
        }
    }
}
impl KeyExchangeProvider for CountingProvider {
    type Ephemeral = AwsLcEphemeral;
    fn start_key_exchange(&self, group: NamedGroup) -> Result<Self::Ephemeral, CryptoError> {
        AwsLcProvider.start_key_exchange(group)
    }
}

struct Pair<'a> {
    client: ClientConnection<'a, CountingProvider>,
    server: rustls::ServerConnection,
    inbound: Vec<u8>,
}
impl Pair<'_> {
    fn pump(&mut self) -> Result<(), ClientError> {
        let mut output = [0; RECORD_BUFFER_SIZE];
        for _ in 0..128 {
            while self.server.wants_write() {
                self.server.write_tls(&mut self.inbound).unwrap();
            }
            let p = self.client.drive(&self.inbound, &mut output)?;
            self.inbound.drain(..p.consumed);
            if p.produced > 0 {
                assert_eq!(
                    self.server
                        .read_tls(&mut Cursor::new(&output[..p.produced]))
                        .unwrap(),
                    p.produced
                );
                self.server.process_new_packets().unwrap();
            }
            if p.status == Status::NeedInput
                && self.inbound.is_empty()
                && !self.server.wants_write()
            {
                return Ok(());
            }
        }
        panic!("fault-test transport did not quiesce");
    }
    fn assert_authenticated_fatal_alert(&mut self, expected: rustls::AlertDescription) {
        let mut alert = [0; RECORD_BUFFER_SIZE];
        let n = self.client.drain_output(&mut alert);
        assert!(n > 0);
        assert_eq!(self.client.drain_output(&mut [0; 1]), 0);
        assert_eq!(
            self.server.read_tls(&mut Cursor::new(&alert[..n])).unwrap(),
            n
        );
        // The native peer decrypts the expected alert, not an incomplete Finished,
        // KeyUpdate, nonce-shifted record or application record.
        assert_eq!(
            self.server.process_new_packets().unwrap_err(),
            rustls::Error::AlertReceived(expected)
        );
        assert!(self.server.is_handshaking() || self.client.read_plaintext(&mut [0; 8]).is_err());
    }
    fn block_at_client_finished(&mut self) {
        let mut output = [0; RECORD_BUFFER_SIZE];
        for _ in 0..32 {
            let p = self.client.drive(&[], &mut output).unwrap();
            if p.produced > 0 {
                self.server
                    .read_tls(&mut Cursor::new(&output[..p.produced]))
                    .unwrap();
                self.server.process_new_packets().unwrap();
            }
            if p.status == Status::NeedInput {
                break;
            }
        }
        while self.server.wants_write() {
            self.server.write_tls(&mut self.inbound).unwrap();
        }
        for _ in 0..128 {
            let p = self.client.drive(&self.inbound, &mut []).unwrap();
            self.inbound.drain(..p.consumed);
            if p.status == Status::NeedOutput {
                assert!(!self.client.is_established());
                return;
            }
        }
        panic!("ClientFinished was not queued");
    }
}
fn with_pair(
    fail_import: Option<usize>,
    fail_finished: bool,
    f: impl FnOnce(&mut Pair<'_>, &CountingProvider),
) {
    let provider = CountingProvider::default();
    {
        let mut counts = provider.0.lock().unwrap();
        counts.fail_import = fail_import;
        counts.fail_finished = fail_finished;
    }
    let ca = CertificateDer::from(include_bytes!("../../tls-bench/fixtures/ca.der").as_slice());
    let limits = ClientLimits {
        send_records_per_key: 3,
        ..ClientLimits::default()
    };
    let config = Arc::new(
        ClientConfig::new(
            &[ca],
            b"bench/1",
            &[CipherSuite::Aes128GcmSha256],
            NamedGroup::X25519,
            limits,
        )
        .unwrap(),
    );
    let mut record = vec![0; RECORD_BUFFER_SIZE];
    let mut handshake = vec![0; config.limits().handshake_body + 4];
    let mut plaintext = vec![0; PLAINTEXT_BUFFER_SIZE];
    let mut outbound = vec![0; RECORD_BUFFER_SIZE];
    let client = ClientConnection::new(
        provider.clone(),
        config,
        ServerName::try_from("localhost").unwrap(),
        UnixTime::since_unix_epoch(Duration::from_secs(1792022400)),
        ClientBuffers {
            record: &mut record,
            handshake: &mut handshake,
            plaintext: &mut plaintext,
            outbound: &mut outbound,
        },
    )
    .unwrap();
    let mut native = rustls::crypto::aws_lc_rs::default_provider();
    native.cipher_suites = vec![rustls::crypto::aws_lc_rs::cipher_suite::TLS13_AES_128_GCM_SHA256];
    native.kx_groups = vec![rustls::crypto::aws_lc_rs::kx_group::X25519];
    let mut config = rustls::ServerConfig::builder_with_provider(Arc::new(native))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![CertificateDer::from(
                include_bytes!("../../tls-bench/fixtures/server.der").as_slice(),
            )],
            rustls::pki_types::PrivatePkcs8KeyDer::from(
                include_bytes!("../../tls-bench/fixtures/server-key.der").as_slice(),
            )
            .into(),
        )
        .unwrap();
    config.send_tls13_tickets = 0;
    config.alpn_protocols = vec![b"bench/1".to_vec()];
    let mut pair = Pair {
        client,
        server: rustls::ServerConnection::new(Arc::new(config)).unwrap(),
        inbound: Vec::new(),
    };
    f(&mut pair, &provider);
}
fn assert_keys_retired(provider: &CountingProvider) {
    let counts = provider.0.lock().unwrap();
    assert!(counts.created > 0);
    assert_eq!(
        counts.created, counts.dropped,
        "all created key wrappers must Drop while connection remains alive"
    );
}
fn assert_failed(client: &mut ClientConnection<'_, CountingProvider>) {
    assert!(!client.is_established());
    assert!(client.write_plaintext(b"after failure").is_err());
    assert!(client.read_plaintext(&mut [0; 8]).is_err());
    assert!(matches!(
        client.drive(&[], &mut [0; 8]),
        Err(ClientError::Failed)
    ));
    assert!(matches!(
        client.drive(&[23, 3, 3, 0, 1, 0], &mut [0; 8]),
        Err(ClientError::Failed)
    ));
    assert_eq!(client.drain_output(&mut [0; 128]), 0);
}

#[test]
fn finished_verification_and_application_import_faults_are_atomic() {
    for (import, hmac, expected) in [
        (None, true, rustls::AlertDescription::DecryptError),
        (Some(3), false, rustls::AlertDescription::InternalError),
        (Some(4), false, rustls::AlertDescription::InternalError),
    ] {
        with_pair(import, hmac, |pair, provider| {
            let error = pair.pump().unwrap_err();
            if hmac {
                assert!(matches!(
                    error,
                    ClientError::Schedule(tls_core::key_schedule::KeyScheduleError::Crypto(
                        CryptoError::AuthenticationFailed
                    ))
                ));
            } else {
                assert!(matches!(
                    error,
                    ClientError::Crypto(CryptoError::BackendFailure)
                ));
            }
            {
                let counts = provider.0.lock().unwrap();
                assert_eq!(counts.imports, import.unwrap_or(2));
                assert_eq!(counts.created, if hmac { 2 } else { import.unwrap() - 1 });
            }
            assert!(!pair.client.is_established());
            assert!(pair.server.is_handshaking());
            assert_keys_retired(provider);
            pair.assert_authenticated_fatal_alert(expected);
            assert_failed(&mut pair.client);
        });
    }
}

#[test]
fn automatic_key_update_import_fault_preserves_old_record_sequence_for_alert() {
    with_pair(Some(5), false, |pair, provider| {
        pair.pump().unwrap();
        assert!(pair.client.is_established());
        assert!(!pair.server.is_handshaking());
        assert_eq!(provider.0.lock().unwrap().imports, 4);
        for _ in 0..2 {
            assert_eq!(pair.client.write_plaintext(b"accepted").unwrap(), 8);
            pair.pump().unwrap();
            let mut bytes = [0; 8];
            pair.server.reader().read_exact(&mut bytes).unwrap();
            assert_eq!(&bytes, b"accepted");
        }
        assert!(matches!(
            pair.client.write_plaintext(b"must not escape"),
            Err(ClientError::Crypto(CryptoError::BackendFailure))
        ));
        assert_eq!(provider.0.lock().unwrap().imports, 5);
        assert_eq!(provider.0.lock().unwrap().created, 4);
        assert_keys_retired(provider);
        pair.assert_authenticated_fatal_alert(rustls::AlertDescription::InternalError);
        assert_failed(&mut pair.client);
    });
}

#[test]
fn eof_discards_queued_and_partial_records_without_substitute_alert() {
    for established in [false, true] {
        for handed_off in [0, 6] {
            with_pair(None, false, |pair, provider| {
                if established {
                    pair.pump().unwrap();
                    assert_eq!(
                        pair.client.write_plaintext(b"pending application").unwrap(),
                        19
                    );
                } else {
                    pair.block_at_client_finished();
                }
                if handed_off != 0 {
                    assert_eq!(pair.client.drain_output(&mut [0; 6]), handed_off);
                }
                assert!(matches!(
                    pair.client.finish_input(),
                    Err(ClientError::Truncated)
                ));
                assert_eq!(provider.0.lock().unwrap().imports, 4);
                assert_eq!(provider.0.lock().unwrap().created, 4);
                assert_keys_retired(provider);
                assert_eq!(
                    pair.client.drain_output(&mut [0; RECORD_BUFFER_SIZE]),
                    0,
                    "discard unsent/partial record and send no substitute alert"
                );
                assert_failed(&mut pair.client);
                assert!(matches!(
                    pair.client.finish_input(),
                    Err(ClientError::Failed)
                ));
            });
        }
    }
}
