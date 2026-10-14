//! Real authenticated in-memory TLS 1.3 interoperability; no timing comparison.
use rustls::pki_types::PrivatePkcs8KeyDer;
use std::io::{Cursor, Read, Write};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tls_client::{
    ClientBuffers, ClientConfig, ClientConnection, ClientError, ClientLimits,
    PLAINTEXT_BUFFER_SIZE, RECORD_BUFFER_SIZE, Status,
};
use tls_crypto::{AeadKey, CipherSuite, CryptoProvider, NamedGroup};
use tls_crypto_awslc::AwsLcProvider;
use tls_pki::{CertificateDer, ServerName, UnixTime};
use zeroize::Zeroize;

const CA: &[u8] = include_bytes!("../../tls-bench/fixtures/ca.der");
const CERT: &[u8] = include_bytes!("../../tls-bench/fixtures/server.der");
const KEY: &[u8] = include_bytes!("../../tls-bench/fixtures/server-key.der");
const NOW: u64 = 1_792_022_400; // 2026-10-15 00:00:00 UTC
const SUITES: [CipherSuite; 3] = [
    CipherSuite::Aes128GcmSha256,
    CipherSuite::Aes256GcmSha384,
    CipherSuite::Chacha20Poly1305Sha256,
];

#[derive(Default)]
struct Secrets(Mutex<Vec<u8>>, Mutex<Vec<u8>>);
impl std::fmt::Debug for Secrets {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Secrets([redacted])")
    }
}
impl Drop for Secrets {
    fn drop(&mut self) {
        self.0
            .get_mut()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .zeroize();
        self.1
            .get_mut()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .zeroize();
    }
}
impl rustls::KeyLog for Secrets {
    fn log(&self, label: &str, _: &[u8], secret: &[u8]) {
        let storage = match label {
            "SERVER_HANDSHAKE_TRAFFIC_SECRET" => &self.0,
            "SERVER_TRAFFIC_SECRET_0" => &self.1,
            _ => return,
        };
        {
            let mut stored = storage.lock().unwrap();
            stored.zeroize();
            stored.extend_from_slice(secret);
        }
    }
}
fn server(
    suite: CipherSuite,
    group: NamedGroup,
    secrets: Arc<Secrets>,
) -> rustls::ServerConnection {
    let mut provider = rustls::crypto::aws_lc_rs::default_provider();
    provider.cipher_suites = vec![match suite {
        CipherSuite::Aes128GcmSha256 => {
            rustls::crypto::aws_lc_rs::cipher_suite::TLS13_AES_128_GCM_SHA256
        }
        CipherSuite::Aes256GcmSha384 => {
            rustls::crypto::aws_lc_rs::cipher_suite::TLS13_AES_256_GCM_SHA384
        }
        CipherSuite::Chacha20Poly1305Sha256 => {
            rustls::crypto::aws_lc_rs::cipher_suite::TLS13_CHACHA20_POLY1305_SHA256
        }
    }];
    provider.kx_groups = vec![match group {
        NamedGroup::X25519 => rustls::crypto::aws_lc_rs::kx_group::X25519,
        NamedGroup::Secp256r1 => rustls::crypto::aws_lc_rs::kx_group::SECP256R1,
    }];
    let mut config = rustls::ServerConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![CertificateDer::from(CERT)],
            PrivatePkcs8KeyDer::from(KEY).into(),
        )
        .unwrap();
    config.send_tls13_tickets = 0;
    config.alpn_protocols = vec![b"bench/1".to_vec()];
    config.key_log = secrets;
    rustls::ServerConnection::new(Arc::new(config)).unwrap()
}

struct Pair<'a> {
    client: ClientConnection<'a>,
    server: rustls::ServerConnection,
    to_client: Vec<u8>,
    to_server: Vec<u8>,
    client_wire: Vec<u8>,
    fragment: usize,
}
impl Pair<'_> {
    fn pump(&mut self) -> Result<(), ClientError> {
        let mut output = vec![0; self.fragment];
        for _ in 0..200_000 {
            while self.server.wants_write() {
                self.server.write_tls(&mut self.to_client).unwrap();
            }
            let n = self.to_client.len().min(self.fragment);
            let progress = self.client.drive(&self.to_client[..n], &mut output)?;
            assert!(progress.consumed <= n && progress.produced <= output.len());
            self.to_client.drain(..progress.consumed);
            self.to_server
                .extend_from_slice(&output[..progress.produced]);
            self.client_wire
                .extend_from_slice(&output[..progress.produced]);
            if !self.to_server.is_empty() {
                let mut input = Cursor::new(&self.to_server);
                let n = self.server.read_tls(&mut input).unwrap();
                self.to_server.drain(..n);
                self.server.process_new_packets().unwrap();
            }
            if progress.status == Status::ApplicationData {
                return Ok(());
            }
            if self.to_client.is_empty()
                && self.to_server.is_empty()
                && !self.server.wants_write()
                && (progress.status == Status::NeedInput
                    || (progress.status == Status::Closed
                        && progress.consumed == 0
                        && progress.produced == 0))
            {
                return Ok(());
            }
        }
        panic!("bounded memory transport did not quiesce");
    }
    fn established(&mut self) {
        self.pump().unwrap();
        assert!(self.client.is_established());
        assert!(!self.server.is_handshaking());
        assert_eq!(self.server.alpn_protocol(), Some(b"bench/1".as_slice()));
        assert_eq!(
            self.server.protocol_version(),
            Some(rustls::ProtocolVersion::TLSv1_3)
        );
        self.client_wire.clear();
    }
    fn client_record_count(&self) -> usize {
        let mut offset = 0;
        let mut count = 0;
        while offset < self.client_wire.len() {
            assert!(offset + 5 <= self.client_wire.len());
            assert_eq!(self.client_wire[offset], 23);
            offset += 5 + usize::from(u16::from_be_bytes([
                self.client_wire[offset + 3],
                self.client_wire[offset + 4],
            ]));
            assert!(offset <= self.client_wire.len());
            count += 1;
        }
        count
    }
    fn bulk(&mut self, rounds: usize) {
        let payload: Vec<_> = (0..1021).map(|n| (n % 251) as u8).collect();
        for _ in 0..rounds {
            // A low send cap may first queue a KeyUpdate and accept no application bytes.
            let mut written = 0;
            while written < payload.len() {
                written += self.client.write_plaintext(&payload[written..]).unwrap();
                self.pump().unwrap();
            }
            let mut received = vec![0; payload.len()];
            self.server.reader().read_exact(&mut received).unwrap();
            assert_eq!(received, payload);
            self.server.writer().write_all(&payload).unwrap();
            self.pump().unwrap();
            let mut received = vec![0; payload.len()];
            let mut n = 0;
            while n < received.len() {
                let read = self.client.read_plaintext(&mut received[n..]).unwrap();
                assert!(read > 0);
                n += read;
            }
            assert_eq!(received, payload);
        }
    }
}
#[allow(clippy::too_many_arguments)] // Explicit independent endpoint/transport policies in tests.
fn with_pair(
    suite: CipherSuite,
    initial: NamedGroup,
    server_group: NamedGroup,
    fragment: usize,
    limits: ClientLimits,
    root: &[u8],
    name: &str,
    now: u64,
    f: impl FnOnce(&mut Pair<'_>, &Arc<Secrets>),
) {
    let config = Arc::new(
        ClientConfig::new(
            &[CertificateDer::from(root)],
            b"bench/1",
            &[suite],
            initial,
            limits,
        )
        .unwrap(),
    );
    let mut record = vec![0; RECORD_BUFFER_SIZE];
    let mut handshake = vec![0; config.limits().handshake_body + 4];
    let mut plaintext = vec![0; PLAINTEXT_BUFFER_SIZE];
    let mut outbound = vec![0; RECORD_BUFFER_SIZE];
    let client = ClientConnection::new(
        AwsLcProvider,
        config,
        ServerName::try_from(name.to_owned()).unwrap(),
        UnixTime::since_unix_epoch(Duration::from_secs(now)),
        ClientBuffers {
            record: &mut record,
            handshake: &mut handshake,
            plaintext: &mut plaintext,
            outbound: &mut outbound,
        },
    )
    .unwrap();
    let secrets = Arc::new(Secrets::default());
    let mut pair = Pair {
        client,
        server: server(suite, server_group, secrets.clone()),
        to_client: Vec::new(),
        to_server: Vec::new(),
        client_wire: Vec::new(),
        fragment,
    };
    f(&mut pair, &secrets);
    secrets.0.lock().unwrap().zeroize();
    secrets.1.lock().unwrap().zeroize();
}

#[test]
fn authenticated_suite_group_fragmentation_matrix() {
    for suite in SUITES {
        for group in [NamedGroup::X25519, NamedGroup::Secp256r1] {
            for fragment in [1, 7, 65536] {
                with_pair(
                    suite,
                    group,
                    group,
                    fragment,
                    ClientLimits::default(),
                    CA,
                    "localhost",
                    NOW,
                    |pair, _| {
                        assert!(!pair.client.is_established());
                        assert!(
                            pair.client
                                .read_plaintext(&mut [0; 8])
                                .map_or(true, |n| n == 0)
                        );
                        assert!(
                            pair.client
                                .write_plaintext(b"before authentication")
                                .is_err()
                        );
                        pair.established();
                        pair.bulk(3);
                    },
                );
            }
        }
    }
}
#[test]
fn hello_retry_request_and_key_updates() {
    for suite in SUITES {
        let limits = ClientLimits {
            send_records_per_key: 3,
            ..ClientLimits::default()
        };
        with_pair(
            suite,
            NamedGroup::X25519,
            NamedGroup::Secp256r1,
            7,
            limits,
            CA,
            "localhost",
            NOW,
            |pair, _| {
                pair.established();
                pair.bulk(8);
                let before_request = pair.client_record_count();
                assert!(
                    before_request > 8,
                    "cap-3 automatic KeyUpdates were not emitted"
                );
                pair.server.refresh_traffic_keys().unwrap();
                pair.pump().unwrap();
                assert!(
                    pair.client_record_count() > before_request,
                    "peer-requested KeyUpdate response was not emitted"
                );
                pair.bulk(8);
            },
        );
    }
}
#[test]
fn identity_root_and_expiry_fail_closed() {
    let wrong_root = include_bytes!("../../tls-pki/tests/fixtures/ku-root.der");
    for (root, name, now) in [
        (CA, "elsewhere.example", NOW),
        (wrong_root.as_slice(), "localhost", NOW),
        (CA, "localhost", NOW + 20 * 366 * 86400),
        (CA, "localhost", NOW - 86400 * 2),
    ] {
        with_pair(
            SUITES[0],
            NamedGroup::X25519,
            NamedGroup::X25519,
            7,
            ClientLimits::default(),
            root,
            name,
            now,
            |pair, _| {
                assert!(matches!(pair.pump(), Err(ClientError::Pki(_))));
                assert!(!pair.client.is_established());
                assert!(
                    pair.client
                        .read_plaintext(&mut [0; 8])
                        .map_or(true, |n| n == 0)
                );
                assert!(pair.client.write_plaintext(b"rejected").is_err());
                let mut alert = [0; 128];
                while pair.client.drain_output(&mut alert) != 0 {}
                assert!(pair.client.drive(&[], &mut alert).is_err());
            },
        );
    }
}
#[test]
fn close_notify_and_unclean_eof() {
    with_pair(
        SUITES[0],
        NamedGroup::X25519,
        NamedGroup::X25519,
        7,
        ClientLimits::default(),
        CA,
        "localhost",
        NOW,
        |pair, _| {
            pair.established();
            pair.bulk(1);
            pair.server.send_close_notify();
            pair.pump().unwrap();
            pair.client.close_notify().unwrap();
            pair.pump().unwrap();
            pair.client.finish_input().unwrap();
        },
    );
    with_pair(
        SUITES[0],
        NamedGroup::X25519,
        NamedGroup::X25519,
        7,
        ClientLimits::default(),
        CA,
        "localhost",
        NOW,
        |pair, _| {
            pair.established();
            assert!(matches!(
                pair.client.finish_input(),
                Err(ClientError::Truncated)
            ));
        },
    );
}

// Test-only secret capture deliberately does not write NSS logs or print secrets.
// Decrypt/re-encrypt a real rustls flight to distinguish CV/Finished verification
// failure from the record authentication failure that a ciphertext bitflip causes.
fn mutate_flight(wire: &mut [u8], secret: &[u8], target: u8) {
    let provider = AwsLcProvider;
    let mut key = [0; 16];
    let mut iv = [0; 12];
    tls_core::key_schedule::expand_label(
        &provider,
        SUITES[0].hash(),
        secret,
        b"key",
        &[],
        &mut key,
    )
    .unwrap();
    tls_core::key_schedule::expand_label(&provider, SUITES[0].hash(), secret, b"iv", &[], &mut iv)
        .unwrap();
    let key_owner = provider.aead_key(SUITES[0], &key).unwrap();
    key.zeroize();
    let mut offset = 0;
    let mut sequence = 0_u64;
    let mut mutated = false;
    while offset < wire.len() {
        let length = u16::from_be_bytes([wire[offset + 3], wire[offset + 4]]) as usize;
        let end = offset + 5 + length;
        if wire[offset] == 23 {
            if target == 0 {
                wire[end - 1] ^= 1;
                return;
            }
            let mut nonce = iv;
            for (dst, src) in nonce[4..].iter_mut().zip(sequence.to_be_bytes()) {
                *dst ^= src;
            }
            let header: [u8; 5] = wire[offset..offset + 5].try_into().unwrap();
            let body = &mut wire[offset + 5..end];
            let plain = key_owner.open_in_place(&nonce, &header, body).unwrap();
            let content_end = body[..plain].iter().rposition(|b| *b != 0).unwrap();
            assert_eq!(body[content_end], 22);
            let mut cursor = 0;
            while cursor < content_end {
                assert!(
                    cursor + 4 <= content_end,
                    "rustls fixture message fragmentation changed"
                );
                let size = ((body[cursor + 1] as usize) << 16)
                    | ((body[cursor + 2] as usize) << 8)
                    | body[cursor + 3] as usize;
                assert!(
                    cursor + 4 + size <= content_end,
                    "rustls fixture message fragmentation changed"
                );
                if body[cursor] == target {
                    body[cursor + 3 + size] ^= 1;
                    mutated = true;
                }
                cursor += 4 + size;
            }
            key_owner
                .seal_in_place(&nonce, &header, body, plain)
                .unwrap();
            sequence += 1;
        }
        offset = end;
    }
    iv.zeroize();
    assert!(
        mutated,
        "target handshake message absent from rustls flight"
    );
}
#[test]
fn authenticated_cv_finished_and_aead_mutations_are_rejected() {
    for target in [0, 15, 20] {
        with_pair(
            SUITES[0],
            NamedGroup::X25519,
            NamedGroup::X25519,
            65536,
            ClientLimits::default(),
            CA,
            "localhost",
            NOW,
            |pair, secrets| {
                // Drain ClientHello directly, then retain the whole first server flight.
                let mut output = vec![0; RECORD_BUFFER_SIZE];
                for _ in 0..32 {
                    let p = pair.client.drive(&[], &mut output).unwrap();
                    pair.to_server.extend_from_slice(&output[..p.produced]);
                    if matches!(p.status, Status::NeedInput) {
                        break;
                    }
                }
                pair.server
                    .read_tls(&mut Cursor::new(&pair.to_server))
                    .unwrap();
                pair.to_server.clear();
                pair.server.process_new_packets().unwrap();
                while pair.server.wants_write() {
                    pair.server.write_tls(&mut pair.to_client).unwrap();
                }
                mutate_flight(&mut pair.to_client, &secrets.0.lock().unwrap(), target);
                let error = pair.pump().unwrap_err();
                match target {
                    0 => assert!(matches!(
                        error,
                        ClientError::Protected(tls_core::protected::ProtectedError::Crypto(
                            tls_crypto::CryptoError::AuthenticationFailed
                        ))
                    )),
                    15 => assert!(matches!(error, ClientError::Pki(_))),
                    20 => assert!(matches!(
                        error,
                        ClientError::Schedule(_) | ClientError::Crypto(_)
                    )),
                    _ => unreachable!(),
                }
                assert!(!pair.client.is_established());
                assert!(
                    pair.client
                        .read_plaintext(&mut [0; 8])
                        .map_or(true, |n| n == 0)
                );
            },
        );
    }
}

fn server_application_keys(secret: &[u8]) -> (tls_crypto_awslc::AwsLcKey, [u8; 12]) {
    let provider = AwsLcProvider;
    let mut key = [0; 16];
    let mut iv = [0; 12];
    tls_core::key_schedule::expand_label(
        &provider,
        SUITES[0].hash(),
        secret,
        b"key",
        &[],
        &mut key,
    )
    .unwrap();
    tls_core::key_schedule::expand_label(&provider, SUITES[0].hash(), secret, b"iv", &[], &mut iv)
        .unwrap();
    let owner = provider.aead_key(SUITES[0], &key).unwrap();
    key.zeroize();
    (owner, iv)
}

#[test]
fn no_resumption_client_ignores_authenticated_ticket_and_continues_application_data() {
    for fragment in [1, 7, 65536] {
        with_pair(
            SUITES[0],
            NamedGroup::X25519,
            NamedGroup::X25519,
            fragment,
            ClientLimits::default(),
            CA,
            "localhost",
            NOW,
            |pair, secrets| {
                pair.established();
                let (key, mut iv) = server_application_keys(&secrets.1.lock().unwrap());
                // This client omits PSK modes, so rustls does not naturally issue a
                // ticket. Inject one authenticated under the actual session key.
                let mut ticket = Vec::new();
                ticket.extend_from_slice(&604800_u32.to_be_bytes());
                ticket.extend_from_slice(&0x12345678_u32.to_be_bytes());
                ticket.extend_from_slice(&[2, 0x42, 0x43]); // nonce vector
                ticket.extend_from_slice(&[0, 3, 1, 2, 3]); // nonempty ticket vector
                ticket.extend_from_slice(&[0, 6, 0xfe, 1, 0, 2, 4, 5]); // unknown extension
                let mut body = vec![4, 0, 0, u8::try_from(ticket.len()).unwrap()];
                body.extend_from_slice(&ticket);
                body.push(22); // inner handshake content type
                let plain_len = body.len();
                body.resize(plain_len + 16, 0);
                let cipher_len = u16::try_from(body.len()).unwrap().to_be_bytes();
                let header = [23, 3, 3, cipher_len[0], cipher_len[1]];
                key.seal_in_place(&iv, &header, &mut body, plain_len)
                    .unwrap();
                pair.to_client.extend_from_slice(&header);
                pair.to_client.extend_from_slice(&body);
                pair.pump().unwrap();
                assert!(pair.client.is_established());
                assert_eq!(pair.client.read_plaintext(&mut [0; 16]).unwrap(), 0);
                // Obtain a genuine rustls application record, then reseal its
                // original authenticated plaintext at seq1 after the injected NST.
                // This one-way test ends here: rustls's internal send counter did
                // not include the injected record and is not used afterward.
                let payload = b"application data after ignored ticket";
                pair.server.writer().write_all(payload).unwrap();
                let mut wire = Vec::new();
                while pair.server.wants_write() {
                    pair.server.write_tls(&mut wire).unwrap();
                }
                let header: [u8; 5] = wire[..5].try_into().unwrap();
                assert_eq!(
                    wire.len(),
                    5 + usize::from(u16::from_be_bytes([header[3], header[4]]))
                );
                let plain_len = key.open_in_place(&iv, &header, &mut wire[5..]).unwrap();
                let mut next_nonce = iv;
                next_nonce[11] ^= 1;
                key.seal_in_place(&next_nonce, &header, &mut wire[5..], plain_len)
                    .unwrap();
                pair.to_client.extend_from_slice(&wire);
                pair.pump().unwrap();
                let mut received = [0; 128];
                let n = pair.client.read_plaintext(&mut received).unwrap();
                assert_eq!(&received[..n], payload);
                assert!(pair.client.is_established());
                iv.zeroize();
                next_nonce.zeroize();
            },
        );
    }
}

#[test]
fn compatibility_ccs_after_finished_is_rejected() {
    with_pair(
        SUITES[0],
        NamedGroup::X25519,
        NamedGroup::X25519,
        7,
        ClientLimits::default(),
        CA,
        "localhost",
        NOW,
        |pair, _| {
            pair.established();
            pair.to_client.extend_from_slice(&[20, 3, 3, 0, 1, 1]);
            assert!(matches!(pair.pump(), Err(ClientError::UnexpectedMessage)));
            assert!(!pair.client.is_established());
            assert!(
                pair.client
                    .read_plaintext(&mut [0; 8])
                    .map_or(true, |n| n == 0)
            );
        },
    );
}

fn authenticated_server_record(secret: &[u8], sequence: u64, kind: u8, content: &[u8]) -> Vec<u8> {
    let (key, mut nonce) = server_application_keys(secret);
    for (dst, src) in nonce[4..].iter_mut().zip(sequence.to_be_bytes()) {
        *dst ^= src;
    }
    let plain_len = content.len() + 1;
    let mut body = content.to_vec();
    body.push(kind);
    body.resize(plain_len + 16, 0);
    let size = u16::try_from(body.len()).unwrap().to_be_bytes();
    let header = [23, 3, 3, size[0], size[1]];
    key.seal_in_place(&nonce, &header, &mut body, plain_len)
        .unwrap();
    nonce.zeroize();
    let mut wire = header.to_vec();
    wire.extend_from_slice(&body);
    wire
}

#[test]
fn pending_peer_key_update_blocks_application_until_response_is_processed() {
    for suite in SUITES {
        with_pair(
            suite,
            NamedGroup::X25519,
            NamedGroup::X25519,
            65536,
            ClientLimits::default(),
            CA,
            "localhost",
            NOW,
            |pair, _| {
                pair.established();
                pair.server.refresh_traffic_keys().unwrap();
                let mut wire = Vec::new();
                while pair.server.wants_write() {
                    pair.server.write_tls(&mut wire).unwrap();
                }
                assert_eq!(
                    wire.len(),
                    5 + usize::from(u16::from_be_bytes([wire[3], wire[4]]))
                );
                let progress = pair.client.drive(&wire, &mut [0; 128]).unwrap();
                assert_eq!(progress.consumed, wire.len());
                assert_eq!(progress.produced, 0);
                assert_eq!(progress.status, Status::NeedWork);
                assert!(matches!(
                    pair.client.write_plaintext(b"must wait for KU"),
                    Err(ClientError::InputPending)
                ));
                assert!(
                    pair.client.is_established(),
                    "recoverable input-pending error must not abort"
                );
                assert_eq!(pair.client_record_count(), 0);
                pair.pump().unwrap();
                assert_eq!(
                    pair.client_record_count(),
                    1,
                    "requested update response precedes application data"
                );
                pair.bulk(1);
            },
        );
    }
}

#[test]
fn authenticated_user_canceled_is_ignored_until_close_notify() {
    with_pair(
        SUITES[0],
        NamedGroup::X25519,
        NamedGroup::X25519,
        7,
        ClientLimits::default(),
        CA,
        "localhost",
        NOW,
        |pair, secrets| {
            pair.established();
            pair.to_client
                .extend_from_slice(&authenticated_server_record(
                    &secrets.1.lock().unwrap(),
                    0,
                    21,
                    &[1, 90],
                ));
            pair.pump().unwrap();
            assert!(pair.client.is_established());
            assert_eq!(
                pair.client_record_count(),
                0,
                "user_canceled must not cause a reciprocal alert"
            );
            assert_eq!(pair.client.read_plaintext(&mut [0; 8]).unwrap(), 0);
            pair.to_client
                .extend_from_slice(&authenticated_server_record(
                    &secrets.1.lock().unwrap(),
                    1,
                    21,
                    &[1, 0],
                ));
            pair.pump().unwrap();
            pair.client.finish_input().unwrap();
            assert_eq!(
                pair.client_record_count(),
                1,
                "close_notify is reciprocated once"
            );
        },
    );
}

#[test]
fn authenticated_fatal_peer_alert_aborts_without_reciprocal_alert() {
    with_pair(
        SUITES[0],
        NamedGroup::X25519,
        NamedGroup::X25519,
        7,
        ClientLimits::default(),
        CA,
        "localhost",
        NOW,
        |pair, secrets| {
            pair.established();
            pair.to_client
                .extend_from_slice(&authenticated_server_record(
                    &secrets.1.lock().unwrap(),
                    0,
                    21,
                    &[2, 40],
                ));
            assert!(matches!(pair.pump(), Err(ClientError::PeerAlert(40))));
            assert!(!pair.client.is_established());
            assert_eq!(pair.client_record_count(), 0);
            assert_eq!(
                pair.client.drain_output(&mut [0; 128]),
                0,
                "fatal peer alert must not be answered"
            );
            assert!(pair.client.write_plaintext(b"after fatal alert").is_err());
            assert!(
                pair.client
                    .read_plaintext(&mut [0; 8])
                    .map_or(true, |n| n == 0)
            );
        },
    );
}

fn first_server_flight(pair: &mut Pair<'_>) {
    let mut output = vec![0; RECORD_BUFFER_SIZE];
    for _ in 0..32 {
        let progress = pair.client.drive(&[], &mut output).unwrap();
        pair.to_server
            .extend_from_slice(&output[..progress.produced]);
        if progress.status == Status::NeedInput {
            break;
        }
    }
    let consumed = pair
        .server
        .read_tls(&mut Cursor::new(&pair.to_server))
        .unwrap();
    assert_eq!(consumed, pair.to_server.len());
    pair.to_server.clear();
    pair.server.process_new_packets().unwrap();
    while pair.server.wants_write() {
        pair.server.write_tls(&mut pair.to_client).unwrap();
    }
}

#[test]
fn fatal_peer_alert_during_fragmented_ticket_has_no_reciprocal_response() {
    with_pair(
        SUITES[0],
        NamedGroup::X25519,
        NamedGroup::X25519,
        7,
        ClientLimits::default(),
        CA,
        "localhost",
        NOW,
        |pair, secrets| {
            pair.established();
            pair.to_client
                .extend_from_slice(&authenticated_server_record(
                    &secrets.1.lock().unwrap(),
                    0,
                    22,
                    &[4, 0, 0, 4, 0],
                ));
            pair.pump().unwrap();
            assert!(pair.client.is_established());
            assert!(matches!(
                pair.client.write_plaintext(b"fragment pending"),
                Err(ClientError::InputPending)
            ));
            pair.to_client
                .extend_from_slice(&authenticated_server_record(
                    &secrets.1.lock().unwrap(),
                    1,
                    21,
                    &[2, 40],
                ));
            assert!(matches!(pair.pump(), Err(ClientError::PeerAlert(40))));
            assert!(!pair.client.is_established());
            assert_eq!(pair.client_record_count(), 0);
            assert_eq!(pair.client.drain_output(&mut [0; 128]), 0);
            assert!(
                pair.client
                    .read_plaintext(&mut [0; 8])
                    .map_or(true, |n| n == 0)
            );
        },
    );
}

#[test]
fn client_finished_final_byte_handoff_gates_establishment() {
    with_pair(
        SUITES[0],
        NamedGroup::X25519,
        NamedGroup::X25519,
        65536,
        ClientLimits::default(),
        CA,
        "localhost",
        NOW,
        |pair, _| {
            first_server_flight(pair);
            let mut finished_pending = false;
            for _ in 0..128 {
                let progress = pair.client.drive(&pair.to_client, &mut []).unwrap();
                assert_eq!(progress.produced, 0);
                pair.to_client.drain(..progress.consumed);
                if progress.status == Status::NeedOutput {
                    finished_pending = true;
                    break;
                }
            }
            assert!(finished_pending);
            assert!(pair.to_client.is_empty());
            assert!(!pair.client.is_established());
            assert!(matches!(
                pair.client.read_plaintext(&mut [0; 8]),
                Err(ClientError::NotEstablished)
            ));
            assert!(matches!(
                pair.client.write_plaintext(b"not yet"),
                Err(ClientError::NotEstablished)
            ));
            let progress = pair.client.drive(&[], &mut []).unwrap();
            assert_eq!(progress.produced, 0);
            assert_eq!(progress.status, Status::NeedOutput);
            let mut wire = vec![0; 5];
            assert_eq!(pair.client.drain_output(&mut wire), 5);
            assert_eq!(wire[0], 23);
            let cipher_len = usize::from(u16::from_be_bytes([wire[3], wire[4]]));
            assert!(cipher_len > 2);
            let mut first_cipher_byte = [0; 1];
            assert_eq!(pair.client.drain_output(&mut first_cipher_byte), 1);
            wire.extend_from_slice(&first_cipher_byte);
            assert!(!pair.client.is_established());
            assert!(matches!(
                pair.client.read_plaintext(&mut [0; 8]),
                Err(ClientError::NotEstablished)
            ));
            assert!(matches!(
                pair.client.write_plaintext(b"still not yet"),
                Err(ClientError::NotEstablished)
            ));
            let mut middle = vec![0; cipher_len - 2];
            assert_eq!(pair.client.drain_output(&mut middle), middle.len());
            wire.extend_from_slice(&middle);
            assert!(!pair.client.is_established());
            let mut final_byte = [0; 1];
            assert_eq!(pair.client.drain_output(&mut final_byte), 1);
            wire.extend_from_slice(&final_byte);
            assert!(pair.client.is_established());
            let consumed = pair.server.read_tls(&mut Cursor::new(&wire)).unwrap();
            assert_eq!(consumed, wire.len());
            pair.server.process_new_packets().unwrap();
            assert!(!pair.server.is_handshaking());
            pair.bulk(1);
        },
    );
}

#[test]
fn replayed_native_hello_retry_request_is_unexpected_message() {
    with_pair(
        SUITES[0],
        NamedGroup::X25519,
        NamedGroup::Secp256r1,
        65536,
        ClientLimits::default(),
        CA,
        "localhost",
        NOW,
        |pair, _| {
            first_server_flight(pair);
            let record_len =
                5 + usize::from(u16::from_be_bytes([pair.to_client[3], pair.to_client[4]]));
            let hrr = pair.to_client[..record_len].to_vec();
            assert_eq!(hrr[0], 22);
            assert_eq!(hrr[5], 2);
            pair.to_client.clear();
            let progress = pair.client.drive(&hrr, &mut []).unwrap();
            assert_eq!(progress.consumed, hrr.len());
            assert_eq!(progress.status, Status::NeedWork);
            let mut second_hello = vec![0; RECORD_BUFFER_SIZE];
            let mut hello_ready = false;
            for _ in 0..32 {
                let progress = pair.client.drive(&[], &mut []).unwrap();
                if progress.status == Status::NeedOutput {
                    hello_ready = true;
                    break;
                }
            }
            assert!(hello_ready);
            assert!(pair.client.drain_output(&mut second_hello) > 0);
            assert_eq!(pair.client.drain_output(&mut [0; 1]), 0);
            // Retain CH2 locally: replay HRR before the native peer receives it.
            pair.to_client.extend_from_slice(&hrr);
            assert!(matches!(pair.pump(), Err(ClientError::UnexpectedMessage)));
            assert!(!pair.client.is_established());
            assert!(
                pair.client
                    .read_plaintext(&mut [0; 8])
                    .map_or(true, |n| n == 0)
            );
            let mut alert = [0; 128];
            let n = pair.client.drain_output(&mut alert);
            assert_eq!(&alert[..n], &[21, 3, 3, 0, 2, 2, 10]);
        },
    );
}
