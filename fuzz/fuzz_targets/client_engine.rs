#![no_main]
//! Bounded real-provider traces, including authenticated rustls peers. The public
//! test certificate/key are fixtures, never production credentials. Fresh engine
//! connections exercise lifecycle behavior, not a proof of global nonce freshness.
use libfuzzer_sys::fuzz_target;
use rustls::pki_types::PrivatePkcs8KeyDer;
use std::io::{Cursor, Read, Write};
use std::sync::Arc;
use std::time::Duration;
use tls_client::{
    ClientBuffers, ClientConfig, ClientConnection, ClientError, ClientLimits,
    PLAINTEXT_BUFFER_SIZE, RECORD_BUFFER_SIZE, Status,
};
use tls_core::hello::{self, ClientHelloParams};
use tls_crypto::{CipherSuite, NamedGroup};
use tls_crypto_awslc::AwsLcProvider;
use tls_pki::{CertificateDer, ServerName, UnixTime};

const CA: &[u8] = include_bytes!("../../crates/tls-bench/fixtures/ca.der");
const CERT: &[u8] = include_bytes!("../../crates/tls-bench/fixtures/server.der");
const KEY: &[u8] = include_bytes!("../../crates/tls-bench/fixtures/server-key.der");

fn byte(data: &[u8], n: usize) -> u8 {
    data.get(n).copied().unwrap_or(0)
}

fn server(suite: CipherSuite, group: NamedGroup) -> rustls::ServerConnection {
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
    rustls::ServerConnection::new(Arc::new(config)).unwrap()
}

struct Transport {
    server: rustls::ServerConnection,
    inbound: Vec<u8>,
    outbound: Vec<u8>,
    fragment: usize,
}
impl Transport {
    fn emit(&mut self) {
        while self.server.wants_write() {
            self.server.write_tls(&mut self.inbound).unwrap();
            assert!(self.inbound.len() <= 65536);
        }
    }

    fn pump(
        &mut self,
        client: &mut ClientConnection<'_>,
        received: &mut Vec<u8>,
    ) -> Result<(), ClientError> {
        let mut output = [0; 128];
        let mut plaintext = [0; 31];
        for step in 0..12000 {
            self.emit();
            let n = self.inbound.len().min(self.fragment);
            // A zero-sized output must give backpressure without losing bytes.
            let capacity = if step % 17 == 0 { 0 } else { self.fragment };
            let progress = client.drive(&self.inbound[..n], &mut output[..capacity])?;
            assert!(progress.consumed <= n && progress.produced <= capacity);
            self.inbound.drain(..progress.consumed);
            self.outbound
                .extend_from_slice(&output[..progress.produced]);
            assert!(self.outbound.len() <= RECORD_BUFFER_SIZE);
            if !self.outbound.is_empty() {
                let read = self
                    .server
                    .read_tls(&mut Cursor::new(&self.outbound))
                    .unwrap();
                self.outbound.drain(..read);
                self.server.process_new_packets().unwrap();
            }
            if progress.status == Status::ApplicationData {
                assert!(client.is_established());
                let n = client.read_plaintext(&mut plaintext).unwrap();
                assert!(n > 0);
                received.extend_from_slice(&plaintext[..n]);
                assert!(received.len() <= 4096);
            }
            if self.inbound.is_empty()
                && self.outbound.is_empty()
                && !self.server.wants_write()
                && matches!(progress.status, Status::NeedInput | Status::Closed)
            {
                return Ok(());
            }
        }
        panic!("bounded clean transport failed to quiesce");
    }
}

fn codecs(data: &[u8]) {
    let _ = hello::parse_server_hello(data);
    let _ = hello::parse_encrypted_extensions(data);
    let _ = hello::parse_certificate_verify(data);
    let mut certificates = [&[][..]; 8];
    match hello::parse_certificate(data, &mut certificates[..usize::from(byte(data, 0) % 9)]) {
        Ok(count) => assert!(count <= certificates.len()),
        Err(_) => assert!(
            certificates
                .iter()
                .all(|certificate| certificate.is_empty())
        ),
    }
    let random = [byte(data, 1); 32];
    let params = ClientHelloParams {
        random: &random,
        session_id: &data[..data.len().min(32)],
        server_name: Some(if byte(data, 0) & 2 == 0 {
            b"localhost"
        } else {
            data
        }),
        alpn: b"bench/1",
        suites: &[0x1301, 0x1302, 0x1303],
        groups: &[0x001d, 0x0017],
        signatures: &[0x0403, 0x0804],
        key_share_group: 0x001d,
        key_share: &data[..data.len().min(256)],
        cookie: if byte(data, 0) & 4 == 0 {
            None
        } else {
            Some(&data[..data.len().min(64)])
        },
    };
    let mut full = [0xa5; 1024];
    let mut short = [0xa5; 1024];
    let capacity = usize::from(u16::from_be_bytes([byte(data, 2), byte(data, 3)])) % 1025;
    let expected = hello::encode_client_hello(&params, &mut full);
    let actual = hello::encode_client_hello(&params, &mut short[..capacity]);
    if let Ok(length) = actual {
        assert_eq!(expected, Ok(length));
        assert!(length <= capacity && length >= 4);
        assert_eq!(short[..length], full[..length]);
        assert_eq!(short[0], 1);
        assert_eq!(
            usize::from(short[1]) * 65536 + usize::from(short[2]) * 256 + usize::from(short[3]),
            length - 4
        );
    } else if expected.is_ok_and(|length| length <= capacity) {
        panic!("adequate encoder buffer rejected valid parameters");
    }
}

fn run(data: &[u8]) {
    codecs(data);
    let suite = [
        CipherSuite::Aes128GcmSha256,
        CipherSuite::Aes256GcmSha384,
        CipherSuite::Chacha20Poly1305Sha256,
    ][usize::from(byte(data, 1) % 3)];
    let initial = if byte(data, 2) & 1 == 0 {
        NamedGroup::X25519
    } else {
        NamedGroup::Secp256r1
    };
    let other = if initial == NamedGroup::X25519 {
        NamedGroup::Secp256r1
    } else {
        NamedGroup::X25519
    };
    let limits = ClientLimits {
        handshake_body: 4096,
        handshake_bytes: 32768,
        handshake_messages: 16,
        work_bytes: 1 + usize::from(byte(data, 3) % 64),
        send_records_per_key: 2 + u64::from(byte(data, 4) % 5),
        post_handshake_messages: 32,
        ..ClientLimits::default()
    };
    let config = Arc::new(
        ClientConfig::new(
            &[CertificateDer::from(CA)],
            b"bench/1",
            &[suite],
            initial,
            limits,
        )
        .unwrap(),
    );
    let mut record = vec![0xa5; RECORD_BUFFER_SIZE];
    let mut handshake = vec![0xa5; limits.handshake_body + 4];
    let mut plaintext = vec![0xa5; PLAINTEXT_BUFFER_SIZE];
    let mut outbound = vec![0xa5; RECORD_BUFFER_SIZE];
    // Caller-storage shortage is a local, explicit constructor error. Exercise
    // each buffer independently; do not infer a wipe contract for rejected loans.
    if byte(data, 0) & 16 != 0 {
        let sizes = [
            RECORD_BUFFER_SIZE,
            limits.handshake_body + 4,
            PLAINTEXT_BUFFER_SIZE,
            RECORD_BUFFER_SIZE,
        ];
        let which = usize::from(byte(data, 11) % 4);
        let mut sizes = sizes;
        sizes[which] -= 1 + usize::from(byte(data, 12));
        let mut a = vec![0xa5; sizes[0]];
        let mut b = vec![0xa5; sizes[1]];
        let mut c = vec![0xa5; sizes[2]];
        let mut d = vec![0xa5; sizes[3]];
        assert!(matches!(
            ClientConnection::new(
                AwsLcProvider,
                config.clone(),
                ServerName::try_from("localhost".to_owned()).unwrap(),
                UnixTime::since_unix_epoch(Duration::from_secs(1_792_022_400)),
                ClientBuffers {
                    record: &mut a,
                    handshake: &mut b,
                    plaintext: &mut c,
                    outbound: &mut d
                },
            ),
            Err(ClientError::BufferTooSmall)
        ));
    }
    {
        let buffers = ClientBuffers {
            record: &mut record,
            handshake: &mut handshake,
            plaintext: &mut plaintext,
            outbound: &mut outbound,
        };
        let mut client = ClientConnection::new(
            AwsLcProvider,
            config,
            ServerName::try_from("localhost".to_owned()).unwrap(),
            UnixTime::since_unix_epoch(Duration::from_secs(1_792_022_400)),
            buffers,
        )
        .unwrap();
        let mut output = [0; RECORD_BUFFER_SIZE];
        if byte(data, 0) & 1 == 0 {
            client.drain_output(&mut output);
            let mut offset = 0;
            for step in 0..512 {
                let end = data
                    .len()
                    .min(offset + 1 + usize::from(byte(data, step) % 128));
                let capacity = usize::from(byte(data, step + 1) % 65);
                match client.drive(&data[offset..end], &mut output[..capacity]) {
                    Ok(progress) => {
                        assert!(progress.consumed <= end - offset && progress.produced <= capacity);
                        offset += progress.consumed;
                        assert!(!client.is_established());
                        assert_ne!(progress.status, Status::ApplicationData);
                    }
                    Err(_) => break,
                }
                if offset == data.len() {
                    break;
                }
            }
            assert!(!client.is_established());
            assert!(client.read_plaintext(&mut output).is_err());
            let _ = client.finish_input();
            assert!(client.write_plaintext(b"unauthenticated").is_err());
        } else {
            let mut transport = Transport {
                server: server(
                    suite,
                    if byte(data, 2) & 2 == 0 {
                        initial
                    } else {
                        other
                    },
                ),
                inbound: Vec::new(),
                outbound: Vec::new(),
                fragment: 8 + usize::from(byte(data, 5) % 121),
            };
            let mut received = Vec::new();
            transport.pump(&mut client, &mut received).unwrap();
            assert!(client.is_established() && !transport.server.is_handshaking());
            assert_eq!(client.alpn(), Some(b"bench/1".as_slice()));
            assert_eq!(client.retried(), byte(data, 2) & 2 != 0);
            let payload = if data.is_empty() {
                b"payload".as_slice()
            } else {
                &data[..data.len().min(512)]
            };
            for round in 0..1 + usize::from(byte(data, 6) % 6) {
                if byte(data, 7 + round) & 1 != 0 {
                    transport.server.refresh_traffic_keys().unwrap();
                    transport.emit();
                    let progress = client.drive(&transport.inbound, &mut []).unwrap();
                    assert_eq!(progress.status, Status::NeedWork);
                    transport.inbound.drain(..progress.consumed);
                    // Receiving a complete but not yet dispatched control record
                    // must prevent a next ApplicationData record overtaking it.
                    assert!(matches!(
                        client.write_plaintext(payload),
                        Err(ClientError::InputPending)
                    ));
                    transport.pump(&mut client, &mut received).unwrap();
                }
                let mut written = 0;
                for _ in 0..4 {
                    written += client.write_plaintext(&payload[written..]).unwrap();
                    transport.pump(&mut client, &mut received).unwrap();
                    if written == payload.len() {
                        break;
                    }
                }
                assert_eq!(written, payload.len());
                let mut actual = vec![0; payload.len()];
                transport.server.reader().read_exact(&mut actual).unwrap();
                assert_eq!(actual, payload);
                transport.server.writer().write_all(payload).unwrap();
                transport.pump(&mut client, &mut received).unwrap();
                assert_eq!(received, payload);
                received.clear();
            }
            // Authentic-state ciphertext mutation, late CCS and truncated EOF
            // must never release the corresponding unauthenticated payload.
            if !byte(data, 8).is_multiple_of(4) {
                match byte(data, 8) % 4 {
                    1 => {
                        transport.server.writer().write_all(payload).unwrap();
                        transport.emit();
                        let index = usize::from(byte(data, 9)) % transport.inbound.len();
                        transport.inbound[index] ^= 1 << (byte(data, 10) % 8);
                    }
                    2 => transport.inbound.extend_from_slice(&[20, 3, 3, 0, 1, 1]),
                    _ => {
                        transport.server.writer().write_all(payload).unwrap();
                        transport.emit();
                        assert!(transport.inbound.pop().is_some());
                    }
                }
                let result = transport.pump(&mut client, &mut received);
                if result.is_ok() {
                    let _ = client.finish_input();
                }
                assert!(received.is_empty());
                assert!(!client.is_established());
                assert!(client.read_plaintext(&mut output).is_err());
                assert!(client.write_plaintext(payload).is_err());
            } else {
                transport.server.send_close_notify();
                transport.pump(&mut client, &mut received).unwrap();
                client.finish_input().unwrap();
            }
        }
    }
    assert!(
        record
            .iter()
            .chain(&handshake)
            .chain(&plaintext)
            .chain(&outbound)
            .all(|byte| *byte == 0)
    );
}

fuzz_target!(|input: &[u8]| {
    run(&input[..input.len().min(4096)]);
});
