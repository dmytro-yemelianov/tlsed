//! Public behavior and post-ownership storage checks over real rustls records.
//! Borrowed plaintext is never inspected while ClientConnection owns its loan.
use std::io::{Cursor, Write};
use std::sync::Arc;
use std::time::Duration;
use tls_client::{
    ClientBuffers, ClientConfig, ClientConnection, ClientError, ClientLimits,
    PLAINTEXT_BUFFER_SIZE, RECORD_BUFFER_SIZE, Status,
};
use tls_crypto::{CipherSuite, CryptoError, NamedGroup};
use tls_crypto_awslc::AwsLcProvider;
use tls_pki::{CertificateDer, ServerName, UnixTime};

struct Pair<'a> {
    client: ClientConnection<'a>,
    server: rustls::ServerConnection,
    inbound: Vec<u8>,
}
impl Pair<'_> {
    fn pump(&mut self) -> Result<(), ClientError> {
        let mut output = [0; RECORD_BUFFER_SIZE];
        for _ in 0..256 {
            while self.server.wants_write() {
                self.server.write_tls(&mut self.inbound).unwrap();
            }
            let progress = self.client.drive(&self.inbound, &mut output)?;
            self.inbound.drain(..progress.consumed);
            if progress.produced != 0 {
                assert_eq!(
                    self.server
                        .read_tls(&mut Cursor::new(&output[..progress.produced]))
                        .unwrap(),
                    progress.produced
                );
                self.server.process_new_packets().unwrap();
            }
            if progress.status == Status::ApplicationData
                || progress.status == Status::NeedInput
                    && self.inbound.is_empty()
                    && !self.server.wants_write()
            {
                return Ok(());
            }
        }
        panic!("read-wiping transport did not quiesce");
    }
    fn establish(&mut self) {
        self.pump().unwrap();
        assert!(self.client.is_established());
        assert!(!self.server.is_handshaking());
        assert_eq!(self.server.alpn_protocol(), Some(b"bench/1".as_slice()));
    }
    fn queue_server_plaintext(&mut self, payload: &[u8]) {
        self.server.writer().write_all(payload).unwrap();
        while self.server.wants_write() {
            self.server.write_tls(&mut self.inbound).unwrap();
        }
    }
    fn assert_unread_backpressure(&mut self) {
        assert!(
            !self.inbound.is_empty(),
            "queue the subsequent record before checking backpressure"
        );
        let before = self.inbound.clone();
        let mut output = [0x5a; 32];
        let progress = self.client.drive(&self.inbound, &mut output).unwrap();
        assert_eq!(progress.status, Status::ApplicationData);
        assert_eq!((progress.consumed, progress.produced), (0, 0));
        assert_eq!(self.inbound, before);
        assert_eq!(output, [0x5a; 32]);
    }
}

fn with_pair(f: impl FnOnce(&mut Pair<'_>)) {
    let limits = ClientLimits::default();
    let config = Arc::new(
        ClientConfig::new(
            &[CertificateDer::from(
                include_bytes!("../../tls-bench/fixtures/ca.der").as_slice(),
            )],
            b"bench/1",
            &[CipherSuite::Aes128GcmSha256],
            NamedGroup::X25519,
            limits,
        )
        .unwrap(),
    );
    // Extra loan capacity and nonzero initial contents make complete post-Drop
    // wiping observable without violating the live connection's mutable borrow.
    let mut record = vec![0xa1; RECORD_BUFFER_SIZE + 29];
    let mut handshake = vec![0xa2; limits.handshake_body + 4 + 23];
    let mut plaintext = vec![0xa3; PLAINTEXT_BUFFER_SIZE + 31];
    let mut outbound = vec![0xa4; RECORD_BUFFER_SIZE + 37];
    {
        let client = ClientConnection::new(
            AwsLcProvider,
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
        let mut provider = rustls::crypto::aws_lc_rs::default_provider();
        provider.cipher_suites =
            vec![rustls::crypto::aws_lc_rs::cipher_suite::TLS13_AES_128_GCM_SHA256];
        provider.kx_groups = vec![rustls::crypto::aws_lc_rs::kx_group::X25519];
        let mut config = rustls::ServerConfig::builder_with_provider(Arc::new(provider))
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
        f(&mut pair);
    } // All mutable loans are released here; checking them is safe.
    for (name, loan) in [
        ("record", record),
        ("handshake", handshake),
        ("plaintext", plaintext),
        ("outbound", outbound),
    ] {
        assert!(
            loan.iter().all(|byte| *byte == 0),
            "entire {name} loan, including unused capacity, must be wiped after Drop"
        );
    }
}
fn payload(length: usize, seed: u8) -> Vec<u8> {
    (0..length)
        .map(|i| ((i % 251) as u8).wrapping_add(seed))
        .collect()
}
fn partial_reads(pair: &mut Pair<'_>, expected: &[u8]) {
    let mut offset = 0;
    let sizes = [0, 1, 7, 63, 257, 4096, 8192];
    let mut step = 0;
    while offset < expected.len() {
        let capacity = sizes[step % sizes.len()];
        step += 1;
        let mut output = vec![0xb5; capacity];
        let count = pair.client.read_plaintext(&mut output).unwrap();
        assert_eq!(count, capacity.min(expected.len() - offset));
        assert_eq!(&output[..count], &expected[offset..offset + count]);
        assert!(output[count..].iter().all(|byte| *byte == 0xb5));
        offset += count;
    }
    assert_eq!(pair.client.read_plaintext(&mut [0; 8]).unwrap(), 0);
}

#[test]
fn partial_reads_zero_output_backpressure_and_large_to_short_records() {
    with_pair(|pair| {
        let mut output = [0xb5; 8];
        assert!(matches!(
            pair.client.read_plaintext(&mut output),
            Err(ClientError::NotEstablished)
        ));
        assert_eq!(output, [0xb5; 8]);
        pair.establish();
        for (length, short, seed) in [(64, 17, 1), (1024, 31, 23), (16384, 9, 97)] {
            let first = payload(length, seed);
            let next = payload(short, seed + 1);
            pair.queue_server_plaintext(&first);
            pair.pump().unwrap();
            assert_eq!(pair.client.read_plaintext(&mut []).unwrap(), 0);
            let mut first_byte = [0; 1];
            assert_eq!(pair.client.read_plaintext(&mut first_byte).unwrap(), 1);
            assert_eq!(first_byte[0], first[0]);
            pair.queue_server_plaintext(&next);
            pair.assert_unread_backpressure();
            assert_eq!(pair.client.read_plaintext(&mut []).unwrap(), 0);
            pair.assert_unread_backpressure();
            partial_reads(pair, &first[1..]);
            pair.pump().unwrap();
            partial_reads(pair, &next);
        }
    });
}

#[test]
fn unread_plaintext_is_wiped_when_live_connection_is_dropped() {
    for length in [64, 1024, 16384] {
        with_pair(|pair| {
            pair.establish();
            let bytes = payload(length, 61);
            pair.queue_server_plaintext(&bytes);
            pair.pump().unwrap();
            let mut prefix = [0; 7];
            assert_eq!(pair.client.read_plaintext(&mut prefix).unwrap(), 7);
            assert_eq!(&prefix, &bytes[..7]);
            // The remainder intentionally stays unread until connection Drop.
        });
    }
}

#[test]
fn unauthenticated_record_never_releases_plaintext_and_failed_loans_are_wiped() {
    with_pair(|pair| {
        pair.establish();
        pair.queue_server_plaintext(&payload(16384, 83));
        *pair.inbound.last_mut().unwrap() ^= 1;
        assert!(matches!(
            pair.pump(),
            Err(ClientError::Protected(
                tls_core::protected::ProtectedError::Crypto(CryptoError::AuthenticationFailed)
            ))
        ));
        let mut output = [0xb5; 16384];
        assert!(pair.client.read_plaintext(&mut output).is_err());
        assert_eq!(output, [0xb5; 16384]);
        assert!(!pair.client.is_established());
    });
}

#[test]
fn eof_with_unread_authenticated_plaintext_prevents_further_release() {
    with_pair(|pair| {
        pair.establish();
        let bytes = payload(16384, 41);
        pair.queue_server_plaintext(&bytes);
        pair.pump().unwrap();
        let mut prefix = [0; 7];
        assert_eq!(pair.client.read_plaintext(&mut prefix).unwrap(), 7);
        assert_eq!(&prefix, &bytes[..7]);
        assert!(matches!(
            pair.client.finish_input(),
            Err(ClientError::Truncated)
        ));
        let mut output = [0xb5; 32];
        assert!(pair.client.read_plaintext(&mut output).is_err());
        assert_eq!(output, [0xb5; 32]);
    });
}
