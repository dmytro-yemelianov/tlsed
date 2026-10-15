//! Exact-range secret erasure, including unaligned guarded loans in real TLS.
use super::*;
use std::io::{Cursor, Write};
use std::time::Duration;

const GUARD: u8 = 0xa5;

#[test]
fn secret_wipe_covers_requested_bytes_and_preserves_every_outer_guard() {
    let lengths: Vec<usize> = (0..=65)
        .chain([127, 128, 129, 1023, 1024, 1025, 16383, 16384, 16385, 16640])
        .collect();
    for offset in 0..32 {
        for &length in &lengths {
            // Fixed guard pad plus variable offset covers all residue classes
            // without assuming any allocator alignment or maximal aligned middle.
            let start = 16 + offset;
            let mut storage = vec![GUARD; start + length + 32];
            zeroize_secret(&mut storage[start..start + length]);
            assert!(storage[..start].iter().all(|byte| *byte == GUARD));
            assert!(storage[start..start + length].iter().all(|byte| *byte == 0));
            assert!(storage[start + length..].iter().all(|byte| *byte == GUARD));
        }
    }
}

fn native_server() -> rustls::ServerConnection {
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
    rustls::ServerConnection::new(Arc::new(config)).unwrap()
}
fn authenticate(client: &mut ClientConnection<'_>, server: &mut rustls::ServerConnection) {
    let mut incoming = Vec::new();
    let mut output = vec![0; RECORD_BUFFER_SIZE];
    for _ in 0..128 {
        while server.wants_write() {
            server.write_tls(&mut incoming).unwrap();
        }
        let progress = client.drive(&incoming, &mut output).unwrap();
        incoming.drain(..progress.consumed);
        if progress.produced != 0 {
            let mut cursor = Cursor::new(&output[..progress.produced]);
            while cursor.position() < progress.produced as u64 {
                assert!(server.read_tls(&mut cursor).unwrap() > 0);
                server.process_new_packets().unwrap();
            }
        }
        if client.is_established() && !server.is_handshaking() && incoming.is_empty() {
            assert_eq!(client.alpn(), Some(b"bench/1".as_slice()));
            return;
        }
    }
    panic!("guarded-loan native handshake did not establish");
}
fn guarded_parts(
    storage: &mut [u8],
    offset: usize,
    loan_length: usize,
) -> (&[u8], &mut [u8], &[u8]) {
    let (before, rest) = storage.split_at_mut(16 + offset);
    let (loan, after) = rest.split_at_mut(loan_length);
    (before, loan, after)
}
fn assert_guards(guards: &[&[u8]]) {
    for guard in guards {
        assert!(guard.iter().all(|byte| *byte == GUARD));
    }
}
fn inspect_plain(client: &ClientConnection<'_>, payload: &[u8], consumed: usize) {
    let loan = client.plaintext.as_deref().unwrap();
    assert!(loan[..consumed].iter().all(|byte| *byte == 0));
    assert_eq!(&loan[consumed..payload.len()], &payload[consumed..]);
    assert!(loan[payload.len()..].iter().all(|byte| *byte == 0));
}

#[test]
fn authenticated_partial_reads_at_varied_loan_offsets_preserve_guards_and_unread_data() {
    for offset in 0..16 {
        let config = Arc::new(
            ClientConfig::new(
                &[CertificateDer::from(
                    include_bytes!("../../tls-bench/fixtures/ca.der").as_slice(),
                )],
                b"bench/1",
                &[CipherSuite::Aes128GcmSha256],
                NamedGroup::X25519,
                ClientLimits::default(),
            )
            .unwrap(),
        );
        let record_length = RECORD_BUFFER_SIZE + 19;
        let handshake_length = config.limits().handshake_body + 4 + 13;
        let plain_length = PLAINTEXT_BUFFER_SIZE + 257;
        let outbound_length = RECORD_BUFFER_SIZE + 23;
        let mut record = vec![GUARD; 16 + offset + record_length + 32];
        let mut handshake = vec![GUARD; 16 + offset + handshake_length + 32];
        let mut plaintext = vec![GUARD; 16 + offset + plain_length + 32];
        let mut outbound = vec![GUARD; 16 + offset + outbound_length + 32];
        let (record_before, record_loan, record_after) =
            guarded_parts(&mut record, offset, record_length);
        let (handshake_before, handshake_loan, handshake_after) =
            guarded_parts(&mut handshake, offset, handshake_length);
        let (plain_before, plain_loan, plain_after) =
            guarded_parts(&mut plaintext, offset, plain_length);
        let (out_before, out_loan, out_after) =
            guarded_parts(&mut outbound, offset, outbound_length);
        let guards = [
            record_before,
            record_after,
            handshake_before,
            handshake_after,
            plain_before,
            plain_after,
            out_before,
            out_after,
        ];
        let mut client = ClientConnection::new(
            AwsLcProvider,
            config,
            ServerName::try_from("localhost").unwrap(),
            UnixTime::since_unix_epoch(Duration::from_secs(1_792_022_400)),
            ClientBuffers {
                record: record_loan,
                handshake: handshake_loan,
                plaintext: plain_loan,
                outbound: out_loan,
            },
        )
        .unwrap();
        assert_guards(&guards);
        assert!(
            client
                .record
                .as_deref()
                .unwrap()
                .iter()
                .all(|byte| *byte == 0)
        );
        assert!(
            client
                .plaintext
                .as_deref()
                .unwrap()
                .iter()
                .all(|byte| *byte == 0)
        );
        let mut server = native_server();
        authenticate(&mut client, &mut server);
        assert_guards(&guards);
        for size in [16384, 17, 1024, 3, 64] {
            let payload: Vec<_> = (0..size).map(|i| (i % 251 + 1) as u8).collect();
            server.writer().write_all(&payload).unwrap();
            let mut wire = Vec::new();
            while server.wants_write() {
                server.write_tls(&mut wire).unwrap();
            }
            let progress = client.drive(&wire, &mut []).unwrap();
            assert_eq!(progress.consumed, wire.len());
            assert_eq!(progress.status, Status::ApplicationData);
            inspect_plain(&client, &payload, 0);
            assert_guards(&guards);
            let mut consumed = 0;
            for capacity in [0, 1, 3, 0, 17, 257, 512, 16384] {
                if consumed == size {
                    break;
                }
                let mut destination = vec![0xe1; capacity];
                let count = client.read_plaintext(&mut destination).unwrap();
                assert_eq!(count, capacity.min(size - consumed));
                assert_eq!(&destination[..count], &payload[consumed..consumed + count]);
                assert!(destination[count..].iter().all(|byte| *byte == 0xe1));
                consumed += count;
                inspect_plain(&client, &payload, consumed);
                assert_guards(&guards);
                if consumed < size {
                    let blocked = client.drive(&[], &mut []).unwrap();
                    assert_eq!(blocked.status, Status::ApplicationData);
                    assert_eq!((blocked.consumed, blocked.produced), (0, 0));
                }
            }
            assert_eq!(consumed, size);
            assert!(
                client
                    .plaintext
                    .as_deref()
                    .unwrap()
                    .iter()
                    .all(|byte| *byte == 0)
            );
        }
        drop(client);
        assert_guards(&guards);
        for (storage, length) in [
            (&record, record_length),
            (&handshake, handshake_length),
            (&plaintext, plain_length),
            (&outbound, outbound_length),
        ] {
            let start = 16 + offset;
            assert!(storage[..start].iter().all(|byte| *byte == GUARD));
            assert!(storage[start..start + length].iter().all(|byte| *byte == 0));
            assert!(storage[start + length..].iter().all(|byte| *byte == GUARD));
        }
    }
}
