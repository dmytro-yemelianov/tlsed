//! Wire-buffer clearing boundaries, observed inside actual authenticated peers.
use super::*;
use std::io::{Cursor, Read, Write};
use std::time::Duration;

const CA: &[u8] = include_bytes!("../../tls-bench/fixtures/ca.der");
const CERT: &[u8] = include_bytes!("../../tls-bench/fixtures/server.der");
const KEY: &[u8] = include_bytes!("../../tls-bench/fixtures/server-key.der");
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
            vec![CertificateDer::from(CERT)],
            rustls::pki_types::PrivatePkcs8KeyDer::from(KEY).into(),
        )
        .unwrap();
    config.send_tls13_tickets = 0;
    config.alpn_protocols = vec![b"bench/1".to_vec()];
    rustls::ServerConnection::new(Arc::new(config)).unwrap()
}
fn with_client(f: impl FnOnce(&mut ClientConnection<'_>, &mut rustls::ServerConnection)) {
    let config = Arc::new(
        ClientConfig::new(
            &[CertificateDer::from(CA)],
            b"bench/1",
            &[CipherSuite::Aes128GcmSha256],
            NamedGroup::X25519,
            ClientLimits::default(),
        )
        .unwrap(),
    );
    let mut record = vec![0xa5; RECORD_BUFFER_SIZE + 43];
    let mut handshake = vec![0xa6; config.limits().handshake_body + 4 + 29];
    let mut plaintext = vec![0xa7; PLAINTEXT_BUFFER_SIZE + 53];
    let mut outbound = vec![0xa8; RECORD_BUFFER_SIZE + 61];
    {
        let mut client = ClientConnection::new(
            AwsLcProvider,
            config,
            ServerName::try_from("localhost").unwrap(),
            UnixTime::since_unix_epoch(Duration::from_secs(1_792_022_400)),
            ClientBuffers {
                record: &mut record,
                handshake: &mut handshake,
                plaintext: &mut plaintext,
                outbound: &mut outbound,
            },
        )
        .unwrap();
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
        assert!(
            client.outbound.as_deref().unwrap()[client.out_len..]
                .iter()
                .all(|byte| *byte == 0)
        );
        let mut server = native_server();
        f(&mut client, &mut server);
    }
    for (name, loan) in [
        ("record", record),
        ("handshake", handshake),
        ("plaintext", plaintext),
        ("outbound", outbound),
    ] {
        assert!(
            loan.iter().all(|byte| *byte == 0),
            "entire {name} loan must be zero after Drop, including extra capacity"
        );
    }
}
fn feed_native(server: &mut rustls::ServerConnection, wire: &[u8]) {
    let mut cursor = Cursor::new(wire);
    while cursor.position() < wire.len() as u64 {
        assert!(server.read_tls(&mut cursor).unwrap() > 0);
        server.process_new_packets().unwrap();
    }
}
fn checked_partial_drain(client: &mut ClientConnection<'_>) -> Vec<u8> {
    let wire_len = client.out_len;
    assert!(wire_len > 0);
    let expected = client.outbound.as_deref().unwrap()[..wire_len].to_vec();
    let finished = matches!(client.outgoing, Some(Outgoing::ClientFinished));
    let mut handed = Vec::new();
    let chunks = [0, 1, 7, 0, 64, 257, 4096, 8192];
    let mut step = 0;
    while handed.len() < wire_len {
        let requested = chunks[step % chunks.len()].min(wire_len - handed.len());
        step += 1;
        let mut output = vec![0xe1; requested];
        let count = client.drain_output(&mut output);
        assert_eq!(count, requested);
        handed.extend_from_slice(&output[..count]);
        let loan = client.outbound.as_deref().unwrap();
        assert!(loan[..handed.len()].iter().all(|byte| *byte == 0));
        assert_eq!(&loan[handed.len()..wire_len], &expected[handed.len()..]);
        assert!(loan[wire_len..].iter().all(|byte| *byte == 0));
        if handed.len() < wire_len {
            assert_eq!(client.out_offset, handed.len());
            assert_eq!(client.out_len, wire_len);
            if finished {
                assert!(!client.is_established());
                assert!(matches!(
                    client.read_plaintext(&mut [0; 1]),
                    Err(ClientError::NotEstablished)
                ));
                assert!(matches!(
                    client.write_plaintext(b"not yet"),
                    Err(ClientError::NotEstablished)
                ));
            }
        }
    }
    assert_eq!(handed, expected);
    assert_eq!(client.out_len, 0);
    assert_eq!(client.out_offset, 0);
    assert!(
        client
            .outbound
            .as_deref()
            .unwrap()
            .iter()
            .all(|byte| *byte == 0)
    );
    if finished {
        assert!(client.is_established());
    }
    assert_eq!(client.drain_output(&mut [0; 1]), 0);
    handed
}
fn authenticate(client: &mut ClientConnection<'_>, server: &mut rustls::ServerConnection) {
    // Exercise public ClientHello drain clearing as well as encrypted Finished.
    let hello = checked_partial_drain(client);
    feed_native(server, &hello);
    let mut incoming = Vec::new();
    while server.wants_write() {
        server.write_tls(&mut incoming).unwrap();
    }
    let mut queued_finished = false;
    for _ in 0..128 {
        let progress = client.drive(&incoming, &mut []).unwrap();
        incoming.drain(..progress.consumed);
        assert_eq!(progress.produced, 0);
        if progress.status == Status::NeedOutput {
            queued_finished = true;
            break;
        }
    }
    assert!(queued_finished);
    assert!(incoming.is_empty());
    assert!(!client.is_established());
    let finished = checked_partial_drain(client);
    feed_native(server, &finished);
    assert!(!server.is_handshaking());
    assert_eq!(client.alpn(), Some(b"bench/1".as_slice()));
}
fn payload(size: usize, seed: u8) -> Vec<u8> {
    (0..size)
        .map(|i| ((i % 251) as u8).wrapping_add(seed))
        .collect()
}
fn application_wire(server: &mut rustls::ServerConnection, payload: &[u8]) -> Vec<u8> {
    server.writer().write_all(payload).unwrap();
    let mut wire = Vec::new();
    while server.wants_write() {
        server.write_tls(&mut wire).unwrap();
    }
    wire
}

#[test]
fn partial_wire_drains_clear_only_handed_bytes_and_peer_authenticates_large_then_small() {
    with_client(|client, server| {
        authenticate(client, server);
        for size in [16384, 17, 1024, 3, 64] {
            let bytes = payload(size, 37);
            assert_eq!(client.write_plaintext(&bytes).unwrap(), bytes.len());
            let wire = checked_partial_drain(client);
            feed_native(server, &wire);
            let mut received = vec![0; size];
            server.reader().read_exact(&mut received).unwrap();
            assert_eq!(received, bytes);
        }
    });
}

#[test]
fn fragmented_receive_preserves_exact_pending_wire_then_clears_complete_record() {
    with_client(|client, server| {
        authenticate(client, server);
        for size in [16384, 17, 1024, 3, 64] {
            let bytes = payload(size, 83);
            let wire = application_wire(server, &bytes);
            assert_eq!(
                wire.len(),
                5 + usize::from(u16::from_be_bytes([wire[3], wire[4]]))
            );
            let mut offset = 0;
            let chunks = [1, 2, 7, 64, 257, 1024];
            let mut step = 0;
            while offset < wire.len() {
                let count = chunks[step % chunks.len()].min(wire.len() - offset);
                step += 1;
                let progress = client
                    .drive(&wire[offset..offset + count], &mut [])
                    .unwrap();
                assert_eq!(progress.consumed, count);
                assert_eq!(progress.produced, 0);
                offset += count;
                let loan = client.record.as_deref().unwrap();
                if offset < wire.len() {
                    assert_eq!(progress.status, Status::NeedInput);
                    assert_eq!(client.record_len, offset);
                    assert_eq!(&loan[..offset], &wire[..offset]);
                    assert!(loan[offset..].iter().all(|byte| *byte == 0));
                    assert!(
                        client
                            .plaintext
                            .as_deref()
                            .unwrap()
                            .iter()
                            .all(|byte| *byte == 0)
                    );
                    let stalled = client.drive(&[], &mut []).unwrap();
                    assert_eq!((stalled.consumed, stalled.produced), (0, 0));
                    assert_eq!(stalled.status, Status::NeedInput);
                    assert_eq!(
                        &client.record.as_deref().unwrap()[..offset],
                        &wire[..offset]
                    );
                } else {
                    assert_eq!(progress.status, Status::ApplicationData);
                    assert_eq!(client.record_len, 0);
                    assert_eq!(client.record_target, 0);
                    assert!(loan.iter().all(|byte| *byte == 0));
                }
            }
            let mut received = vec![0; size];
            assert_eq!(client.read_plaintext(&mut received).unwrap(), size);
            assert_eq!(received, bytes);
        }
    });
}

#[test]
fn incoming_authentication_failure_clears_all_wire_and_plaintext_capacity() {
    with_client(|client, server| {
        authenticate(client, server);
        let mut wire = application_wire(server, &payload(16384, 71));
        *wire.last_mut().unwrap() ^= 1;
        let partial = wire.len() - 1;
        let progress = client.drive(&wire[..partial], &mut []).unwrap();
        assert_eq!(progress.status, Status::NeedInput);
        assert_eq!(
            &client.record.as_deref().unwrap()[..partial],
            &wire[..partial]
        );
        assert!(matches!(
            client.drive(&wire[partial..], &mut []),
            Err(ClientError::Protected(ProtectedError::Crypto(
                CryptoError::AuthenticationFailed
            )))
        ));
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
        let mut destination = [0xe1; 32];
        assert!(client.read_plaintext(&mut destination).is_err());
        assert_eq!(destination, [0xe1; 32]);
        assert!(!client.is_established());
    });
}
