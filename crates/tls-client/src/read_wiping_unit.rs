//! Observe private scratch only after a real authenticated native handshake.
use super::*;
use std::io::{Cursor, Write};
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
            vec![CertificateDer::from(CERT.to_vec())],
            rustls::pki_types::PrivatePkcs8KeyDer::from(KEY.to_vec()).into(),
        )
        .unwrap();
    config.send_tls13_tickets = 0;
    config.alpn_protocols = vec![b"bench/1".to_vec()];
    rustls::ServerConnection::new(Arc::new(config)).unwrap()
}

fn authenticate(client: &mut ClientConnection<'_>, server: &mut rustls::ServerConnection) {
    let mut incoming = Vec::new();
    let mut output = vec![0; RECORD_BUFFER_SIZE];
    for _ in 0..1000 {
        while server.wants_write() {
            server.write_tls(&mut incoming).unwrap();
        }
        let progress = client.drive(&incoming, &mut output).unwrap();
        incoming.drain(..progress.consumed);
        if progress.produced != 0 {
            let mut input = Cursor::new(&output[..progress.produced]);
            while input.position() < progress.produced as u64 {
                assert!(server.read_tls(&mut input).unwrap() > 0);
                server.process_new_packets().unwrap();
            }
        }
        if client.is_established() && !server.is_handshaking() && incoming.is_empty() {
            assert_eq!(client.alpn(), Some(&b"bench/1"[..]));
            return;
        }
    }
    panic!("real native handshake did not complete");
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
fn authenticated_partial_reads_preserve_unread_bytes_and_leave_entire_loan_clean() {
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
    let mut record = vec![0xa5; RECORD_BUFFER_SIZE + 19];
    let mut handshake = vec![0xa5; config.limits().handshake_body + 4 + 11];
    let mut plaintext = vec![0xa5; PLAINTEXT_BUFFER_SIZE + 257];
    let mut outbound = vec![0xa5; RECORD_BUFFER_SIZE + 23];
    let mut client = ClientConnection::new(
        AwsLcProvider,
        config,
        ServerName::try_from("localhost".to_owned()).unwrap(),
        UnixTime::since_unix_epoch(Duration::from_secs(1_792_022_400)),
        ClientBuffers {
            record: &mut record,
            handshake: &mut handshake,
            plaintext: &mut plaintext,
            outbound: &mut outbound,
        },
    )
    .unwrap();
    let mut server = native_server();
    authenticate(&mut client, &mut server);
    let mut network_output = vec![0; RECORD_BUFFER_SIZE];
    for size in [1, 64, 1024, 16384, 17, 8191, 3] {
        let payload: Vec<_> = (0..size).map(|i| (i % 251 + 1) as u8).collect();
        let wire = application_wire(&mut server, &payload);
        let progress = client.drive(&wire, &mut network_output).unwrap();
        assert_eq!(progress.consumed, wire.len());
        assert_eq!(progress.status, Status::ApplicationData);
        let plain = client.plaintext.as_deref().unwrap();
        assert_eq!(&plain[..size], payload);
        assert!(plain[size..].iter().all(|&byte| byte == 0));
        let mut offset = 0;
        for requested in [0, 1, 3, 0, 17, 257, 512, 16384] {
            if offset == size {
                break;
            }
            let mut destination = vec![0xa5; requested];
            let count = client.read_plaintext(&mut destination).unwrap();
            assert_eq!(count, requested.min(size - offset));
            assert_eq!(&destination[..count], &payload[offset..offset + count]);
            assert!(destination[count..].iter().all(|&byte| byte == 0xa5));
            offset += count;
            let plain = client.plaintext.as_deref().unwrap();
            assert!(plain[..offset].iter().all(|&byte| byte == 0));
            assert_eq!(&plain[offset..size], &payload[offset..]);
            assert!(plain[size..].iter().all(|&byte| byte == 0));
            if offset < size {
                assert_eq!(
                    client.drive(&[], &mut network_output).unwrap().status,
                    Status::ApplicationData
                );
            }
        }
        assert_eq!(offset, size);
        assert!(
            client
                .plaintext
                .as_deref()
                .unwrap()
                .iter()
                .all(|&byte| byte == 0)
        );
        assert_eq!(client.read_plaintext(&mut [0xa5; 1]).unwrap(), 0);
    }

    let mut damaged = application_wire(&mut server, &[0x67; 1024]);
    *damaged.last_mut().unwrap() ^= 1;
    assert!(matches!(
        client.drive(&damaged, &mut network_output),
        Err(ClientError::Protected(_))
    ));
    assert!(
        client
            .plaintext
            .as_deref()
            .unwrap()
            .iter()
            .all(|&byte| byte == 0)
    );
    assert!(matches!(
        client.read_plaintext(&mut [0; 1024]),
        Err(ClientError::NotEstablished)
    ));
    drop(client);
    for loan in [&record, &handshake, &plaintext, &outbound] {
        assert!(loan.iter().all(|&byte| byte == 0));
    }
}
