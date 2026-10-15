//! Authenticated TLS 1.3 baseline. Both peers and memory transport are timed.
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer, ServerName};
use rustls::{ClientConfig, Connection, RootCertStore, ServerConfig};
use std::{
    io::{Cursor, Read, Write},
    sync::Arc,
    time::Instant,
};
type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
fn configs() -> Result<(Arc<ClientConfig>, Arc<ServerConfig>)> {
    let mut provider = rustls::crypto::aws_lc_rs::default_provider();
    provider.cipher_suites =
        vec![rustls::crypto::aws_lc_rs::cipher_suite::TLS13_AES_128_GCM_SHA256];
    provider.kx_groups = vec![rustls::crypto::aws_lc_rs::kx_group::X25519];
    let provider = Arc::new(provider);
    let mut roots = RootCertStore::empty();
    roots.add(CertificateDer::from(
        include_bytes!("../fixtures/ca.der").to_vec(),
    ))?;
    let mut client = ClientConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_root_certificates(roots)
        .with_no_client_auth();
    client.resumption = rustls::client::Resumption::disabled();
    client.alpn_protocols = vec![b"bench/1".to_vec()];
    let mut server = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_no_client_auth()
        .with_single_cert(
            vec![CertificateDer::from(
                include_bytes!("../fixtures/server.der").to_vec(),
            )],
            PrivatePkcs8KeyDer::from(include_bytes!("../fixtures/server-key.der").to_vec()).into(),
        )?;
    server.send_tls13_tickets = 0;
    server.alpn_protocols = client.alpn_protocols.clone();
    Ok((Arc::new(client), Arc::new(server)))
}
fn transfer(from: &mut Connection, to: &mut Connection, wire: &mut Vec<u8>) -> Result<()> {
    while from.wants_write() {
        wire.clear();
        from.write_tls(wire)?;
        let mut input = Cursor::new(wire.as_slice());
        while (input.position() as usize) < wire.len() {
            if to.read_tls(&mut input)? == 0 {
                return Err("zero transport progress".into());
            }
            to.process_new_packets()?;
        }
    }
    Ok(())
}
fn pair(c: Arc<ClientConfig>, s: Arc<ServerConfig>) -> Result<(Connection, Connection)> {
    Ok((
        Connection::Client(rustls::ClientConnection::new(
            c,
            ServerName::try_from("localhost")?,
        )?),
        Connection::Server(rustls::ServerConnection::new(s)?),
    ))
}
fn handshake(c: &mut Connection, s: &mut Connection, wire: &mut Vec<u8>) -> Result<()> {
    for _ in 0..32 {
        transfer(c, s, wire)?;
        transfer(s, c, wire)?;
        if !c.is_handshaking() && !s.is_handshaking() {
            if c.protocol_version() != Some(rustls::ProtocolVersion::TLSv1_3)
                || c.alpn_protocol() != Some(b"bench/1")
            {
                return Err("negotiated policy mismatch".into());
            }
            return Ok(());
        }
    }
    Err("handshake exceeded progress bound".into())
}
fn main() -> Result<()> {
    let args: Vec<_> = std::env::args().collect();
    let option = |key: &str, default: usize| -> Result<usize> {
        Ok(match args.iter().position(|x| x == key) {
            Some(i) => args.get(i + 1).ok_or("missing option value")?.parse()?,
            None => default,
        })
    };
    let samples = option("--samples", 30)?;
    let records = option("--bulk-records", 256)?;
    if samples == 0 || records == 0 {
        return Err("sample/record counts must be positive".into());
    }
    let (cc, sc) = configs()?;
    let mut wire = Vec::with_capacity(32768);
    println!("implementation,workload,direction,payload_bytes,iterations,sample,elapsed_ns");
    // Untimed warm-up, with fresh secure randomness; no session resumption.
    for _ in 0..5 {
        let (mut c, mut s) = pair(cc.clone(), sc.clone())?;
        handshake(&mut c, &mut s, &mut wire)?;
    }
    for sample in 0..samples {
        let start = Instant::now();
        let (mut c, mut s) = pair(cc.clone(), sc.clone())?;
        handshake(&mut c, &mut s, &mut wire)?;
        println!(
            "rustls,full_handshake,both,0,1,{sample},{}",
            start.elapsed().as_nanos()
        );
    }
    for size in [64, 1024, 16384] {
        let payload = vec![0x5a; size];
        let mut received = vec![0; size];
        for direction in ["client_to_server", "server_to_client"] {
            let (mut c, mut s) = pair(cc.clone(), sc.clone())?;
            handshake(&mut c, &mut s, &mut wire)?;
            let (sender, receiver) = if direction == "client_to_server" {
                (&mut c, &mut s)
            } else {
                (&mut s, &mut c)
            };
            for sample in 0..samples {
                let start = Instant::now();
                for _ in 0..records {
                    sender.writer().write_all(&payload)?;
                    transfer(sender, receiver, &mut wire)?;
                    receiver.reader().read_exact(&mut received)?;
                    if received != payload {
                        return Err("plaintext mismatch".into());
                    }
                }
                println!(
                    "rustls,bulk,{direction},{size},{records},{sample},{}",
                    start.elapsed().as_nanos()
                );
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn baseline_rejects_wrong_reference_identity() -> Result<()> {
        let (cc, sc) = configs()?;
        let mut c = Connection::Client(rustls::ClientConnection::new(
            cc,
            ServerName::try_from("wrong.invalid")?,
        )?);
        let mut s = Connection::Server(rustls::ServerConnection::new(sc)?);
        let error = handshake(&mut c, &mut s, &mut Vec::new())
            .expect_err("benchmark verifier must reject a SAN mismatch");
        assert!(matches!(
            error.downcast_ref::<rustls::Error>(),
            Some(rustls::Error::InvalidCertificate(_))
        ));
        assert!(c.is_handshaking());
        Ok(())
    }
}
