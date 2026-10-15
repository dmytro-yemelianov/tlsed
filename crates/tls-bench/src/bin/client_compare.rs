//! Authenticated client comparison; the server and strict certificate policy are shared.
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use std::fmt;
use std::io::{Cursor, Read, Write};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tls_client::{ClientBuffers, ClientLimits, PLAINTEXT_BUFFER_SIZE, RECORD_BUFFER_SIZE, Status};
use tls_crypto::{CipherSuite, NamedGroup};
use tls_crypto_awslc::AwsLcProvider;
use tls_pki::{ChainLimits, RevocationPolicy, ServerVerifier};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
const CA: &[u8] = include_bytes!("../../fixtures/ca.der");
const CERT: &[u8] = include_bytes!("../../fixtures/server.der");
const KEY: &[u8] = include_bytes!("../../fixtures/server-key.der");
const TIME: u64 = 1_792_022_400; // 2026-10-15 UTC, inside fixture validity.
const SIGNATURES: [SignatureScheme; 5] = [
    SignatureScheme::ECDSA_NISTP256_SHA256,
    SignatureScheme::RSA_PSS_SHA256,
    SignatureScheme::RSA_PSS_SHA384,
    SignatureScheme::RSA_PSS_SHA512,
    SignatureScheme::ED25519,
];
fn now() -> UnixTime {
    UnixTime::since_unix_epoch(Duration::from_secs(TIME))
}
#[derive(Debug)]
struct FixedTime;
impl rustls::time_provider::TimeProvider for FixedTime {
    fn current_time(&self) -> Option<UnixTime> {
        Some(now())
    }
}
fn engine<T>(result: std::result::Result<T, tls_client::ClientError>) -> Result<T> {
    result.map_err(|e| format!("tlsed: {e:?}").into())
}

struct StrictVerifier {
    verifier: ServerVerifier,
    algorithms: rustls::crypto::WebPkiSupportedAlgorithms,
}
impl fmt::Debug for StrictVerifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("StrictMaintainedServerVerifier")
    }
}
impl ServerCertVerifier for StrictVerifier {
    fn verify_server_cert(
        &self,
        leaf: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        name: &ServerName<'_>,
        _ocsp: &[u8],
        time: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        let mut chain = Vec::with_capacity(intermediates.len() + 1);
        chain.push(CertificateDer::from(leaf.as_ref()));
        chain.extend(
            intermediates
                .iter()
                .map(|cert| CertificateDer::from(cert.as_ref())),
        );
        // Same maintained chain/name/time/strict-KeyUsage checks as tlsed.
        // The marker is returned only after successful actual authentication.
        self.verifier
            .verify_server_certificate(&chain, name, time)
            .map_err(|error| rustls::Error::General(format!("strict PKI: {error:?}")))?;
        Ok(ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _signature: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        Err(rustls::Error::General("TLS1.2 disabled".into()))
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        if !SIGNATURES.contains(&signature.scheme) {
            return Err(rustls::Error::General("unoffered signature scheme".into()));
        }
        rustls::crypto::verify_tls13_signature(message, cert, signature, &self.algorithms)
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        SIGNATURES.to_vec()
    }
}
struct Configs {
    tlsed: Arc<tls_client::ClientConfig>,
    rustls: Arc<rustls::ClientConfig>,
    server: Arc<rustls::ServerConfig>,
}
fn configs(suite: CipherSuite, initial: NamedGroup, retry: bool) -> Result<Configs> {
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
    let x = rustls::crypto::aws_lc_rs::kx_group::X25519;
    let p = rustls::crypto::aws_lc_rs::kx_group::SECP256R1;
    provider.kx_groups = match initial {
        NamedGroup::X25519 => vec![x, p],
        NamedGroup::Secp256r1 => vec![p, x],
    };
    let verifier = StrictVerifier {
        verifier: ServerVerifier::new(
            &[CertificateDer::from(CA)],
            ChainLimits::default(),
            RevocationPolicy::NoRevocationData,
        )
        .map_err(|e| format!("PKI config: {e:?}"))?,
        algorithms: provider.signature_verification_algorithms,
    };
    let mut client = rustls::ClientConfig::builder_with_provider(Arc::new(provider.clone()))
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_no_client_auth();
    client.resumption = rustls::client::Resumption::disabled();
    client.alpn_protocols = vec![b"bench/1".to_vec()];
    client.time_provider = Arc::new(FixedTime);
    provider.kx_groups = if retry { vec![p] } else { provider.kx_groups };
    let mut server = rustls::ServerConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_no_client_auth()
        .with_single_cert(
            vec![CertificateDer::from(CERT.to_vec())],
            PrivatePkcs8KeyDer::from(KEY.to_vec()).into(),
        )?;
    server.send_tls13_tickets = 0;
    server.alpn_protocols = vec![b"bench/1".to_vec()];
    server.time_provider = Arc::new(FixedTime);
    Ok(Configs {
        tlsed: Arc::new(engine(tls_client::ClientConfig::new(
            &[CertificateDer::from(CA)],
            b"bench/1",
            &[suite],
            initial,
            ClientLimits::default(),
        ))?),
        rustls: Arc::new(client),
        server: Arc::new(server),
    })
}

#[derive(Clone, Copy)]
enum Implementation {
    Tlsed,
    Rustls,
}
impl Implementation {
    fn name(self) -> &'static str {
        match self {
            Self::Tlsed => "tlsed",
            Self::Rustls => "rustls_strict",
        }
    }
}
struct Scratch {
    record: Vec<u8>,
    handshake: Vec<u8>,
    plain: Vec<u8>,
    outbound: Vec<u8>,
}
impl Scratch {
    fn new() -> Self {
        Self {
            record: vec![0; RECORD_BUFFER_SIZE],
            handshake: vec![0; ClientLimits::default().handshake_body + 4],
            plain: vec![0; PLAINTEXT_BUFFER_SIZE],
            outbound: vec![0; RECORD_BUFFER_SIZE],
        }
    }
}
enum Client<'a> {
    Tlsed(Box<tls_client::ClientConnection<'a>>),
    Rustls(Box<rustls::ClientConnection>),
}
impl<'a> Client<'a> {
    fn new(
        kind: Implementation,
        config: &Configs,
        scratch: &'a mut Scratch,
        name: &str,
    ) -> Result<Self> {
        let name = ServerName::try_from(name.to_owned())?;
        Ok(match kind {
            Implementation::Tlsed => {
                Self::Tlsed(Box::new(engine(tls_client::ClientConnection::new(
                    AwsLcProvider,
                    config.tlsed.clone(),
                    name,
                    now(),
                    ClientBuffers {
                        record: &mut scratch.record,
                        handshake: &mut scratch.handshake,
                        plaintext: &mut scratch.plain,
                        outbound: &mut scratch.outbound,
                    },
                ))?))
            }
            Implementation::Rustls => Self::Rustls(Box::new(rustls::ClientConnection::new(
                config.rustls.clone(),
                name,
            )?)),
        })
    }
    fn step(&mut self, input: &[u8], output: &mut [u8]) -> Result<(usize, usize, bool, bool)> {
        match self {
            Self::Tlsed(client) => {
                let progress = engine(client.drive(input, output))?;
                let work = !matches!(
                    progress.status,
                    Status::NeedInput | Status::ApplicationData | Status::Closed
                );
                Ok((
                    progress.consumed,
                    progress.produced,
                    work,
                    progress.status == Status::ApplicationData,
                ))
            }
            Self::Rustls(client) => {
                let mut output = output;
                let produced = if client.wants_write() {
                    client.write_tls(&mut output)?
                } else {
                    0
                };
                let (consumed, ready) = if input.is_empty() {
                    (0, false)
                } else {
                    let consumed = client.read_tls(&mut Cursor::new(input))?;
                    let state = client.process_new_packets()?;
                    (consumed, state.plaintext_bytes_to_read() != 0)
                };
                Ok((consumed, produced, client.wants_write(), ready))
            }
        }
    }
    fn established(&self) -> bool {
        match self {
            Self::Tlsed(client) => client.is_established(),
            Self::Rustls(client) => !client.is_handshaking(),
        }
    }
    fn write(&mut self, payload: &[u8]) -> Result<()> {
        match self {
            Self::Tlsed(client) => {
                if engine(client.write_plaintext(payload))? != payload.len() {
                    return Err("short client application write".into());
                }
            }
            Self::Rustls(client) => client.writer().write_all(payload)?,
        }
        Ok(())
    }
    fn read(&mut self, received: &mut [u8]) -> Result<()> {
        match self {
            Self::Tlsed(client) => {
                if engine(client.read_plaintext(received))? != received.len() {
                    return Err("short client application read".into());
                }
            }
            Self::Rustls(client) => client.reader().read_exact(received)?,
        }
        Ok(())
    }
}
/// Byte queue with a read cursor. Consuming advances the cursor; the buffer is compacted only
/// once the consumed prefix is at least half of it, so bytes move O(1) times on average. A
/// plain `Vec::drain(..n)` per fragment shifted the whole remaining record on every step, which
/// dominated the 64-byte fragment profiles for every client.
#[derive(Default)]
struct Queue {
    buf: Vec<u8>,
    at: usize,
}
impl Queue {
    fn with_capacity(n: usize) -> Self {
        Self {
            buf: Vec::with_capacity(n),
            at: 0,
        }
    }
    fn pending(&self) -> &[u8] {
        &self.buf[self.at..]
    }
    fn is_empty(&self) -> bool {
        self.at == self.buf.len()
    }
    fn consume(&mut self, n: usize) {
        self.at += n;
        if self.at == self.buf.len() {
            self.buf.clear();
            self.at = 0;
        } else if self.at * 2 >= self.buf.len() {
            self.buf.drain(..self.at);
            self.at = 0;
        }
    }
    fn clear(&mut self) {
        self.buf.clear();
        self.at = 0;
    }
}
impl std::io::Write for Queue {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        self.buf.extend_from_slice(data);
        Ok(data.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

struct Transport {
    client: Queue,
    server: Queue,
    output: Vec<u8>,
    fragment: usize,
}
impl Transport {
    fn new(fragment: usize) -> Self {
        Self {
            client: Queue::with_capacity(32768),
            server: Queue::with_capacity(32768),
            output: vec![0; fragment],
            fragment,
        }
    }
    fn clear(&mut self) {
        self.client.clear();
        self.server.clear();
    }
    fn pump(
        &mut self,
        client: &mut Client<'_>,
        server: &mut rustls::ServerConnection,
    ) -> Result<()> {
        for _ in 0..200_000 {
            let mut activity = false;
            while server.wants_write() {
                activity |= server.write_tls(&mut self.client)? != 0;
            }
            let input = self.client.pending();
            let input_len = input.len().min(self.fragment);
            let (consumed, produced, work, ready) =
                client.step(&input[..input_len], &mut self.output)?;
            self.client.consume(consumed);
            self.server.buf.extend_from_slice(&self.output[..produced]);
            activity |= consumed != 0 || produced != 0 || work;
            if !self.server.is_empty() {
                let pending = self.server.pending();
                let n = pending.len().min(self.fragment);
                let consumed = server.read_tls(&mut Cursor::new(&pending[..n]))?;
                self.server.consume(consumed);
                server.process_new_packets()?;
                activity |= consumed != 0;
            }
            if ready {
                return Ok(());
            }
            if !activity && self.client.is_empty() && self.server.is_empty() {
                return Ok(());
            }
        }
        Err("memory transport work bound exceeded".into())
    }
    fn handshake(
        &mut self,
        client: &mut Client<'_>,
        server: &mut rustls::ServerConnection,
    ) -> Result<()> {
        self.pump(client, server)?;
        if !client.established()
            || server.is_handshaking()
            || server.protocol_version() != Some(rustls::ProtocolVersion::TLSv1_3)
            || server.alpn_protocol() != Some(b"bench/1")
        {
            return Err("authenticated handshake did not complete".into());
        }
        match client {
            Client::Tlsed(c) if c.alpn() != Some(b"bench/1") => {
                return Err("client ALPN mismatch".into());
            }
            Client::Rustls(c) if c.alpn_protocol() != Some(b"bench/1") => {
                return Err("client ALPN mismatch".into());
            }
            _ => {}
        }
        Ok(())
    }
}

fn measure(
    kind: Implementation,
    config: &Configs,
    samples: usize,
    records: usize,
    fragment: usize,
    only: &str,
) -> Result<()> {
    let mut transport = Transport::new(fragment);
    let mut scratch = Scratch::new();
    for _ in 0..10 {
        transport.clear();
        let mut client = Client::new(kind, config, &mut scratch, "localhost")?;
        let mut server = rustls::ServerConnection::new(config.server.clone())?;
        transport.handshake(&mut client, &mut server)?;
    }
    for workload in [
        "full_handshake_reused_buffers",
        "full_handshake_fresh_buffers",
    ] {
        if only != "all" {
            continue;
        }
        for sample in 0..samples {
            transport.clear();
            let start = Instant::now();
            let mut fresh;
            let buffers =
                if workload.ends_with("fresh_buffers") && matches!(kind, Implementation::Tlsed) {
                    fresh = Scratch::new();
                    &mut fresh
                } else {
                    &mut scratch
                };
            let mut client = Client::new(kind, config, buffers, "localhost")?;
            let mut server = rustls::ServerConnection::new(config.server.clone())?;
            transport.handshake(&mut client, &mut server)?;
            let elapsed = start.elapsed().as_nanos();
            println!("{},{},both,0,1,{sample},{elapsed}", kind.name(), workload);
        }
    }
    for sample in 0..if only == "all" { samples } else { 0 } {
        transport.clear();
        let start = Instant::now();
        {
            let mut fresh;
            let buffers = if matches!(kind, Implementation::Tlsed) {
                fresh = Scratch::new();
                &mut fresh
            } else {
                &mut scratch
            };
            let mut client = Client::new(kind, config, buffers, "localhost")?;
            let mut server = rustls::ServerConnection::new(config.server.clone())?;
            transport.handshake(&mut client, &mut server)?;
            // This additional workload includes key retirement, whole-loan
            // wiping, and release of newly allocated connection storage.
        }
        let elapsed = start.elapsed().as_nanos();
        println!(
            "{},connection_lifecycle,both,0,1,{sample},{elapsed}",
            kind.name()
        );
    }
    for size in [64, 1024, 16384] {
        let payload = vec![0x5a; size];
        let mut received = vec![0; size];
        for direction in ["client_to_server", "server_to_client"] {
            if only != "all"
                && (size != 16384
                    || (only == "bulk-tx-16384" && direction != "client_to_server")
                    || (only == "bulk-rx-16384" && direction != "server_to_client"))
            {
                continue;
            }
            transport.clear();
            let mut client = Client::new(kind, config, &mut scratch, "localhost")?;
            let mut server = rustls::ServerConnection::new(config.server.clone())?;
            transport.handshake(&mut client, &mut server)?;
            for sample in 0..(samples + 5) {
                let start = Instant::now();
                for _ in 0..records {
                    if direction == "client_to_server" {
                        client.write(&payload)?;
                        transport.pump(&mut client, &mut server)?;
                        server.reader().read_exact(&mut received)?;
                    } else {
                        server.writer().write_all(&payload)?;
                        transport.pump(&mut client, &mut server)?;
                        client.read(&mut received)?;
                    }
                    if received != payload {
                        return Err("authenticated plaintext mismatch".into());
                    }
                    std::hint::black_box(&received);
                }
                let elapsed = start.elapsed().as_nanos();
                if sample >= 5 {
                    println!(
                        "{},bulk,{direction},{size},{records},{},{elapsed}",
                        kind.name(),
                        sample - 5
                    );
                }
            }
        }
    }
    Ok(())
}
/// One live connection in the round-robin working-set test: its own scratch buffers (through
/// `Client`), server, and transport.
struct Connection<'a> {
    client: Client<'a>,
    server: rustls::ServerConnection,
    transport: Transport,
}

/// Server-to-client 16 KiB records spread round-robin over `connections` live connections. The
/// bytes per record match `measure`; only the memory each record touches changes, because a
/// connection's buffers are used once per round rather than on every record.
fn measure_round_robin(
    kind: Implementation,
    config: &Configs,
    samples: usize,
    records: usize,
    fragment: usize,
    connections: usize,
) -> Result<()> {
    let mut scratches: Vec<Scratch> = (0..connections).map(|_| Scratch::new()).collect();
    let mut pool = Vec::with_capacity(connections);
    for scratch in scratches.iter_mut() {
        let mut client = Client::new(kind, config, scratch, "localhost")?;
        let mut server = rustls::ServerConnection::new(config.server.clone())?;
        let mut transport = Transport::new(fragment);
        transport.handshake(&mut client, &mut server)?;
        pool.push(Connection {
            client,
            server,
            transport,
        });
    }
    let payload = vec![0x5a; 16384];
    let mut received = vec![0; 16384];
    for sample in 0..(samples + 5) {
        let start = Instant::now();
        for record in 0..records {
            let conn = &mut pool[record % connections];
            conn.server.writer().write_all(&payload)?;
            conn.transport.pump(&mut conn.client, &mut conn.server)?;
            conn.client.read(&mut received)?;
            if received != payload {
                return Err("authenticated plaintext mismatch".into());
            }
            std::hint::black_box(&received);
        }
        let elapsed = start.elapsed().as_nanos();
        if sample >= 5 {
            println!(
                "{},round_robin_{connections},server_to_client,16384,{records},{},{elapsed}",
                kind.name(),
                sample - 5
            );
        }
    }
    Ok(())
}

fn main() -> Result<()> {
    let args: Vec<_> = std::env::args().collect();
    let option = |key: &str, default: &str| -> Result<String> {
        Ok(match args.iter().position(|x| x == key) {
            Some(i) => args.get(i + 1).ok_or("missing option value")?.clone(),
            None => default.into(),
        })
    };
    let samples: usize = option("--samples", "100")?.parse()?;
    let records: usize = option("--bulk-records", "256")?.parse()?;
    let fragment: usize = option("--fragment", "16645")?.parse()?;
    if samples == 0 || records == 0 || fragment == 0 || fragment > 32768 {
        return Err("invalid counts/fragment".into());
    }
    let suite = match option("--suite", "aes128")?.as_str() {
        "aes128" => CipherSuite::Aes128GcmSha256,
        "aes256" => CipherSuite::Aes256GcmSha384,
        "chacha" => CipherSuite::Chacha20Poly1305Sha256,
        _ => return Err("invalid suite".into()),
    };
    let group = option("--group", "x25519")?;
    let initial = match group.as_str() {
        "x25519" | "hrr" => NamedGroup::X25519,
        "p256" => NamedGroup::Secp256r1,
        _ => return Err("invalid group".into()),
    };
    let config = configs(suite, initial, group == "hrr")?;
    // Diagnostic isolation only; the canonical paired run keeps every workload.
    let only = option("--only", "all")?;
    if !matches!(only.as_str(), "all" | "bulk-tx-16384" | "bulk-rx-16384") {
        return Err("invalid workload filter".into());
    }
    let order = option("--order", "tlsed-first")?;
    let kinds = match order.as_str() {
        "tlsed-first" => [Implementation::Tlsed, Implementation::Rustls],
        "rustls-first" => [Implementation::Rustls, Implementation::Tlsed],
        _ => return Err("invalid order".into()),
    };
    // Diagnostic isolation only: measure one client in its own process.
    let implementation = option("--impl", "both")?;
    if !matches!(implementation.as_str(), "both" | "tlsed" | "rustls") {
        return Err("invalid implementation filter".into());
    }
    // Working-set test: with --connections, the bulk records are spread round-robin over K live
    // connections, including K = 1, so every point in a series uses the same path.
    let round_robin = args.iter().any(|x| x == "--connections");
    let connections: usize = option("--connections", "1")?.parse()?;
    if connections == 0 || connections > 1024 {
        return Err("invalid connection count".into());
    }
    println!("implementation,workload,direction,payload_bytes,iterations,sample,elapsed_ns");
    for kind in kinds {
        let selected = matches!(
            (implementation.as_str(), kind),
            ("both", _) | ("tlsed", Implementation::Tlsed) | ("rustls", Implementation::Rustls)
        );
        if !selected {
            continue;
        }
        let before = minor_faults();
        if round_robin {
            measure_round_robin(kind, &config, samples, records, fragment, connections)?;
        } else {
            measure(kind, &config, samples, records, fragment, &only)?;
        }
        if let (Some(before), Some(after)) = (before, minor_faults()) {
            eprintln!("minor_faults,{},{}", kind.name(), after - before);
        }
    }
    Ok(())
}

/// Minor page faults of this process so far, from `/proc/self/stat` (field 10).
#[cfg(target_os = "linux")]
fn minor_faults() -> Option<u64> {
    let stat = std::fs::read_to_string("/proc/self/stat").ok()?;
    let after_comm = stat.rsplit_once(')')?.1;
    after_comm.split_whitespace().nth(7)?.parse().ok()
}

#[cfg(not(target_os = "linux"))]
fn minor_faults() -> Option<u64> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn both_clients_reject_wrong_reference_identity() -> Result<()> {
        let config = configs(CipherSuite::Aes128GcmSha256, NamedGroup::X25519, false)?;
        for kind in [Implementation::Tlsed, Implementation::Rustls] {
            let mut scratch = Scratch::new();
            let mut client = Client::new(kind, &config, &mut scratch, "wrong.example")?;
            let mut server = rustls::ServerConnection::new(config.server.clone())?;
            assert!(
                Transport::new(RECORD_BUFFER_SIZE)
                    .handshake(&mut client, &mut server)
                    .is_err()
            );
            assert!(!client.established());
        }
        Ok(())
    }
}
