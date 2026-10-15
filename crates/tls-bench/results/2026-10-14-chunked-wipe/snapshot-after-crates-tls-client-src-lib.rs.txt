//! Experimental authenticated TLS1.3 client, driven through caller-owned buffers.
//! Maintained AWS-LC and PKI remain trusted; no sockets, runtime, or insecure verifier.
use std::sync::Arc;
use tls_core::client_policy::client_phase_next;
use tls_core::handshake::{HandshakeError, Message, Reassembler, Status as HandshakeStatus};
use tls_core::hello::{self, ClientHelloParams, CodecError};
use tls_core::key_schedule::{
    Client, HandshakeSecrets, KeyScheduleError, ReceivingTraffic, SendingTraffic, Server,
};
use tls_core::protected::{
    ContentType, MAX_INNER_PLAINTEXT, ProtectedError, ProtectedReader, ProtectedWriter,
};
use tls_core::transcript::{Transcript, TranscriptError};
use tls_core::wire::{Header, Limits as WireLimits, Parse, RecordKind, parse_header};
use tls_crypto::{
    CipherSuite, CryptoError, EphemeralKeyExchange, HashAlgorithm, KeyExchangeProvider, NamedGroup,
};
use tls_crypto_awslc::AwsLcProvider;
use tls_pki::{
    CertificateDer, ChainLimits, OwnedVerifiedServerCert, PkiError, RevocationPolicy, ServerName,
    ServerVerifier, UnixTime,
};
use zeroize::Zeroize;

/// Clear the exact byte slice using maintained volatile zeroization. The safe
/// POD view splits disjoint byte edges from an aligned u128 middle without
/// allocation or reading/copying the secret. All-zero u128 has sixteen zero
/// bytes on every endian. Empty or nonmaximal middles still clear via the edges.
#[inline]
fn zeroize_secret(bytes: &mut [u8]) {
    let (head, words, tail) = bytemuck::pod_align_to_mut::<u8, u128>(bytes);
    head.zeroize();
    words.zeroize();
    tail.zeroize();
}

pub const RECORD_BUFFER_SIZE: usize = 16645;
pub const PLAINTEXT_BUFFER_SIZE: usize = 16640;
const GROUPS: [u16; 2] = [0x001d, 0x0017];
const SIGNATURES: [u16; 5] = [0x0403, 0x0804, 0x0805, 0x0806, 0x0807];

#[derive(Clone, Copy, Debug)]
pub struct ClientLimits {
    pub handshake_body: usize,
    pub handshake_bytes: u64,
    pub handshake_messages: u64,
    pub work_bytes: usize,
    pub certificates: usize,
    pub certificate_bytes: usize,
    pub chain_bytes: usize,
    pub cookie_bytes: usize,
    pub send_records_per_key: u64,
    pub post_handshake_messages: u64,
}
impl Default for ClientLimits {
    fn default() -> Self {
        Self {
            handshake_body: 65536,
            handshake_bytes: 1048576,
            handshake_messages: 32,
            work_bytes: 4096,
            certificates: 8,
            certificate_bytes: 65536,
            chain_bytes: 262144,
            cookie_bytes: 4096,
            send_records_per_key: 1 << 24,
            post_handshake_messages: 1024,
        }
    }
}

/// Immutable reusable trust/protocol policy; hostname and validation time are
/// supplied explicitly per connection. Only DNS/IP SAN identities are supported.
pub struct ClientConfig {
    verifier: ServerVerifier,
    alpn: Vec<u8>,
    suites: Vec<CipherSuite>,
    initial_group: NamedGroup,
    limits: ClientLimits,
}
impl ClientConfig {
    pub fn new(
        roots: &[CertificateDer<'_>],
        alpn: &[u8],
        suites: &[CipherSuite],
        initial_group: NamedGroup,
        limits: ClientLimits,
    ) -> Result<Self, ClientError> {
        if suites.is_empty()
            || suites.len() > 3
            || alpn.len() > 255
            || limits.handshake_body < 512
            || limits.handshake_body > 0xffffff
            || limits.handshake_bytes < 512
            || limits.handshake_messages < 8
            || limits.work_bytes == 0
            || limits.certificates == 0
            || limits.certificates > 32
            || limits.cookie_bytes > 4096
            || limits.send_records_per_key < 2
            || limits.post_handshake_messages == 0
            || suites.iter().enumerate().any(|(i, s)| {
                suites[..i].contains(s) || limits.send_records_per_key > s.sending_record_limit()
            })
        {
            return Err(ClientError::InvalidConfig);
        }
        let verifier = ServerVerifier::new(
            roots,
            ChainLimits::new(
                limits.certificates,
                limits.certificate_bytes,
                limits.chain_bytes,
            )?,
            RevocationPolicy::NoRevocationData,
        )?;
        Ok(Self {
            verifier,
            alpn: alpn.to_vec(),
            suites: suites.to_vec(),
            initial_group,
            limits,
        })
    }
    pub fn limits(&self) -> ClientLimits {
        self.limits
    }
}

/// Caller storage is borrowed for the connection lifetime and wiped on abort/Drop.
/// Handshake buffer needs configured body+4; other buffers use the constants above.
pub struct ClientBuffers<'a> {
    pub record: &'a mut [u8],
    pub handshake: &'a mut [u8],
    pub plaintext: &'a mut [u8],
    pub outbound: &'a mut [u8],
}

#[derive(Debug)]
pub enum ClientError {
    InvalidConfig,
    BufferTooSmall,
    NotEstablished,
    OutputPending,
    InputPending,
    Failed,
    UnexpectedMessage,
    IllegalParameter,
    ResourceLimit,
    Truncated,
    PeerAlert(u8),
    Core(tls_core::Error),
    Protected(ProtectedError),
    Codec(CodecError),
    Handshake(HandshakeError),
    Crypto(CryptoError),
    Schedule(KeyScheduleError),
    Transcript(TranscriptError),
    Pki(PkiError),
}
macro_rules! error_from {
    ($type:ty, $variant:ident) => {
        impl From<$type> for ClientError {
            fn from(error: $type) -> Self {
                Self::$variant(error)
            }
        }
    };
}
error_from!(tls_core::Error, Core);
error_from!(ProtectedError, Protected);
error_from!(CodecError, Codec);
error_from!(HandshakeError, Handshake);
error_from!(CryptoError, Crypto);
error_from!(KeyScheduleError, Schedule);
error_from!(TranscriptError, Transcript);
error_from!(PkiError, Pki);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Status {
    NeedInput,
    NeedOutput,
    NeedWork,
    HandshakeProgress,
    HandshakeComplete,
    ApplicationData,
    Closed,
    Failed,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Progress {
    pub consumed: usize,
    pub produced: usize,
    pub status: Status,
}

#[derive(Clone, Copy)]
enum Outgoing {
    Hello,
    ClientFinished,
    Application,
    KeyUpdate,
    Close,
    Fatal,
}

/// Private state advances only after the corresponding actual verification.
/// Each drive processes at most one record and one bounded handshake-copy step.
pub struct ClientConnection<'a, P: KeyExchangeProvider = AwsLcProvider> {
    provider: P,
    config: Arc<ClientConfig>,
    reference: ServerName<'static>,
    now: UnixTime,
    phase: u8,
    retried: bool,
    chosen_suite: Option<CipherSuite>,
    random: [u8; 32],
    ephemeral: Option<P::Ephemeral>,
    transcript256: Option<Transcript<P::Hasher>>,
    transcript384: Option<Transcript<P::Hasher>>,
    handshake_secrets: Option<HandshakeSecrets>,
    read_secret: Option<ReceivingTraffic<Server>>,
    write_secret: Option<SendingTraffic<Client>>,
    reader: Option<ProtectedReader<P::Key>>,
    writer: Option<ProtectedWriter<P::Key>>,
    assembler: Option<Reassembler<'a>>,
    record: Option<&'a mut [u8]>,
    record_len: usize,
    record_target: usize,
    plaintext: Option<&'a mut [u8]>,
    plain_len: usize,
    plain_offset: usize,
    plain_kind: Option<ContentType>,
    outbound: Option<&'a mut [u8]>,
    out_len: usize,
    out_offset: usize,
    outgoing: Option<Outgoing>,
    verified_certificate: Option<OwnedVerifiedServerCert>,
    peer_closed: bool,
    write_closed: bool,
    post_messages: u64,
}

fn suite_code(suite: CipherSuite) -> u16 {
    match suite {
        CipherSuite::Aes128GcmSha256 => 0x1301,
        CipherSuite::Aes256GcmSha384 => 0x1302,
        CipherSuite::Chacha20Poly1305Sha256 => 0x1303,
    }
}
fn named_group(code: u16) -> Result<NamedGroup, ClientError> {
    match code {
        0x001d => Ok(NamedGroup::X25519),
        0x0017 => Ok(NamedGroup::Secp256r1),
        _ => Err(ClientError::IllegalParameter),
    }
}

impl<'a, P: KeyExchangeProvider> ClientConnection<'a, P> {
    pub fn new(
        provider: P,
        config: Arc<ClientConfig>,
        reference: ServerName<'static>,
        now: UnixTime,
        buffers: ClientBuffers<'a>,
    ) -> Result<Self, ClientError> {
        if buffers.record.len() < RECORD_BUFFER_SIZE
            || buffers.outbound.len() < RECORD_BUFFER_SIZE
            || buffers.plaintext.len() < PLAINTEXT_BUFFER_SIZE
            || buffers.handshake.len() < config.limits.handshake_body + 4
        {
            return Err(ClientError::BufferTooSmall);
        }
        if config.suites.iter().any(|s| !provider.supports(*s)) {
            return Err(ClientError::InvalidConfig);
        }
        let limits = config.limits;
        let make_transcript = |algorithm| -> Result<_, ClientError> {
            Ok(Transcript::new(
                provider.hash_context(algorithm)?,
                limits.handshake_body,
                limits.handshake_bytes,
                limits.handshake_messages,
            )?)
        };
        let transcript256 = if config
            .suites
            .iter()
            .any(|s| s.hash() == HashAlgorithm::Sha256)
        {
            Some(make_transcript(HashAlgorithm::Sha256)?)
        } else {
            None
        };
        let transcript384 = if config
            .suites
            .iter()
            .any(|s| s.hash() == HashAlgorithm::Sha384)
        {
            Some(make_transcript(HashAlgorithm::Sha384)?)
        } else {
            None
        };
        let mut random = [0; 32];
        provider.fill_random(&mut random)?;
        let ephemeral = provider.start_key_exchange(config.initial_group)?;
        zeroize_secret(buffers.record);
        zeroize_secret(buffers.plaintext);
        zeroize_secret(buffers.outbound);
        let assembler =
            Reassembler::new(buffers.handshake, limits.handshake_body, limits.work_bytes)?;
        let mut connection = Self {
            provider,
            config,
            reference,
            now,
            phase: 0,
            retried: false,
            chosen_suite: None,
            random,
            ephemeral: Some(ephemeral),
            transcript256,
            transcript384,
            handshake_secrets: None,
            read_secret: None,
            write_secret: None,
            reader: None,
            writer: None,
            assembler: Some(assembler),
            record: Some(buffers.record),
            record_len: 0,
            record_target: 0,
            plaintext: Some(buffers.plaintext),
            plain_len: 0,
            plain_offset: 0,
            plain_kind: None,
            outbound: Some(buffers.outbound),
            out_len: 0,
            out_offset: 0,
            outgoing: None,
            verified_certificate: None,
            peer_closed: false,
            write_closed: false,
            post_messages: 0,
        };
        connection.queue_hello(None)?;
        Ok(connection)
    }

    pub fn is_established(&self) -> bool {
        self.phase == 6
    }
    pub fn negotiated_suite(&self) -> Option<CipherSuite> {
        self.chosen_suite
    }
    pub fn retried(&self) -> bool {
        self.retried
    }
    pub fn alpn(&self) -> Option<&[u8]> {
        if self.is_established() && !self.config.alpn.is_empty() {
            Some(&self.config.alpn)
        } else {
            None
        }
    }
    fn advance(&mut self, event: u8) -> Result<(), ClientError> {
        self.phase = client_phase_next(self.phase, event, true, self.retried)
            .ok_or(ClientError::UnexpectedMessage)?;
        Ok(())
    }
    fn append_transcript(&mut self, encoded: &[u8]) -> Result<(), ClientError> {
        if let Some(t) = self.transcript256.as_mut() {
            t.append(encoded)?;
        }
        if let Some(t) = self.transcript384.as_mut() {
            t.append(encoded)?;
        }
        Ok(())
    }
    fn transcript(&mut self) -> Result<&mut Transcript<P::Hasher>, ClientError> {
        match self
            .chosen_suite
            .ok_or(ClientError::UnexpectedMessage)?
            .hash()
        {
            HashAlgorithm::Sha256 => self.transcript256.as_mut(),
            HashAlgorithm::Sha384 => self.transcript384.as_mut(),
        }
        .ok_or(ClientError::Failed)
    }
    fn choose_suite(&mut self, code: u16) -> Result<CipherSuite, ClientError> {
        let suite = *self
            .config
            .suites
            .iter()
            .find(|s| suite_code(**s) == code)
            .ok_or(ClientError::IllegalParameter)?;
        if self.chosen_suite.is_some_and(|old| old != suite) {
            return Err(ClientError::IllegalParameter);
        }
        self.chosen_suite = Some(suite);
        match suite.hash() {
            HashAlgorithm::Sha256 => {
                self.transcript384.take();
            }
            HashAlgorithm::Sha384 => {
                self.transcript256.take();
            }
        }
        Ok(suite)
    }
    fn queue_hello(&mut self, cookie: Option<&[u8]>) -> Result<(), ClientError> {
        if self.out_len != 0 {
            return Err(ClientError::OutputPending);
        }
        let output = self.outbound.take().ok_or(ClientError::Failed)?;
        let result = (|| {
            let ephemeral = self.ephemeral.as_ref().ok_or(ClientError::Failed)?;
            let mut codes = [0; 3];
            for (i, &suite) in self.config.suites.iter().enumerate() {
                codes[i] = suite_code(suite);
            }
            let sni = match &self.reference {
                ServerName::DnsName(name) => Some(name.as_ref().trim_end_matches('.').as_bytes()),
                ServerName::IpAddress(_) => None,
                _ => return Err(ClientError::InvalidConfig),
            };
            let params = ClientHelloParams {
                random: &self.random,
                session_id: &[],
                server_name: sni,
                alpn: &self.config.alpn,
                suites: &codes[..self.config.suites.len()],
                groups: &GROUPS,
                signatures: &SIGNATURES,
                key_share_group: ephemeral.group().wire_code(),
                key_share: ephemeral.public_key(),
                cookie,
            };
            let length = hello::encode_client_hello(&params, &mut output[5..])?;
            Header {
                content_type: 22,
                legacy_version: 0x0303,
                length: u16::try_from(length).map_err(|_| ClientError::ResourceLimit)?,
            }
            .write(WireLimits::new(RecordKind::Plaintext, 16384)?, output)?;
            self.append_transcript(&output[5..5 + length])?;
            Ok(length + 5)
        })();
        self.outbound = Some(output);
        self.out_len = result?;
        self.out_offset = 0;
        self.outgoing = Some(Outgoing::Hello);
        Ok(())
    }
    fn seal_outgoing(
        &mut self,
        kind: ContentType,
        body: &[u8],
        outgoing: Outgoing,
    ) -> Result<(), ClientError> {
        if self.out_len != 0 {
            return Err(ClientError::OutputPending);
        }
        let output = self.outbound.as_mut().ok_or(ClientError::Failed)?;
        let writer = self.writer.as_mut().ok_or(ClientError::UnexpectedMessage)?;
        self.out_len = writer.seal(kind, body, 0, output)?;
        self.out_offset = 0;
        self.outgoing = Some(outgoing);
        Ok(())
    }
    /// Copy pending network bytes, including a best-effort fatal alert after an error.
    /// The peer can process them only in the order handed to the transport.
    pub fn drain_output(&mut self, output: &mut [u8]) -> usize {
        let count = output
            .len()
            .min(self.out_len.saturating_sub(self.out_offset));
        if let Some(buffer) = self.outbound.as_mut() {
            output[..count].copy_from_slice(&buffer[self.out_offset..self.out_offset + count]);
            // Positive out_len is published only for an encoded ClientHello
            // or a successfully sealed record (including alerts). These bytes
            // are now handed to the transport. Preserve observable clearing
            // without secret-erasure stores for already public wire bytes.
            // Seal failures, plaintext and full abort/Drop retain zeroize.
            buffer[self.out_offset..self.out_offset + count].fill(0);
        }
        self.out_offset += count;
        if self.out_len != 0 && self.out_offset == self.out_len {
            if matches!(self.outgoing, Some(Outgoing::ClientFinished)) && self.phase == 5 {
                // This transition has no failure case for a healthy private phase5.
                self.phase = client_phase_next(self.phase, 252, true, self.retried).unwrap_or(7);
            }
            self.out_len = 0;
            self.out_offset = 0;
            self.outgoing = None;
        }
        count
    }

    pub fn drive(&mut self, input: &[u8], output: &mut [u8]) -> Result<Progress, ClientError> {
        if self.out_len != 0 {
            let finished_handoff =
                self.phase == 5 && matches!(self.outgoing, Some(Outgoing::ClientFinished));
            let produced = self.drain_output(output);
            return Ok(Progress {
                consumed: 0,
                produced,
                status: if self.out_len != 0 {
                    Status::NeedOutput
                } else if finished_handoff && self.phase == 6 {
                    Status::HandshakeComplete
                } else if self.phase == 7 {
                    Status::Failed
                } else if self.write_closed && self.peer_closed {
                    Status::Closed
                } else {
                    Status::HandshakeProgress
                },
            });
        }
        if self.phase == 7 {
            return Err(ClientError::Failed);
        }
        if self.peer_closed {
            return Ok(Progress {
                consumed: 0,
                produced: 0,
                status: Status::Closed,
            });
        }
        if self.plain_kind == Some(ContentType::ApplicationData) {
            return Ok(Progress {
                consumed: 0,
                produced: 0,
                status: Status::ApplicationData,
            });
        }
        let result = if self.plain_kind == Some(ContentType::Handshake) {
            self.process_pending_handshake().map(|status| Progress {
                consumed: 0,
                produced: 0,
                status,
            })
        } else {
            self.receive_record(input)
        };
        match result {
            Ok(progress) => Ok(progress),
            Err(error) => {
                self.abort(&error);
                Err(error)
            }
        }
    }

    fn receive_record(&mut self, input: &[u8]) -> Result<Progress, ClientError> {
        let buffer = self.record.take().ok_or(ClientError::Failed)?;
        let result = (|| {
            let mut consumed = 0;
            if self.record_len < 5 {
                let count = (5 - self.record_len).min(input.len());
                buffer[self.record_len..self.record_len + count].copy_from_slice(&input[..count]);
                self.record_len += count;
                consumed += count;
                if self.record_len < 5 {
                    return Ok(Progress {
                        consumed,
                        produced: 0,
                        status: Status::NeedInput,
                    });
                }
                let kind = if buffer[0] == 23 {
                    RecordKind::Ciphertext
                } else {
                    RecordKind::Plaintext
                };
                let limit = if kind == RecordKind::Ciphertext {
                    16640
                } else {
                    16384
                };
                let Parse::Complete { value, .. } =
                    parse_header(&buffer[..5], WireLimits::new(kind, limit)?)?
                else {
                    return Err(ClientError::Failed);
                };
                if value.content_type == 23 && self.reader.is_none()
                    || value.content_type != 23 && value.content_type != 20 && self.reader.is_some()
                    || value.content_type == 20 && self.phase > 4
                {
                    return Err(ClientError::UnexpectedMessage);
                }
                self.record_target = 5 + usize::from(value.length);
            }
            let count = (self.record_target - self.record_len).min(input.len() - consumed);
            buffer[self.record_len..self.record_len + count]
                .copy_from_slice(&input[consumed..consumed + count]);
            consumed += count;
            self.record_len += count;
            if self.record_len < self.record_target {
                return Ok(Progress {
                    consumed,
                    produced: 0,
                    status: Status::NeedInput,
                });
            }
            let status = self.process_record(&buffer[..self.record_target])?;
            // This loan holds only immutable peer wire bytes. ProtectedReader
            // decrypts a copy in the separate plaintext loan; no secret is
            // written back here. Failed processing still wipes the full loan.
            buffer[..self.record_target].fill(0);
            self.record_len = 0;
            self.record_target = 0;
            Ok(Progress {
                consumed,
                produced: 0,
                status,
            })
        })();
        if result.is_err() {
            zeroize_secret(buffer);
        }
        self.record = Some(buffer);
        result
    }

    fn process_record(&mut self, record: &[u8]) -> Result<Status, ClientError> {
        if record[0] == 20 {
            if record[5..] != [1] {
                return Err(ClientError::IllegalParameter);
            }
            return Ok(Status::HandshakeProgress);
        }
        let plain = self.plaintext.take().ok_or(ClientError::Failed)?;
        let result = (|| {
            let (kind, length) = if record[0] == 23 {
                let reader = self.reader.as_mut().ok_or(ClientError::UnexpectedMessage)?;
                // No new record is admitted while previous plaintext is held.
                // Construction, completed reads/handshakes and control/error
                // paths leave the entire backing loan clean. The provider may
                // mutate only this active prefix; its untouched suffix stays zero.
                debug_assert!(plain.iter().all(|&byte| byte == 0));
                let active_len = record
                    .len()
                    .checked_sub(5)
                    .ok_or(ClientError::IllegalParameter)?;
                let active = plain
                    .get_mut(..active_len)
                    .ok_or(ClientError::BufferTooSmall)?;
                let Parse::Complete { value, .. } = reader.open(record, active)? else {
                    return Err(ClientError::Failed);
                };
                (value.content_type, value.content.len())
            } else {
                let kind = match record[0] {
                    21 => ContentType::Alert,
                    22 => ContentType::Handshake,
                    _ => return Err(ClientError::UnexpectedMessage),
                };
                plain[..record.len() - 5].copy_from_slice(&record[5..]);
                (kind, record.len() - 5)
            };
            self.plain_kind = Some(kind);
            self.plain_len = length;
            self.plain_offset = 0;
            match kind {
                ContentType::Handshake => Ok(Status::NeedWork),
                ContentType::ApplicationData => {
                    self.assembler
                        .as_mut()
                        .ok_or(ClientError::Failed)?
                        .note_other_record()?;
                    if !self.is_established() {
                        return Err(ClientError::UnexpectedMessage);
                    }
                    if length == 0 {
                        self.plain_kind = None;
                        Ok(Status::NeedInput)
                    } else {
                        Ok(Status::ApplicationData)
                    }
                }
                ContentType::Alert => {
                    if length != 2 {
                        return Err(ClientError::IllegalParameter);
                    }
                    // Error alerts terminate both directions, even with a partial
                    // handshake retained. Classify them before an interleaving
                    // error can generate a prohibited reciprocal alert.
                    if plain[1] != 0 && plain[1] != 90 {
                        return Err(ClientError::PeerAlert(plain[1]));
                    }
                    self.assembler
                        .as_mut()
                        .ok_or(ClientError::Failed)?
                        .note_other_record()?;
                    if plain[1] == 90 {
                        // user_canceled is advisory; a peer normally follows it
                        // with close_notify. The alert level is ignored in TLS1.3.
                        self.plain_kind = None;
                        zeroize_secret(plain);
                        return Ok(Status::HandshakeProgress);
                    }
                    if plain[1] != 0 || !self.is_established() {
                        return Err(ClientError::PeerAlert(plain[1]));
                    }
                    self.peer_closed = true;
                    self.reader.take();
                    self.read_secret.take();
                    self.plain_kind = None;
                    zeroize_secret(plain);
                    if !self.write_closed {
                        self.close_notify()?;
                    }
                    Ok(if self.out_len != 0 {
                        Status::NeedOutput
                    } else {
                        Status::Closed
                    })
                }
            }
        })();
        if result.is_err() || self.plain_kind.is_none() {
            zeroize_secret(plain);
        }
        self.plaintext = Some(plain);
        result
    }

    fn process_pending_handshake(&mut self) -> Result<Status, ClientError> {
        let plain = self.plaintext.take().ok_or(ClientError::Failed)?;
        let mut assembler = self.assembler.take().ok_or(ClientError::Failed)?;
        // Key-changing messages must end the physical record; explicit boundary
        // checks separate the handshake regime and application epoch zero.
        let epoch = self.read_secret.as_ref().map_or(0, |s| s.epoch());
        let result = (|| {
            let progress =
                assembler.push_fragment(&plain[self.plain_offset..self.plain_len], epoch, true)?;
            self.plain_offset += progress.consumed;
            if progress.status == HandshakeStatus::MessageReady {
                let message = assembler.message()?.ok_or(ClientError::Failed)?;
                let changes_key = matches!(message.message_type, 2 | 20 | 24);
                self.process_message(message)?;
                assembler.consume_message()?;
                if changes_key {
                    assembler.check_key_change()?;
                }
            }
            if self.plain_offset == self.plain_len {
                zeroize_secret(plain);
                self.plain_kind = None;
                self.plain_len = 0;
                self.plain_offset = 0;
            }
            Ok(if self.out_len != 0 {
                Status::NeedOutput
            } else if self.plain_kind.is_some() {
                Status::NeedWork
            } else {
                Status::HandshakeProgress
            })
        })();
        if result.is_err() {
            zeroize_secret(plain);
        }
        self.plaintext = Some(plain);
        self.assembler = Some(assembler);
        result
    }

    fn process_message(&mut self, message: Message<'_>) -> Result<(), ClientError> {
        if self.phase == 6 {
            return self.process_post_handshake(message);
        }
        let expected = match self.phase {
            0 => 2,
            1 => 8,
            2 => 11,
            3 => 15,
            4 => 20,
            _ => return Err(ClientError::UnexpectedMessage),
        };
        if message.message_type != expected {
            return Err(ClientError::UnexpectedMessage);
        }
        match message.message_type {
            2 => self.server_hello(message),
            8 => {
                let extensions = hello::parse_encrypted_extensions(message.body)?;
                let expected_alpn = if self.config.alpn.is_empty() {
                    None
                } else {
                    Some(self.config.alpn.as_slice())
                };
                if extensions.alpn != expected_alpn
                    || extensions.server_name_ack
                        && !matches!(self.reference, ServerName::DnsName(_))
                {
                    return Err(ClientError::IllegalParameter);
                }
                // supported_groups is a server capability hint, not a selected
                // group; every actual selection is checked in ServerHello/HRR.
                self.append_transcript(message.encoded)?;
                self.advance(8)
            }
            11 => {
                let mut slots = [&[][..]; 32];
                let count = hello::parse_certificate(
                    message.body,
                    &mut slots[..self.config.limits.certificates],
                )?;
                let chain: Vec<_> = slots[..count]
                    .iter()
                    .map(|der| CertificateDer::from(*der))
                    .collect();
                let verified = self.config.verifier.verify_server_certificate(
                    &chain,
                    &self.reference,
                    self.now,
                )?;
                self.verified_certificate = Some(verified.to_owned());
                self.append_transcript(message.encoded)?;
                self.advance(11)
            }
            15 => {
                let verify = hello::parse_certificate_verify(message.body)?;
                if !SIGNATURES.contains(&verify.scheme) {
                    return Err(ClientError::IllegalParameter);
                }
                let snapshot = self.transcript()?.snapshot()?;
                self.verified_certificate
                    .as_ref()
                    .ok_or(ClientError::UnexpectedMessage)?
                    .verify_certificate_verify(
                        verify.scheme,
                        snapshot.as_bytes(),
                        verify.signature,
                    )?;
                self.verified_certificate.take();
                self.append_transcript(message.encoded)?;
                self.advance(15)
            }
            20 => {
                let snapshot = self.transcript()?.snapshot()?;
                self.handshake_secrets
                    .as_ref()
                    .ok_or(ClientError::UnexpectedMessage)?
                    .server
                    .verify_finished(&self.provider, snapshot.as_bytes(), message.body)?;
                self.append_transcript(message.encoded)?;
                self.advance(20)?;
                self.finish_server_handshake()
            }
            _ => Err(ClientError::UnexpectedMessage),
        }
    }

    fn server_hello(&mut self, message: Message<'_>) -> Result<(), ClientError> {
        if self.retried
            && message.body.get(2..34)
                == Some(tls_core::transcript::HELLO_RETRY_REQUEST_RANDOM.as_slice())
        {
            return Err(ClientError::UnexpectedMessage);
        }
        let hello = hello::parse_server_hello(message.body)?;
        if !hello.session_id.is_empty() {
            return Err(ClientError::IllegalParameter);
        }
        let suite = self.choose_suite(hello.suite)?;
        if hello.is_retry {
            if client_phase_next(self.phase, 253, true, self.retried).is_none() {
                return Err(ClientError::UnexpectedMessage);
            }
            if hello
                .cookie
                .is_some_and(|cookie| cookie.len() > self.config.limits.cookie_bytes)
                || hello.selected_group.is_none() && hello.cookie.is_none()
            {
                return Err(ClientError::IllegalParameter);
            }
            if let Some(group) = hello.selected_group {
                let group = named_group(group)?;
                if self.ephemeral.as_ref().ok_or(ClientError::Failed)?.group() == group {
                    return Err(ClientError::IllegalParameter);
                }
                // Old unaccepted private share is retired before generation.
                self.ephemeral.take();
                self.ephemeral = Some(self.provider.start_key_exchange(group)?);
            }
            self.transcript()?
                .apply_hello_retry_request(message.encoded)?;
            self.advance(253)?;
            self.retried = true;
            return self.queue_hello(hello.cookie);
        }
        let share = hello.key_share.ok_or(ClientError::IllegalParameter)?;
        let ephemeral = self.ephemeral.take().ok_or(ClientError::Failed)?;
        if share.group != ephemeral.group().wire_code() {
            return Err(ClientError::IllegalParameter);
        }
        self.append_transcript(message.encoded)?;
        let snapshot = self.transcript()?.snapshot()?;
        let mut shared = [0; 32];
        let result = (|| {
            ephemeral.complete(share.key, &mut shared)?;
            Ok::<_, ClientError>(HandshakeSecrets::derive(
                &self.provider,
                suite,
                &shared,
                snapshot.as_bytes(),
            )?)
        })();
        shared.zeroize();
        let secrets = result?;
        let read = secrets.server.key_material(&self.provider)?;
        let reader = ProtectedReader::new(
            self.provider.aead_key(suite, read.key_bytes())?,
            read.iv_bytes()
                .try_into()
                .map_err(|_| ClientError::Failed)?,
            MAX_INNER_PLAINTEXT,
        )?;
        let write = secrets.client.key_material(&self.provider)?;
        let writer = ProtectedWriter::new(
            self.provider.aead_key(suite, write.key_bytes())?,
            write
                .iv_bytes()
                .try_into()
                .map_err(|_| ClientError::Failed)?,
            MAX_INNER_PLAINTEXT,
            self.config.limits.send_records_per_key,
        )?;
        self.reader = Some(reader);
        self.writer = Some(writer);
        self.handshake_secrets = Some(secrets);
        self.advance(2)
    }

    fn finish_server_handshake(&mut self) -> Result<(), ClientError> {
        let suite = self.chosen_suite.ok_or(ClientError::Failed)?;
        let snapshot = self.transcript()?.snapshot()?;
        let transition = self
            .handshake_secrets
            .take()
            .ok_or(ClientError::Failed)?
            .into_application(&self.provider, snapshot.as_bytes())?;
        let mut finished = [0; 52];
        let size = suite.hash().output_len();
        finished[..4].copy_from_slice(&[20, 0, 0, size as u8]);
        let result = (|| {
            transition.client_handshake.sign_finished(
                &self.provider,
                snapshot.as_bytes(),
                &mut finished[4..4 + size],
            )?;
            self.append_transcript(&finished[..4 + size])?;
            let read = transition.application.server.key_material(&self.provider)?;
            let reader = ProtectedReader::new(
                self.provider.aead_key(suite, read.key_bytes())?,
                read.iv_bytes()
                    .try_into()
                    .map_err(|_| ClientError::Failed)?,
                MAX_INNER_PLAINTEXT,
            )?;
            let write = transition.application.client.key_material(&self.provider)?;
            let writer = ProtectedWriter::new(
                self.provider.aead_key(suite, write.key_bytes())?,
                write
                    .iv_bytes()
                    .try_into()
                    .map_err(|_| ClientError::Failed)?,
                MAX_INNER_PLAINTEXT,
                self.config.limits.send_records_per_key,
            )?;
            self.transcript()?.freeze()?;
            self.transcript256.take();
            self.transcript384.take();
            // Complete every fallible derivation/import before consuming the
            // old write nonce. A queued Finished cannot be rolled back/replaced.
            self.seal_outgoing(
                ContentType::Handshake,
                &finished[..4 + size],
                Outgoing::ClientFinished,
            )?;
            self.reader = Some(reader);
            self.writer = Some(writer);
            Ok::<_, ClientError>(())
        })();
        finished.zeroize();
        result?;
        self.read_secret = Some(transition.application.server.into_receiving());
        self.write_secret = Some(transition.application.client.into_sending());
        // Remaining handshake/exporter owners are dropped here. No resumption or exporter API.
        Ok(())
    }

    fn process_post_handshake(&mut self, message: Message<'_>) -> Result<(), ClientError> {
        self.post_messages = self
            .post_messages
            .checked_add(1)
            .filter(|count| *count <= self.config.limits.post_handshake_messages)
            .ok_or(ClientError::ResourceLimit)?;
        match message.message_type {
            24 => {
                if message.body.len() != 1 || message.body[0] > 1 {
                    return Err(ClientError::IllegalParameter);
                }
                let next = self
                    .read_secret
                    .take()
                    .ok_or(ClientError::Failed)?
                    .update(&self.provider)?;
                let suite = self.chosen_suite.ok_or(ClientError::Failed)?;
                let material = next.key_material(&self.provider)?;
                self.reader = Some(ProtectedReader::new(
                    self.provider.aead_key(suite, material.key_bytes())?,
                    material
                        .iv_bytes()
                        .try_into()
                        .map_err(|_| ClientError::Failed)?,
                    MAX_INNER_PLAINTEXT,
                )?);
                self.read_secret = Some(next);
                if message.body[0] == 1 && !self.write_closed {
                    self.queue_key_update()?;
                }
                Ok(())
            }
            // RFC9846 section4.7.1 requires clients without resumption to silently
            // ignore NST. Reassembly already bounds its complete type/u24 frame;
            // no ticket/PSK/extension semantics or allocation are needed here.
            4 => Ok(()),
            _ => Err(ClientError::UnexpectedMessage),
        }
    }

    fn queue_key_update(&mut self) -> Result<(), ClientError> {
        if self.write_closed {
            return Err(ClientError::UnexpectedMessage);
        }
        // Prepare the next key before consuming an old-key nonce. If preparation
        // fails, a fatal alert can still use the peer's expected old sequence.
        let next = self
            .write_secret
            .take()
            .ok_or(ClientError::Failed)?
            .update(&self.provider)?;
        let suite = self.chosen_suite.ok_or(ClientError::Failed)?;
        let material = next.key_material(&self.provider)?;
        let writer = ProtectedWriter::new(
            self.provider.aead_key(suite, material.key_bytes())?,
            material
                .iv_bytes()
                .try_into()
                .map_err(|_| ClientError::Failed)?,
            MAX_INNER_PLAINTEXT,
            self.config.limits.send_records_per_key,
        )?;
        // Seal under the OLD write key; then commit the ready new key. Pending
        // output prevents any new-key application record overtaking this update.
        self.seal_outgoing(
            ContentType::Handshake,
            &[24, 0, 0, 1, 0],
            Outgoing::KeyUpdate,
        )?;
        self.writer = Some(writer);
        self.write_secret = Some(next);
        Ok(())
    }

    /// Queues up to16384 plaintext bytes. Returns zero when an automatic old-key
    /// KeyUpdate must be drained first; caller retries the same application input.
    pub fn write_plaintext(&mut self, input: &[u8]) -> Result<usize, ClientError> {
        if !self.is_established() || self.write_closed {
            return Err(ClientError::NotEstablished);
        }
        if self.out_len != 0 {
            return Err(ClientError::OutputPending);
        }
        if self.plain_kind == Some(ContentType::Handshake)
            || self
                .assembler
                .as_ref()
                .is_some_and(|a| a.buffered_len() != 0)
        {
            // Process a retained/fragmented control message first. In particular,
            // a received update_requested requires a response before later data.
            return Err(ClientError::InputPending);
        }
        if input.is_empty() {
            return Ok(0);
        }
        let result = (|| {
            if self
                .writer
                .as_ref()
                .ok_or(ClientError::Failed)?
                .next_sequence()
                >= self.config.limits.send_records_per_key - 1
            {
                self.queue_key_update()?;
                return Ok(0);
            }
            let count = input.len().min(16384);
            self.seal_outgoing(
                ContentType::ApplicationData,
                &input[..count],
                Outgoing::Application,
            )?;
            Ok(count)
        })();
        match result {
            Ok(count) => Ok(count),
            Err(error) => {
                self.abort(&error);
                Err(error)
            }
        }
    }
    pub fn read_plaintext(&mut self, output: &mut [u8]) -> Result<usize, ClientError> {
        if !self.is_established() {
            return Err(ClientError::NotEstablished);
        }
        if self.plain_kind != Some(ContentType::ApplicationData) {
            return Ok(0);
        }
        let count = output.len().min(self.plain_len - self.plain_offset);
        let plain = self.plaintext.as_mut().ok_or(ClientError::Failed)?;
        output[..count].copy_from_slice(&plain[self.plain_offset..self.plain_offset + count]);
        zeroize_secret(&mut plain[self.plain_offset..self.plain_offset + count]);
        self.plain_offset += count;
        if self.plain_offset == self.plain_len {
            // ProtectedReader cleared the entire tail on successful open;
            // every content range has now been consumed and cleared above.
            // The whole loan is already zero. Failure/Drop still wipe it fully.
            self.plain_kind = None;
            self.plain_len = 0;
            self.plain_offset = 0;
        }
        Ok(count)
    }
    pub fn close_notify(&mut self) -> Result<(), ClientError> {
        if !self.is_established() {
            return Err(ClientError::NotEstablished);
        }
        if self.write_closed {
            return Ok(());
        }
        if self.out_len != 0 {
            return Err(ClientError::OutputPending);
        }
        let result = self.seal_outgoing(ContentType::Alert, &[1, 0], Outgoing::Close);
        match result {
            Ok(()) => {
                self.write_closed = true;
                self.writer.take();
                self.write_secret.take();
                Ok(())
            }
            Err(error) => {
                self.abort(&error);
                Err(error)
            }
        }
    }
    pub fn finish_input(&mut self) -> Result<(), ClientError> {
        if self.phase == 7 {
            return Err(ClientError::Failed);
        }
        if self.record_len == 0 && self.peer_closed {
            self.assembler
                .as_mut()
                .ok_or(ClientError::Failed)?
                .finish_input()?;
            return Ok(());
        }
        let error = ClientError::Truncated;
        self.abort(&error);
        Err(error)
    }

    fn abort(&mut self, error: &ClientError) {
        // Error is returned with its typed provider/PKI cause. Alert transmission
        // is best effort and never resurrects a failed connection or key owner.
        let alert = match error {
            ClientError::UnexpectedMessage => 10,
            ClientError::IllegalParameter => 47,
            ClientError::Codec(
                CodecError::InvalidParameter
                | CodecError::InvalidName
                | CodecError::DuplicateExtension,
            ) => 47,
            ClientError::Codec(CodecError::UnsupportedExtension) => 110,
            ClientError::Codec(CodecError::MissingExtension) => 109,
            ClientError::Handshake(
                HandshakeError::UnexpectedType
                | HandshakeError::EpochChanged
                | HandshakeError::MisalignedKeyChange
                | HandshakeError::InterleavedRecord,
            ) => 10,
            ClientError::Codec(_) | ClientError::Handshake(_) | ClientError::Truncated => 50,
            ClientError::Pki(_) if self.phase == 3 => 51,
            ClientError::Schedule(_) if self.phase == 4 => 51,
            ClientError::Pki(_) => 42,
            ClientError::Core(tls_core::Error::RecordOverflow)
            | ClientError::Protected(ProtectedError::Wire(tls_core::Error::RecordOverflow)) => 22,
            ClientError::Protected(ProtectedError::InvalidInner) => 10,
            ClientError::Crypto(CryptoError::InvalidKey | CryptoError::InvalidLength) => 47,
            ClientError::Crypto(
                CryptoError::BackendFailure
                | CryptoError::EntropyUnavailable
                | CryptoError::UnsupportedAlgorithm,
            ) => 80,
            ClientError::Core(_) | ClientError::Crypto(_) | ClientError::Protected(_) => 20,
            _ => 80,
        };
        // Reentrant failure paths may restore temporary caller buffers after an
        // earlier abort. Preserve an already queued alert while wiping them too.
        if self.phase != 7 {
            let had_pending_output = self.out_len != 0;
            if let Some(output) = self.outbound.as_mut() {
                zeroize_secret(output);
            }
            self.out_len = 0;
            self.out_offset = 0;
            self.outgoing = None;
            if matches!(error, ClientError::PeerAlert(_)) || had_pending_output {
                // RFC9846 section6: receiving an error alert terminates sending;
                // do not generate a reciprocal alert. Discarding queued/partial
                // wire also makes further alerts unsafe: the nonce/record bytes
                // already consumed cannot be rewound. Retire the direction.
            } else if self.writer.is_some() && !self.write_closed {
                let _ = self.seal_outgoing(ContentType::Alert, &[2, alert], Outgoing::Fatal);
            } else if self.reader.is_none()
                && self.phase == 0
                && let Some(output) = self.outbound.as_mut()
            {
                output[..7].copy_from_slice(&[21, 3, 3, 0, 2, 2, alert]);
                self.out_len = 7;
                self.outgoing = Some(Outgoing::Fatal);
            }
        }
        self.phase = client_phase_next(self.phase, 255, false, self.retried).unwrap_or(7);
        self.reader.take();
        self.writer.take();
        self.ephemeral.take();
        self.handshake_secrets.take();
        self.read_secret.take();
        self.write_secret.take();
        self.verified_certificate.take();
        self.transcript256.take();
        self.transcript384.take();
        self.assembler.take();
        if let Some(buffer) = self.record.as_mut() {
            zeroize_secret(buffer);
        }
        if let Some(buffer) = self.plaintext.as_mut() {
            zeroize_secret(buffer);
        }
        self.plain_kind = None;
        self.plain_len = 0;
        self.plain_offset = 0;
        self.record_len = 0;
        self.record_target = 0;
    }
}

impl<P: KeyExchangeProvider> Drop for ClientConnection<'_, P> {
    fn drop(&mut self) {
        if let Some(buffer) = self.record.as_mut() {
            zeroize_secret(buffer);
        }
        if let Some(buffer) = self.plaintext.as_mut() {
            zeroize_secret(buffer);
        }
        if let Some(buffer) = self.outbound.as_mut() {
            zeroize_secret(buffer);
        }
        // Reassembler/secret/provider owners also retire through their own Drop.
    }
}

#[cfg(test)]
mod read_wiping_unit;

#[cfg(test)]
mod wire_wiping_unit;

#[cfg(test)]
mod secret_wiping_unit;
