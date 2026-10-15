//! Allocation-free syntactic TLS 1.3 hello and server-authentication codecs.
//! These views confer no authentication. Endpoint negotiation, provider key
//! validation, PKI, transcript ordering and resource policy remain mandatory.
use crate::transcript::HELLO_RETRY_REQUEST_RANDOM;

pub const MAX_OFFERED_CODES: usize = 64;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CodecError {
    Truncated,
    InvalidLength,
    InvalidParameter,
    InvalidName,
    UnsupportedExtension,
    DuplicateExtension,
    MissingExtension,
    BufferTooSmall,
}

pub struct ClientHelloParams<'a> {
    pub random: &'a [u8; 32],
    pub session_id: &'a [u8],
    pub server_name: Option<&'a [u8]>,
    /// Empty omits ALPN; otherwise one opaque protocol of at most255 bytes.
    pub alpn: &'a [u8],
    pub suites: &'a [u16],
    pub groups: &'a [u16],
    pub signatures: &'a [u16],
    pub key_share_group: u16,
    pub key_share: &'a [u8],
    pub cookie: Option<&'a [u8]>,
}

struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}
impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }
    fn take(&mut self, length: usize) -> Result<&'a [u8], CodecError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(CodecError::InvalidLength)?;
        let out = self
            .bytes
            .get(self.offset..end)
            .ok_or(CodecError::Truncated)?;
        self.offset = end;
        Ok(out)
    }
    fn u8(&mut self) -> Result<u8, CodecError> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16, CodecError> {
        let b = self.take(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }
    fn u24(&mut self) -> Result<usize, CodecError> {
        let b = self.take(3)?;
        Ok((usize::from(b[0]) << 16) | (usize::from(b[1]) << 8) | usize::from(b[2]))
    }
    fn vec8(&mut self) -> Result<&'a [u8], CodecError> {
        let n = usize::from(self.u8()?);
        self.take(n)
    }
    fn vec16(&mut self) -> Result<&'a [u8], CodecError> {
        let n = usize::from(self.u16()?);
        self.take(n)
    }
    fn vec24(&mut self) -> Result<&'a [u8], CodecError> {
        let n = self.u24()?;
        self.take(n)
    }
    fn remaining(&self) -> usize {
        self.bytes.len() - self.offset
    }
    fn finish(&self) -> Result<(), CodecError> {
        if self.remaining() == 0 {
            Ok(())
        } else {
            Err(CodecError::InvalidLength)
        }
    }
}
struct Writer<'a> {
    bytes: &'a mut [u8],
    offset: usize,
}
impl Writer<'_> {
    fn put(&mut self, bytes: &[u8]) -> Result<(), CodecError> {
        let end = self
            .offset
            .checked_add(bytes.len())
            .ok_or(CodecError::InvalidLength)?;
        self.bytes
            .get_mut(self.offset..end)
            .ok_or(CodecError::BufferTooSmall)?
            .copy_from_slice(bytes);
        self.offset = end;
        Ok(())
    }
    fn u8(&mut self, n: usize) -> Result<(), CodecError> {
        self.put(&[u8::try_from(n).map_err(|_| CodecError::InvalidLength)?])
    }
    fn u16(&mut self, n: usize) -> Result<(), CodecError> {
        self.put(
            &u16::try_from(n)
                .map_err(|_| CodecError::InvalidLength)?
                .to_be_bytes(),
        )
    }
    fn u24(&mut self, n: usize) -> Result<(), CodecError> {
        if n > 0xff_ffff {
            return Err(CodecError::InvalidLength);
        }
        self.put(&[
            ((n >> 16) & 255) as u8,
            ((n >> 8) & 255) as u8,
            (n & 255) as u8,
        ])
    }
    fn extension(&mut self, kind: u16, size: usize) -> Result<(), CodecError> {
        self.u16(usize::from(kind))?;
        self.u16(size)
    }
    fn codes(&mut self, codes: &[u16]) -> Result<(), CodecError> {
        self.u16(codes.len() * 2)?;
        for &code in codes {
            self.u16(usize::from(code))?;
        }
        Ok(())
    }
}
fn codes_valid(codes: &[u16]) -> bool {
    !codes.is_empty()
        && codes.len() <= MAX_OFFERED_CODES
        && codes
            .iter()
            .enumerate()
            .all(|(i, code)| !codes[..i].contains(code))
}
fn dns_name(name: &[u8]) -> bool {
    if name.is_empty() || name.len() > 253 {
        return false;
    }
    for label in name.split(|&b| b == b'.') {
        if label.is_empty()
            || label.len() > 63
            || label[0] == b'-'
            || label[label.len() - 1] == b'-'
            || !label
                .iter()
                .all(|b| b.is_ascii_alphanumeric() || *b == b'-')
        {
            return false;
        }
    }
    // RFC6066 forbids literal IP addresses in host_name. IPv6 fails LDH syntax;
    // detect dotted-decimal IPv4 without allocating or parsing identity/PKI.
    let mut parts = 0;
    let mut all_ip = true;
    for part in name.split(|&b| b == b'.') {
        parts += 1;
        if part.len() > 3 || !part.iter().all(u8::is_ascii_digit) {
            all_ip = false;
            continue;
        }
        let mut value = 0_u16;
        for &digit in part {
            value = value * 10 + u16::from(digit - b'0');
        }
        if value > 255 {
            all_ip = false;
        }
    }
    !(all_ip && parts == 4)
}

/// Complete ClientHello handshake encoding, with TLS1.3 versions/groups/signatures
/// and a single share; no PSK, early_data, tickets, compression or insecure fallback.
/// Invalid parameters/output shortage leave output unchanged. Provider-supported
/// algorithm codes, random generation, share validation/freshness are caller policy.
pub fn encode_client_hello(
    params: &ClientHelloParams<'_>,
    output: &mut [u8],
) -> Result<usize, CodecError> {
    if params.session_id.len() > 32
        || params.alpn.len() > 255
        || !codes_valid(params.suites)
        || !codes_valid(params.groups)
        || !codes_valid(params.signatures)
        || !params.groups.contains(&params.key_share_group)
        || params.key_share.is_empty()
        || params.key_share.len() > 65529
    {
        return Err(CodecError::InvalidParameter);
    }
    if params.server_name.is_some_and(|name| !dns_name(name)) {
        return Err(CodecError::InvalidName);
    }
    if params
        .cookie
        .is_some_and(|cookie| cookie.is_empty() || cookie.len() > 65533)
    {
        return Err(CodecError::InvalidParameter);
    }
    let mut extensions = 7
        + 6
        + params.groups.len() * 2
        + 6
        + params.signatures.len() * 2
        + 10
        + params.key_share.len();
    if let Some(name) = params.server_name {
        extensions += 9 + name.len();
    }
    if !params.alpn.is_empty() {
        extensions += 7 + params.alpn.len();
    }
    if let Some(cookie) = params.cookie {
        extensions += 6 + cookie.len();
    }
    if extensions > 65535 {
        return Err(CodecError::InvalidLength);
    }
    let body_len = 41 + params.session_id.len() + params.suites.len() * 2 + extensions;
    let total = body_len + 4;
    if output.len() < total {
        return Err(CodecError::BufferTooSmall);
    }
    let mut writer = Writer {
        bytes: &mut output[..total],
        offset: 0,
    };
    writer.u8(1)?;
    writer.u24(body_len)?;
    writer.u16(0x0303)?;
    writer.put(params.random)?;
    writer.u8(params.session_id.len())?;
    writer.put(params.session_id)?;
    writer.codes(params.suites)?;
    writer.put(&[1, 0])?;
    writer.u16(extensions)?;
    writer.extension(43, 3)?;
    writer.put(&[2, 3, 4])?;
    writer.extension(10, 2 + params.groups.len() * 2)?;
    writer.codes(params.groups)?;
    writer.extension(13, 2 + params.signatures.len() * 2)?;
    writer.codes(params.signatures)?;
    writer.extension(51, 6 + params.key_share.len())?;
    writer.u16(4 + params.key_share.len())?;
    writer.u16(usize::from(params.key_share_group))?;
    writer.u16(params.key_share.len())?;
    writer.put(params.key_share)?;
    if let Some(name) = params.server_name {
        writer.extension(0, 5 + name.len())?;
        writer.u16(3 + name.len())?;
        writer.u8(0)?;
        writer.u16(name.len())?;
        writer.put(name)?;
    }
    if !params.alpn.is_empty() {
        writer.extension(16, 3 + params.alpn.len())?;
        writer.u16(1 + params.alpn.len())?;
        writer.u8(params.alpn.len())?;
        writer.put(params.alpn)?;
    }
    if let Some(cookie) = params.cookie {
        writer.extension(44, 2 + cookie.len())?;
        writer.u16(cookie.len())?;
        writer.put(cookie)?;
    }
    Ok(writer.offset)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KeyShare<'a> {
    pub group: u16,
    pub key: &'a [u8],
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ServerHello<'a> {
    pub random: &'a [u8; 32],
    pub session_id: &'a [u8],
    pub suite: u16,
    pub is_retry: bool,
    pub key_share: Option<KeyShare<'a>>,
    pub selected_group: Option<u16>,
    pub cookie: Option<&'a [u8]>,
}
fn seen(mask: &mut u8, bit: u8) -> Result<(), CodecError> {
    if *mask & bit != 0 {
        return Err(CodecError::DuplicateExtension);
    }
    *mask |= bit;
    Ok(())
}
/// Parse a complete ServerHello body; version selection comes solely from the
/// required0304 supported_versions, legacy_version ignored perRFC9846§4.3.1.
/// Only43/51 are supported normally; HRR additionally permits44cookie. Cookie-only
/// HRR is accepted; endpoint checks retry policy/offered values/session equality.
pub fn parse_server_hello(body: &[u8]) -> Result<ServerHello<'_>, CodecError> {
    let mut reader = Reader::new(body);
    let _legacy = reader.u16()?;
    let random: &[u8; 32] = reader
        .take(32)?
        .try_into()
        .map_err(|_| CodecError::InvalidLength)?;
    let session_id = reader.vec8()?;
    if session_id.len() > 32 {
        return Err(CodecError::InvalidParameter);
    }
    let suite = reader.u16()?;
    if reader.u8()? != 0 {
        return Err(CodecError::InvalidParameter);
    }
    let extensions = reader.vec16()?;
    reader.finish()?;
    let is_retry = *random == HELLO_RETRY_REQUEST_RANDOM;
    let mut result = ServerHello {
        random,
        session_id,
        suite,
        is_retry,
        key_share: None,
        selected_group: None,
        cookie: None,
    };
    let mut mask = 0;
    let mut ext = Reader::new(extensions);
    while ext.remaining() != 0 {
        let kind = ext.u16()?;
        let data = ext.vec16()?;
        let mut value = Reader::new(data);
        match kind {
            43 => {
                seen(&mut mask, 1)?;
                if value.u16()? != 0x0304 {
                    return Err(CodecError::InvalidParameter);
                }
            }
            51 => {
                seen(&mut mask, 2)?;
                let group = value.u16()?;
                if is_retry {
                    result.selected_group = Some(group);
                } else {
                    let key = value.vec16()?;
                    if key.is_empty() {
                        return Err(CodecError::InvalidLength);
                    }
                    result.key_share = Some(KeyShare { group, key });
                }
            }
            44 if is_retry => {
                seen(&mut mask, 4)?;
                let cookie = value.vec16()?;
                if cookie.is_empty() {
                    return Err(CodecError::InvalidLength);
                }
                result.cookie = Some(cookie);
            }
            _ => return Err(CodecError::UnsupportedExtension),
        }
        value.finish()?;
    }
    if mask & 1 == 0
        || (!is_retry && result.key_share.is_none())
        || (is_retry && result.selected_group.is_none() && result.cookie.is_none())
    {
        return Err(CodecError::MissingExtension);
    }
    Ok(result)
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EncryptedExtensions<'a> {
    pub alpn: Option<&'a [u8]>,
    pub server_name_ack: bool,
    /// Borrowed big-endian u16 vector, without its length prefix. These are
    /// server preference hints; endpoint validates extension offer and policy.
    pub supported_groups: Option<&'a [u8]>,
}
pub fn parse_encrypted_extensions(body: &[u8]) -> Result<EncryptedExtensions<'_>, CodecError> {
    let mut reader = Reader::new(body);
    let extensions = reader.vec16()?;
    reader.finish()?;
    let mut result = EncryptedExtensions {
        alpn: None,
        server_name_ack: false,
        supported_groups: None,
    };
    let mut ext = Reader::new(extensions);
    let mut mask = 0;
    while ext.remaining() != 0 {
        let kind = ext.u16()?;
        let data = ext.vec16()?;
        let mut value = Reader::new(data);
        match kind {
            0 => {
                seen(&mut mask, 1)?;
                result.server_name_ack = true;
            }
            16 => {
                seen(&mut mask, 2)?;
                let names = value.vec16()?;
                let mut names = Reader::new(names);
                let name = names.vec8()?;
                if name.is_empty() {
                    return Err(CodecError::InvalidLength);
                }
                names.finish()?;
                result.alpn = Some(name);
            }
            10 => {
                seen(&mut mask, 4)?;
                let groups = value.vec16()?;
                if groups.is_empty() || !groups.len().is_multiple_of(2) {
                    return Err(CodecError::InvalidLength);
                }
                result.supported_groups = Some(groups);
            }
            _ => return Err(CodecError::UnsupportedExtension),
        }
        value.finish()?;
    }
    Ok(result)
}

fn certificates_pass<'a>(
    body: &'a [u8],
    mut slots: Option<&mut [&'a [u8]]>,
    capacity: usize,
) -> Result<usize, CodecError> {
    let mut reader = Reader::new(body);
    if !reader.vec8()?.is_empty() {
        return Err(CodecError::InvalidParameter);
    }
    let list = reader.vec24()?;
    reader.finish()?;
    if list.is_empty() {
        return Err(CodecError::InvalidLength);
    }
    let mut list = Reader::new(list);
    let mut count = 0;
    while list.remaining() != 0 {
        if count >= capacity {
            return Err(CodecError::BufferTooSmall);
        }
        let certificate = list.vec24()?;
        if certificate.is_empty() {
            return Err(CodecError::InvalidLength);
        }
        if !list.vec16()?.is_empty() {
            return Err(CodecError::UnsupportedExtension);
        }
        if let Some(storage) = slots.as_mut() {
            storage[count] = certificate;
        }
        count += 1;
    }
    Ok(count)
}
/// Server certificate list into caller reference slots. Empty chain/context and
/// all certificate-entry extensions are rejected in this no-status/SCT-offer
/// profile. Bytes stay borrowed; DER/PKIX validation is a maintained verifier job.
/// Slots are cleared on every error, and remain empty until full first-pass
/// validation succeeds. Handshake-byte cap and configured slot count bound work.
pub fn parse_certificate<'a>(
    body: &'a [u8],
    certificates: &mut [&'a [u8]],
) -> Result<usize, CodecError> {
    certificates.fill(&[]);
    let count = certificates_pass(body, None, certificates.len())?;
    match certificates_pass(body, Some(certificates), count) {
        Ok(count) => Ok(count),
        Err(error) => {
            certificates.fill(&[]);
            Err(error)
        }
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CertificateVerify<'a> {
    pub scheme: u16,
    pub signature: &'a [u8],
}
pub fn parse_certificate_verify(body: &[u8]) -> Result<CertificateVerify<'_>, CodecError> {
    let mut reader = Reader::new(body);
    let scheme = reader.u16()?;
    let signature = reader.vec16()?;
    if signature.is_empty() {
        return Err(CodecError::InvalidLength);
    }
    reader.finish()?;
    Ok(CertificateVerify { scheme, signature })
}
