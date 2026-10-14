//! Caller-buffer TLS 1.3 AEAD record components (RFC 9846 §§5.2–5.5).
//!
//! These components authenticate records under caller-installed traffic keys;
//! they do not authenticate peer identity, run a handshake, or handle KeyUpdate.
//! An endpoint must dispatch permitted unencrypted CCS before calling `open`.
use crate::Error;
use crate::counter::{ReadCounter, WriteCounter};
use crate::wire::{HEADER_LEN, Limits, MAX_PLAINTEXT, Parse, RecordKind, parse_record};
use tls_crypto::{AeadKey, CryptoError, NONCE_LEN, TAG_LEN};
use zeroize::Zeroize;

pub const MAX_INNER_PLAINTEXT: usize = MAX_PLAINTEXT + 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ContentType {
    Alert = 21,
    Handshake = 22,
    ApplicationData = 23,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProtectedError {
    Wire(Error),
    Crypto(CryptoError),
    InvalidInner,
    InvalidLimit,
    ProviderLength,
    Exhausted,
    Failed,
    BufferTooSmall,
}

/// Pure size guard. The cap includes the inner type byte and zero padding.
/// Negotiation of RFC 8449 record_size_limit remains an endpoint responsibility.
// Explicit matches keep Aeneas extraction free of unsupported Option Try calls.
#[allow(clippy::question_mark)]
pub fn inner_length(content_len: usize, padding_len: usize, inner_limit: usize) -> Option<usize> {
    if inner_limit == 0 || inner_limit > MAX_INNER_PLAINTEXT {
        return None;
    }
    let Some(with_type) = content_len.checked_add(1) else {
        return None;
    };
    let Some(length) = with_type.checked_add(padding_len) else {
        return None;
    };
    if length > inner_limit {
        None
    } else {
        Some(length)
    }
}

/// Allowed protected content and structural content lengths. This guard does
/// not authenticate a byte string or validate message bodies/handshake states.
pub fn valid_content_type(content_type: u8, content_len: usize) -> bool {
    match content_type {
        21 => content_len == 2,
        22 => content_len != 0,
        23 => true,
        _ => false,
    }
}

fn validate_limit(limit: usize) -> Result<(), ProtectedError> {
    if limit == 0 || limit > MAX_INNER_PLAINTEXT {
        Err(ProtectedError::InvalidLimit)
    } else {
        Ok(())
    }
}

fn nonce_for(iv: &[u8; NONCE_LEN], sequence: u64) -> [u8; NONCE_LEN] {
    let mut nonce = *iv;
    for (byte, sequence_byte) in nonce[4..].iter_mut().zip(sequence.to_be_bytes()) {
        *byte ^= sequence_byte;
    }
    nonce
}

/// Erase caller bytes with aligned u128 stores, as `Reassembler::drop` does.
fn wipe(bytes: &mut [u8]) {
    let (head, words, tail) = bytemuck::pod_align_to_mut::<u8, u128>(bytes);
    head.zeroize();
    words.zeroize();
    tail.zeroize();
}

/// Index of the last nonzero byte. Zero blocks are skipped from the end, so long
/// padding costs one comparison per block. Same result as `rposition(|&b| b != 0)`.
const SCAN_BLOCK: usize = 64;

fn last_nonzero(bytes: &[u8]) -> Option<usize> {
    let mut end = bytes.len();
    while end >= SCAN_BLOCK && bytes[end - SCAN_BLOCK..end] == [0u8; SCAN_BLOCK] {
        end -= SCAN_BLOCK;
    }
    bytes[..end].iter().rposition(|&byte| byte != 0)
}

fn decode_inner(inner: &[u8], limit: usize) -> Result<(ContentType, usize), ProtectedError> {
    if inner.is_empty() || inner.len() > limit {
        return Err(ProtectedError::InvalidInner);
    }
    let index = last_nonzero(inner).ok_or(ProtectedError::InvalidInner)?;
    if !valid_content_type(inner[index], index) {
        return Err(ProtectedError::InvalidInner);
    }
    let content_type = match inner[index] {
        21 => ContentType::Alert,
        22 => ContentType::Handshake,
        23 => ContentType::ApplicationData,
        _ => return Err(ProtectedError::InvalidInner),
    };
    Ok((content_type, index))
}

/// Connection-owned sending traffic key and IV; neither Clone nor Debug.
/// Caller buffer shortages and invalid local content do not consume a nonce.
/// Crypto failure, provider contract violation and exhausted keys are terminal;
/// they immediately drop the owned key and erase the static IV.
/// Reserved nonces are retired before calling the provider, even on failure.
/// Fresh key installation/rotation is deliberately not exposed in this milestone.
/// Choose a stricter record cap if needed; never above the suite's sending cap.
pub struct ProtectedWriter<K: AeadKey> {
    key: Option<K>,
    iv: [u8; NONCE_LEN],
    counter: WriteCounter,
    inner_limit: usize,
    failed: bool,
}

impl<K: AeadKey> ProtectedWriter<K> {
    pub fn new(
        key: K,
        mut iv: [u8; NONCE_LEN],
        inner_limit: usize,
        record_limit: u64,
    ) -> Result<Self, ProtectedError> {
        if validate_limit(inner_limit).is_err()
            || record_limit == 0
            || record_limit > key.suite().sending_record_limit()
        {
            iv.zeroize();
            return Err(ProtectedError::InvalidLimit);
        }
        let counter = WriteCounter::new(record_limit).map_err(ProtectedError::Wire)?;
        Ok(Self {
            key: Some(key),
            iv,
            counter,
            inner_limit,
            failed: false,
        })
    }

    pub const fn next_sequence(&self) -> u64 {
        self.counter.next_sequence()
    }
    pub const fn is_failed(&self) -> bool {
        self.failed
    }

    fn fail<T>(&mut self, output: &mut [u8], error: ProtectedError) -> Result<T, ProtectedError> {
        self.failed = true;
        wipe(output);
        self.iv.zeroize();
        drop(self.key.take());
        Err(error)
    }

    /// Serialize and protect exactly one record. Output tail after the returned
    /// wire length is untouched on success; terminal errors wipe all output.
    /// Preflight errors leave output and sequence untouched. Padding is zeroed.
    pub fn seal(
        &mut self,
        content_type: ContentType,
        content: &[u8],
        padding: usize,
        output: &mut [u8],
    ) -> Result<usize, ProtectedError> {
        if self.failed {
            return self.fail(output, ProtectedError::Failed);
        }
        if !valid_content_type(content_type as u8, content.len()) {
            return Err(ProtectedError::InvalidInner);
        }
        let inner_len = inner_length(content.len(), padding, self.inner_limit)
            .ok_or(ProtectedError::InvalidInner)?;
        let cipher_len = inner_len + TAG_LEN; // bounded by 16,385 + fixed tag
        let wire_len = HEADER_LEN + cipher_len;
        if output.len() < wire_len {
            return Err(ProtectedError::BufferTooSmall);
        }
        let reservation = match self.counter.reserve() {
            Ok(value) => value,
            Err(_) => {
                return self.fail(output, ProtectedError::Exhausted);
            }
        };
        let mut nonce = nonce_for(&self.iv, reservation.sequence());
        let mut aad = [0; HEADER_LEN];
        aad[0] = 23;
        aad[1..3].copy_from_slice(&0x0303_u16.to_be_bytes());
        aad[3..].copy_from_slice(&(cipher_len as u16).to_be_bytes());
        output[..HEADER_LEN].copy_from_slice(&aad);
        let body = &mut output[HEADER_LEN..wire_len];
        body[..content.len()].copy_from_slice(content);
        body[content.len()] = content_type as u8;
        body[content.len() + 1..].fill(0);
        let result = match self.key.as_ref() {
            Some(key) => key.seal_in_place(&nonce, &aad, body, inner_len),
            None => Err(CryptoError::BackendFailure),
        };
        nonce.zeroize();
        let error = match result {
            Ok(length) if length == cipher_len => return Ok(wire_len),
            Ok(_) => ProtectedError::ProviderLength,
            Err(error) => ProtectedError::Crypto(error),
        };
        self.fail(output, error)
    }
}

impl<K: AeadKey> Drop for ProtectedWriter<K> {
    fn drop(&mut self) {
        self.iv.zeroize();
    }
}

/// Successfully authenticated and structurally validated inner content.
/// This is authentication under the supplied key, not verified server identity;
/// a real endpoint must still apply handshake/authentication release policy.
/// No Debug formatter is provided for the plaintext.
pub struct OpenedRecord<'a> {
    pub content_type: ContentType,
    pub content: &'a [u8],
}

/// Separately owned receiving key/IV. No sending-specific GCM usage limit is
/// imposed on receiving. Counters conservatively stop before sequence wrap.
/// Invalid wire, failed AEAD, invalid inner content and exhaustion are terminal;
/// terminal errors drop the owned key, erase its IV and wipe the entire supplied
/// plaintext buffer. Partial input and
/// output shortages do not reserve a nonce. No rotation/reset API is exposed.
pub struct ProtectedReader<K: AeadKey> {
    key: Option<K>,
    iv: [u8; NONCE_LEN],
    counter: ReadCounter,
    inner_limit: usize,
    failed: bool,
}

impl<K: AeadKey> ProtectedReader<K> {
    pub fn new(
        key: K,
        mut iv: [u8; NONCE_LEN],
        inner_limit: usize,
    ) -> Result<Self, ProtectedError> {
        if validate_limit(inner_limit).is_err() {
            iv.zeroize();
            return Err(ProtectedError::InvalidLimit);
        }
        let counter = ReadCounter::new(u64::MAX).map_err(ProtectedError::Wire)?;
        Ok(Self {
            key: Some(key),
            iv,
            counter,
            inner_limit,
            failed: false,
        })
    }

    pub const fn next_sequence(&self) -> u64 {
        self.counter.next_sequence()
    }
    pub const fn is_failed(&self) -> bool {
        self.failed
    }

    fn fail<T>(&mut self, output: &mut [u8], error: ProtectedError) -> Result<T, ProtectedError> {
        self.failed = true;
        wipe(output);
        self.iv.zeroize();
        drop(self.key.take());
        Err(error)
    }

    /// Open the first complete wire record; report its consumed length so the
    /// caller can retain coalesced trailing records. Copy ciphertext into caller
    /// storage, then authenticate in place. No borrowed content is returned
    /// until AEAD and all inner checks succeed. Incomplete input is untouched.
    pub fn open<'a>(
        &mut self,
        input: &[u8],
        output: &'a mut [u8],
    ) -> Result<Parse<OpenedRecord<'a>>, ProtectedError> {
        if self.failed {
            return self.fail(output, ProtectedError::Failed);
        }
        let limits = Limits::new(RecordKind::Ciphertext, self.inner_limit + TAG_LEN)
            .map_err(ProtectedError::Wire)?;
        let (record, consumed) = match parse_record(input, limits) {
            Ok(Parse::Incomplete { needed }) => return Ok(Parse::Incomplete { needed }),
            Ok(Parse::Complete { value, consumed }) => (value, consumed),
            Err(error) => return self.fail(output, ProtectedError::Wire(error)),
        };
        if record.payload.len() <= TAG_LEN {
            return self.fail(output, ProtectedError::InvalidInner);
        }
        if output.len() < record.payload.len() {
            return Err(ProtectedError::BufferTooSmall);
        }
        let reservation = match self.counter.reserve() {
            Ok(value) => value,
            Err(_) => return self.fail(output, ProtectedError::Exhausted),
        };
        let mut nonce = nonce_for(&self.iv, reservation.sequence());
        let cipher_len = record.payload.len();
        output[..cipher_len].copy_from_slice(record.payload);
        let result = match self.key.as_ref() {
            Some(key) => key.open_in_place(&nonce, &input[..HEADER_LEN], &mut output[..cipher_len]),
            None => Err(CryptoError::BackendFailure),
        };
        nonce.zeroize();
        let inner_len = match result {
            Ok(length) if length == cipher_len - TAG_LEN => length,
            Ok(_) => return self.fail(output, ProtectedError::ProviderLength),
            Err(error) => return self.fail(output, ProtectedError::Crypto(error)),
        };
        let (content_type, content_len) = match decode_inner(&output[..inner_len], self.inner_limit)
        {
            Ok(value) => value,
            Err(error) => return self.fail(output, error),
        };
        // Erase type, padding, decrypted trailing tag, and unused caller scratch.
        wipe(&mut output[content_len..]);
        Ok(Parse::Complete {
            value: OpenedRecord {
                content_type,
                content: &output[..content_len],
            },
            consumed,
        })
    }
}

impl<K: AeadKey> Drop for ProtectedReader<K> {
    fn drop(&mut self) {
        self.iv.zeroize();
    }
}

#[cfg(test)]
mod equivalence {
    use super::*;

    #[test]
    fn wipe_zeroes_exact_range() {
        for offset in 0..32 {
            for size in (0..=257).chain([1_023, 1_024, 1_025, 16_383, 16_384, 16_385]) {
                let start = 16 + offset;
                let mut data = [0xa5u8; 16_512];
                let mut expected = [0xa5u8; 16_512];
                expected[start..start + size].fill(0);
                wipe(&mut data[start..start + size]);
                assert!(data == expected, "size={size} offset={offset}");
            }
        }
    }

    #[test]
    fn last_nonzero_matches_rposition() {
        let mut state = 0x9E37_79B9_7F4A_7C15_u64;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        let mut bytes = [0u8; 16_385];
        for len in (0..=300).chain([1_023, 1_024, 4_095, 16_383, 16_384, 16_385]) {
            assert_eq!(last_nonzero(&bytes[..len]), None, "zeros len={len}");
            let step = if len <= 300 { 1 } else { 97 };
            for pos in (0..len).step_by(step) {
                bytes[pos] = 1;
                assert_eq!(
                    last_nonzero(&bytes[..len]),
                    bytes[..len].iter().rposition(|&b| b != 0),
                    "single len={len} pos={pos}"
                );
                bytes[pos] = 0;
            }
            for _ in 0..64 {
                bytes[..len].fill(0);
                if len > 0 {
                    for _ in 0..(next() % 8) {
                        let pos = (next() as usize) % len;
                        bytes[pos] = (next() as u8) | 1;
                    }
                }
                assert_eq!(
                    last_nonzero(&bytes[..len]),
                    bytes[..len].iter().rposition(|&b| b != 0),
                    "random len={len}"
                );
            }
            bytes[..len].fill(0);
        }
    }
}
