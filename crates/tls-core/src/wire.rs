//! Pure record-header codec (RFC 9846 §§5.1–5.2).
use crate::Error;

pub const HEADER_LEN: usize = 5;
pub const MAX_PLAINTEXT: usize = 16_384;
pub const MAX_CIPHERTEXT: usize = 16_640;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecordKind {
    Plaintext,
    Ciphertext,
}

/// Caller-selected stricter wire-body limit; never above the protocol maximum.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Limits {
    kind: RecordKind,
    max_payload: usize,
}

impl Limits {
    pub fn new(kind: RecordKind, max_payload: usize) -> Result<Self, Error> {
        let maximum = match kind {
            RecordKind::Plaintext => MAX_PLAINTEXT,
            RecordKind::Ciphertext => MAX_CIPHERTEXT,
        };
        if max_payload > maximum {
            return Err(Error::InvalidLimit);
        }
        Ok(Self { kind, max_payload })
    }

    pub const fn max_payload(self) -> usize {
        self.max_payload
    }

    pub const fn kind(self) -> RecordKind {
        self.kind
    }

    pub const fn max_wire_size(self) -> usize {
        HEADER_LEN + self.max_payload
    }
}

/// This validates outer syntax only; it does not authorize record types in any
/// handshake state, check alert values/CCS body, or validate an AEAD tag.
/// A ciphertext header intentionally rejects CCS, which is not ciphertext. A
/// future endpoint must dispatch and drop permitted unencrypted CCS before
/// attempting ciphertext deprotection (RFC 9846 §5), checking its body and the
/// handshake window in which it is permitted.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Header {
    pub content_type: u8,
    pub legacy_version: u16,
    pub length: u16,
}

impl Header {
    pub fn validate(self, limits: Limits) -> Result<Self, Error> {
        if usize::from(self.length) > limits.max_payload {
            return Err(Error::RecordOverflow);
        }
        match limits.kind {
            RecordKind::Plaintext => match self.content_type {
                20 if self.length == 1 => {}
                21 if self.length == 2 => {}
                22 if self.length != 0 => {}
                20..=22 => return Err(Error::InvalidLength),
                _ => return Err(Error::UnexpectedType),
            },
            RecordKind::Ciphertext => {
                if self.content_type != 23 {
                    return Err(Error::UnexpectedType);
                }
                if self.legacy_version != 0x0303 {
                    return Err(Error::InvalidVersion);
                }
                if self.length == 0 {
                    return Err(Error::InvalidLength);
                }
            }
        }
        // RFC 9846: plaintext legacy_record_version is ignored on receive.
        Ok(self)
    }

    /// Writers always emit 0x0303. Initial ClientHello compatibility 0x0301 is
    /// intentionally not implemented in this first foundation.
    pub fn write(self, limits: Limits, output: &mut [u8]) -> Result<usize, Error> {
        let canonical = Self {
            legacy_version: 0x0303,
            ..self
        };
        canonical.validate(limits)?;
        let output = output.get_mut(..HEADER_LEN).ok_or(Error::BufferTooSmall)?;
        output[0] = canonical.content_type;
        output[1..3].copy_from_slice(&canonical.legacy_version.to_be_bytes());
        output[3..5].copy_from_slice(&canonical.length.to_be_bytes());
        Ok(HEADER_LEN)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Parse<T> {
    /// Exact additional bytes required for the header or complete body.
    Incomplete {
        needed: usize,
    },
    Complete {
        value: T,
        consumed: usize,
    },
}

pub fn parse_header(input: &[u8], limits: Limits) -> Result<Parse<Header>, Error> {
    let Some(bytes) = input.get(..HEADER_LEN) else {
        return Ok(Parse::Incomplete {
            needed: HEADER_LEN - input.len(),
        });
    };
    let header = Header {
        content_type: bytes[0],
        legacy_version: u16::from_be_bytes([bytes[1], bytes[2]]),
        length: u16::from_be_bytes([bytes[3], bytes[4]]),
    }
    .validate(limits)?;
    Ok(Parse::Complete {
        value: header,
        consumed: HEADER_LEN,
    })
}

/// Borrowed wire body, including ciphertext where applicable. This is never
/// authenticated application plaintext.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Record<'a> {
    pub header: Header,
    pub payload: &'a [u8],
}

pub fn parse_record(input: &[u8], limits: Limits) -> Result<Parse<Record<'_>>, Error> {
    let header = match parse_header(input, limits)? {
        Parse::Incomplete { needed } => return Ok(Parse::Incomplete { needed }),
        Parse::Complete { value, .. } => value,
    };
    let total = HEADER_LEN + usize::from(header.length);
    let Some(record) = input.get(..total) else {
        return Ok(Parse::Incomplete {
            needed: total - input.len(),
        });
    };
    Ok(Parse::Complete {
        value: Record {
            header,
            payload: &record[HEADER_LEN..],
        },
        consumed: total,
    })
}
