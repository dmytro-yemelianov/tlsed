//! Bounded syntactic handshake reassembly. The endpoint must supply actual
//! record boundaries/key epochs and validate message bodies and ordering.
use zeroize::Zeroize;

pub const HANDSHAKE_HEADER_LEN: usize = 4;
pub const MAX_HANDSHAKE_BODY: usize = 0x00ff_ffff;

/// Checked arithmetic shared with the Lean model and translated proof.
pub fn checked_handshake_total(body: usize, cap: usize) -> Option<usize> {
    if body > MAX_HANDSHAKE_BODY || body > cap {
        None
    } else {
        body.checked_add(HANDSHAKE_HEADER_LEN)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HandshakeError {
    InvalidLimit,
    BufferTooSmall,
    UnexpectedType,
    MessageTooLarge,
    EpochChanged,
    MisalignedKeyChange,
    InterleavedRecord,
    IncompleteMessage,
    Failed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Status {
    NeedInput,
    NeedWork,
    MessageReady,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Progress {
    pub consumed: usize,
    pub status: Status,
}

/// A syntactic message, not proof of certificate/Finished authenticity.
pub struct Message<'a> {
    pub message_type: u8,
    pub body: &'a [u8],
    /// Exact handshake header plus body for eventual transcript hashing.
    pub encoded: &'a [u8],
}

fn supported_type(kind: u8) -> bool {
    // EndOfEarlyData is excluded because initial releases disable 0-RTT;
    // message_hash is internal to HRR transcripts and never a wire message.
    matches!(kind, 1 | 2 | 4 | 8 | 11 | 13 | 15 | 20 | 24)
}

fn requires_record_alignment(kind: u8) -> bool {
    matches!(kind, 1 | 2 | 20 | 24)
}

/// One retained message, explicit consumption, caller storage, and bounded work.
/// Network/framing errors poison the instance. Premature consumption is a
/// recoverable caller error. Compatibility CCS is dropped by the endpoint before
/// calling this component; other record types must use `note_other_record`.
pub struct Reassembler<'a> {
    scratch: &'a mut [u8],
    cap: usize,
    work_budget: usize,
    buffered: usize,
    target: Option<usize>,
    epoch: Option<u64>,
    failed: bool,
}

impl<'a> Reassembler<'a> {
    pub fn new(
        scratch: &'a mut [u8],
        max_body: usize,
        work_budget: usize,
    ) -> Result<Self, HandshakeError> {
        let maximum =
            checked_handshake_total(max_body, max_body).ok_or(HandshakeError::InvalidLimit)?;
        if work_budget == 0 {
            return Err(HandshakeError::InvalidLimit);
        }
        if scratch.len() < maximum {
            return Err(HandshakeError::BufferTooSmall);
        }
        Ok(Self {
            scratch,
            cap: max_body,
            work_budget,
            buffered: 0,
            target: None,
            epoch: None,
            failed: false,
        })
    }

    pub const fn buffered_len(&self) -> usize {
        self.buffered
    }

    pub const fn is_failed(&self) -> bool {
        self.failed
    }

    fn ready(&self) -> bool {
        self.target == Some(self.buffered)
    }

    fn fail<T>(&mut self, error: HandshakeError) -> Result<T, HandshakeError> {
        self.scratch[..self.buffered].zeroize();
        self.failed = true;
        Err(error)
    }

    /// `input` is a slice of one decoded Handshake record's remaining content.
    /// `end_of_record` says that its final byte is the actual record boundary,
    /// not a TCP/read/work boundary. Call again with the unconsumed tail after
    /// NeedWork, or after processing and consuming a ready message.
    pub fn push_fragment(
        &mut self,
        input: &[u8],
        key_epoch: u64,
        end_of_record: bool,
    ) -> Result<Progress, HandshakeError> {
        if self.failed {
            return Err(HandshakeError::Failed);
        }
        if self.ready() {
            return Ok(Progress {
                consumed: 0,
                status: Status::MessageReady,
            });
        }
        if self.buffered != 0 && self.epoch != Some(key_epoch) {
            return self.fail(HandshakeError::EpochChanged);
        }
        if self.buffered == 0 && !input.is_empty() {
            self.epoch = Some(key_epoch);
        }
        let mut consumed = 0;
        if self.target.is_none() {
            let take = (HANDSHAKE_HEADER_LEN - self.buffered)
                .min(input.len())
                .min(self.work_budget);
            self.scratch[self.buffered..self.buffered + take].copy_from_slice(&input[..take]);
            self.buffered += take;
            consumed += take;
            if self.buffered == HANDSHAKE_HEADER_LEN {
                if !supported_type(self.scratch[0]) {
                    return self.fail(HandshakeError::UnexpectedType);
                }
                let body = (usize::from(self.scratch[1]) << 16)
                    | (usize::from(self.scratch[2]) << 8)
                    | usize::from(self.scratch[3]);
                let Some(target) = checked_handshake_total(body, self.cap) else {
                    return self.fail(HandshakeError::MessageTooLarge);
                };
                self.target = Some(target);
            }
        }
        if let Some(target) = self.target {
            let take = (target - self.buffered)
                .min(input.len() - consumed)
                .min(self.work_budget - consumed);
            self.scratch[self.buffered..self.buffered + take]
                .copy_from_slice(&input[consumed..consumed + take]);
            self.buffered += take;
            consumed += take;
        }
        if self.ready()
            && requires_record_alignment(self.scratch[0])
            && (!end_of_record || consumed != input.len())
        {
            return self.fail(HandshakeError::MisalignedKeyChange);
        }
        Ok(Progress {
            consumed,
            status: if self.ready() {
                Status::MessageReady
            } else if consumed < input.len() {
                Status::NeedWork
            } else {
                Status::NeedInput
            },
        })
    }

    pub fn message(&self) -> Result<Option<Message<'_>>, HandshakeError> {
        if self.failed {
            return Err(HandshakeError::Failed);
        }
        if !self.ready() {
            return Ok(None);
        }
        Ok(Some(Message {
            message_type: self.scratch[0],
            body: &self.scratch[HANDSHAKE_HEADER_LEN..self.buffered],
            encoded: &self.scratch[..self.buffered],
        }))
    }

    pub fn consume_message(&mut self) -> Result<(), HandshakeError> {
        if self.failed {
            return Err(HandshakeError::Failed);
        }
        if !self.ready() {
            return Err(HandshakeError::IncompleteMessage);
        }
        self.scratch[..self.buffered].zeroize();
        self.buffered = 0;
        self.target = None;
        self.epoch = None;
        Ok(())
    }

    /// Prevent fragmented handshake interleaving; valid compatibility CCS is
    /// ignored by the endpoint before this method is considered.
    pub fn note_other_record(&mut self) -> Result<(), HandshakeError> {
        if self.failed {
            return Err(HandshakeError::Failed);
        }
        if self.buffered != 0 {
            return self.fail(HandshakeError::InterleavedRecord);
        }
        Ok(())
    }

    /// All retained handshake bytes must be handled before changing traffic keys.
    pub fn check_key_change(&mut self) -> Result<(), HandshakeError> {
        if self.failed {
            return Err(HandshakeError::Failed);
        }
        if self.buffered != 0 {
            return self.fail(HandshakeError::EpochChanged);
        }
        Ok(())
    }

    /// A ready complete message may still be processed after EOF; a partial
    /// message is rejected. Orderly TLS closure is an endpoint responsibility.
    pub fn finish_input(&mut self) -> Result<(), HandshakeError> {
        if self.failed {
            return Err(HandshakeError::Failed);
        }
        if self.buffered != 0 && !self.ready() {
            return self.fail(HandshakeError::IncompleteMessage);
        }
        Ok(())
    }
}

impl Drop for Reassembler<'_> {
    fn drop(&mut self) {
        // Clear the entire caller loan, including unused reassembly storage.
        let (head, words, tail) = bytemuck::pod_align_to_mut::<u8, u128>(self.scratch);
        head.zeroize();
        words.zeroize();
        tail.zeroize();
    }
}
