//! Incremental one-record accumulator with explicit backpressure.
use crate::Error;
use crate::wire::{HEADER_LEN, Limits, Parse, Record, parse_header, parse_record};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Status {
    NeedInput,
    /// A record is retained until `consume_record`; push then consumes zero.
    RecordReady,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Progress {
    pub consumed: usize,
    pub status: Status,
}

/// Caller-owned reusable storage. Accumulation is at most one configured-size
/// wire record, and each push copies at most that size. No allocation, input
/// amplification, shifting, callbacks, or hidden I/O. Only one record is handled
/// per call, bounding work even for arbitrarily large coalesced input.
///
/// Malformed wire input and truncated EOF permanently fail this framer. Calling
/// `consume_record` before a complete record returns `IncompleteRecord` without
/// failing the framer, allowing further input. Drop it to discard failed input. A body
/// is syntactic, unauthenticated wire bytes. The caller must enforce connection
/// state and protection rules before using it. Concurrent access requires Rust's
/// ordinary exclusive mutable borrow; cancellation retains accepted bytes.
pub struct Framer<'a> {
    scratch: &'a mut [u8],
    limits: Limits,
    buffered: usize,
    target: Option<usize>,
    failed: bool,
}

impl<'a> Framer<'a> {
    pub fn new(scratch: &'a mut [u8], limits: Limits) -> Result<Self, Error> {
        if scratch.len() < limits.max_wire_size() {
            return Err(Error::BufferTooSmall);
        }
        Ok(Self {
            scratch,
            limits,
            buffered: 0,
            target: None,
            failed: false,
        })
    }

    pub const fn buffered_len(&self) -> usize {
        self.buffered
    }

    pub fn push(&mut self, input: &[u8]) -> Result<Progress, Error> {
        if self.failed {
            return Err(Error::Failed);
        }
        if self.ready() {
            return Ok(Progress {
                consumed: 0,
                status: Status::RecordReady,
            });
        }
        let mut consumed = 0;
        if self.target.is_none() {
            let take = (HEADER_LEN - self.buffered).min(input.len());
            self.scratch[self.buffered..self.buffered + take].copy_from_slice(&input[..take]);
            self.buffered += take;
            consumed += take;
            if self.buffered == HEADER_LEN {
                match parse_header(&self.scratch[..HEADER_LEN], self.limits) {
                    Ok(Parse::Complete { value, .. }) => {
                        self.target = Some(HEADER_LEN + usize::from(value.length));
                    }
                    Err(error) => {
                        self.failed = true;
                        return Err(error);
                    }
                    Ok(Parse::Incomplete { .. }) => {
                        self.failed = true;
                        return Err(Error::Failed);
                    }
                }
            }
        }
        if let Some(target) = self.target {
            let take = (target - self.buffered).min(input.len() - consumed);
            self.scratch[self.buffered..self.buffered + take]
                .copy_from_slice(&input[consumed..consumed + take]);
            self.buffered += take;
            consumed += take;
        }
        Ok(Progress {
            consumed,
            status: if self.ready() {
                Status::RecordReady
            } else {
                Status::NeedInput
            },
        })
    }

    fn ready(&self) -> bool {
        self.target == Some(self.buffered)
    }

    /// Borrow ends before the retained record can be consumed or overwritten.
    pub fn record(&self) -> Result<Option<Record<'_>>, Error> {
        if self.failed {
            return Err(Error::Failed);
        }
        if !self.ready() {
            return Ok(None);
        }
        match parse_record(&self.scratch[..self.buffered], self.limits)? {
            Parse::Complete { value, .. } => Ok(Some(value)),
            Parse::Incomplete { .. } => Err(Error::Failed),
        }
    }

    pub fn consume_record(&mut self) -> Result<(), Error> {
        if self.failed {
            return Err(Error::Failed);
        }
        if !self.ready() {
            return Err(Error::IncompleteRecord);
        }
        self.buffered = 0;
        self.target = None;
        Ok(())
    }

    /// Transport EOF boundary only; a clean record boundary does not prove TLS
    /// `close_notify` or detect truncation of an otherwise valid stream.
    pub fn finish_input(&mut self) -> Result<(), Error> {
        if self.failed {
            return Err(Error::Failed);
        }
        if self.buffered != 0 && !self.ready() {
            self.failed = true;
            return Err(Error::IncompleteRecord);
        }
        Ok(())
    }
}
