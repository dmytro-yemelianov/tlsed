//! Capacity-respecting greedy segmentation, minimizing record count only.
use crate::Error;

/// Minimum number of nonempty chunks of at most `capacity` for `bytes`.
/// Avoids overflowing `bytes + capacity - 1`, even for `usize::MAX`.
// Keep the executable arithmetic identical to the Lean/model contract.
#[allow(clippy::manual_is_multiple_of)]
pub fn record_count(bytes: usize, capacity: usize) -> Result<usize, Error> {
    if capacity == 0 {
        return Err(Error::InvalidLimit);
    }
    Ok(bytes / capacity + usize::from(bytes % capacity != 0))
}

/// Allocation-free chunk lengths; no padding, latency or crypto cost model.
#[derive(Debug)]
pub struct ChunkSchedule {
    remaining: usize,
    capacity: usize,
}

impl ChunkSchedule {
    pub fn new(bytes: usize, capacity: usize) -> Result<Self, Error> {
        record_count(bytes, capacity)?;
        Ok(Self {
            remaining: bytes,
            capacity,
        })
    }
}

impl Iterator for ChunkSchedule {
    type Item = usize;

    fn next(&mut self) -> Option<usize> {
        if self.remaining == 0 {
            return None;
        }
        let length = self.remaining.min(self.capacity);
        self.remaining -= length;
        Some(length)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let count = self.remaining / self.capacity
            + usize::from(!self.remaining.is_multiple_of(self.capacity));
        (count, Some(count))
    }
}

impl ExactSizeIterator for ChunkSchedule {}
impl core::iter::FusedIterator for ChunkSchedule {}
