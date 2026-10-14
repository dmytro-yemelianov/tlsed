//! Sequence/epoch bookkeeping, without keys or AEAD integration.
use crate::Error;

/// RFC 9846 §4.7.3 sending limit. Receivers must not enforce this limit.
pub const MAX_SEND_EPOCH: u64 = (1_u64 << 48) - 1;

/// Pure model operation. Conservatively refuses sequence `u64::MAX` rather
/// than needing a wrapped sentinel. `limit` is an exclusive reservation bound.
pub fn reserve_next(next: u64, limit: u64) -> Option<u64> {
    if next >= limit {
        return None;
    }
    next.checked_add(1)
}

pub fn rotate_epoch(epoch: u64, maximum: u64) -> Option<u64> {
    if epoch >= maximum {
        return None;
    }
    epoch.checked_add(1)
}

/// No Clone/Copy: a reservation represents one attempted future AEAD operation.
/// It is retired on reservation, including if crypto later fails or is canceled.
/// This token alone is not a nonce and cannot guarantee unique provider keys.
///
/// ```compile_fail
/// use tls_core::counter::WriteCounter;
/// let mut counter = WriteCounter::new(8).unwrap();
/// let reservation = counter.reserve().unwrap();
/// let duplicate = reservation.clone();
/// ```
#[derive(Debug, Eq, PartialEq)]
pub struct Reservation {
    epoch: u64,
    sequence: u64,
}

impl Reservation {
    pub const fn epoch(&self) -> u64 {
        self.epoch
    }
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }
}

struct Counter {
    epoch: u64,
    next: u64,
    record_limit: u64,
    epoch_limit: u64,
}

impl Counter {
    fn new(record_limit: u64, epoch_limit: u64) -> Result<Self, Error> {
        if record_limit == 0 {
            return Err(Error::InvalidLimit);
        }
        Ok(Self {
            epoch: 0,
            next: 0,
            record_limit,
            epoch_limit,
        })
    }

    fn reserve(&mut self) -> Result<Reservation, Error> {
        let incremented = reserve_next(self.next, self.record_limit).ok_or(Error::Exhausted)?;
        let reservation = Reservation {
            epoch: self.epoch,
            sequence: self.next,
        };
        self.next = incremented;
        Ok(reservation)
    }

    fn rotate(&mut self) -> Result<(), Error> {
        let epoch = rotate_epoch(self.epoch, self.epoch_limit).ok_or(Error::Exhausted)?;
        self.epoch = epoch;
        self.next = 0;
        Ok(())
    }
}

/// Direction-specific nonclone mutable counter. An integrating endpoint must
/// choose the provider's safe record limit, retain room for KeyUpdate under old
/// keys, terminate on AEAD failure, and install fresh keys atomically with epoch
/// rotation. This component does not send KeyUpdate or enforce those assumptions.
///
/// ```compile_fail
/// use tls_core::counter::WriteCounter;
/// let counter = WriteCounter::new(8).unwrap();
/// let duplicate = counter.clone();
/// ```
pub struct WriteCounter(Counter);

impl WriteCounter {
    pub fn new(record_limit: u64) -> Result<Self, Error> {
        Ok(Self(Counter::new(record_limit, MAX_SEND_EPOCH)?))
    }
    pub fn reserve(&mut self) -> Result<Reservation, Error> {
        self.0.reserve()
    }
    /// Call exactly when fresh sending keys have been successfully installed.
    pub fn rotate_after_fresh_keys(&mut self) -> Result<(), Error> {
        self.0.rotate()
    }
    pub const fn epoch(&self) -> u64 {
        self.0.epoch
    }
    pub const fn next_sequence(&self) -> u64 {
        self.0.next
    }
}

/// Inbound is separately owned. It never applies the outbound epoch cap.
/// A caller-selected record bound is a resource policy, not an inferred AEAD
/// sending-limit rule. Failed decryption must terminate the future endpoint.
///
/// ```compile_fail
/// use tls_core::counter::ReadCounter;
/// let counter = ReadCounter::new(8).unwrap();
/// let duplicate = counter.clone();
/// ```
pub struct ReadCounter(Counter);

impl ReadCounter {
    pub fn new(record_limit: u64) -> Result<Self, Error> {
        Ok(Self(Counter::new(record_limit, u64::MAX)?))
    }
    pub fn reserve(&mut self) -> Result<Reservation, Error> {
        self.0.reserve()
    }
    pub fn rotate_after_fresh_keys(&mut self) -> Result<(), Error> {
        self.0.rotate()
    }
    pub const fn epoch(&self) -> u64 {
        self.0.epoch
    }
    pub const fn next_sequence(&self) -> u64 {
        self.0.next
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn epoch_cap_differs_by_direction() {
        let mut send = WriteCounter::new(2).unwrap();
        send.0.epoch = MAX_SEND_EPOCH;
        assert_eq!(send.rotate_after_fresh_keys(), Err(Error::Exhausted));
        assert_eq!(send.epoch(), MAX_SEND_EPOCH);
        let mut receive = ReadCounter::new(2).unwrap();
        receive.0.epoch = MAX_SEND_EPOCH;
        receive.rotate_after_fresh_keys().unwrap();
        assert_eq!(receive.epoch(), MAX_SEND_EPOCH + 1);
        receive.0.epoch = u64::MAX;
        assert_eq!(receive.rotate_after_fresh_keys(), Err(Error::Exhausted));
    }
}
