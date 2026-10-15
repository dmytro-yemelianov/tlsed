#![no_main]
use libfuzzer_sys::fuzz_target;
use tls_core::auth::{ClientAuthModel, Event, State};
use tls_core::counter::{WriteCounter, reserve_next, rotate_epoch};
use tls_core::schedule::record_count;

fuzz_target!(|data: &[u8]| {
    let mut model = ClientAuthModel::default();
    let mut counter = WriteCounter::new(32).unwrap();
    for &byte in data {
        let event = match byte % 6 {
            0 => Event::HelloAccepted,
            1 => Event::CertificateAndIdentityVerified,
            2 => Event::CertificateVerifyVerified,
            3 => Event::FinishedVerified,
            4 => Event::Abort,
            _ => Event::AeadFailed,
        };
        let before = model.state();
        if model.apply(event).is_err() {
            assert_eq!(model.state(), before);
        }
        assert!(!model.may_release(false));
        assert_eq!(model.may_release(true), model.state() == State::Established);
        if byte % 7 == 0 {
            counter.rotate_after_fresh_keys().unwrap();
        } else {
            let before = counter.next_sequence();
            match counter.reserve() {
                Ok(value) => {
                    assert_eq!(value.sequence(), before);
                    assert_eq!(counter.next_sequence(), before + 1);
                }
                Err(_) => assert_eq!(counter.next_sequence(), before),
            }
        }
    }
    if let Some(bytes) = data.get(..16) {
        let a = u64::from_le_bytes(bytes[..8].try_into().unwrap());
        let b = u64::from_le_bytes(bytes[8..].try_into().unwrap());
        assert_eq!(
            reserve_next(a, b),
            if a < b { a.checked_add(1) } else { None }
        );
        assert_eq!(
            rotate_epoch(a, b),
            if a < b { a.checked_add(1) } else { None }
        );
        if let (Ok(n), Ok(cap)) = (usize::try_from(a), usize::try_from(b)) {
            if cap > 0 {
                let count = record_count(n, cap).unwrap();
                assert!((count as u128) * (cap as u128) >= n as u128);
            } else {
                assert!(record_count(n, cap).is_err());
            }
        }
    }
});
