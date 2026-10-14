use tls_core::Error;
use tls_core::auth::{ClientAuthModel, Event, State, may_release, transition};
use tls_core::counter::{ReadCounter, WriteCounter, reserve_next, rotate_epoch};
use tls_core::framing::{Framer, Status};
use tls_core::schedule::{ChunkSchedule, record_count};
use tls_core::wire::{
    HEADER_LEN, Header, Limits, MAX_CIPHERTEXT, MAX_PLAINTEXT, Parse, RecordKind, parse_header,
    parse_record,
};

fn plaintext(cap: usize) -> Limits {
    Limits::new(RecordKind::Plaintext, cap).unwrap()
}
fn encoded(body: &[u8]) -> Vec<u8> {
    let header = Header {
        content_type: 22,
        legacy_version: 0,
        length: u16::try_from(body.len()).unwrap(),
    };
    let mut result = vec![0; HEADER_LEN + body.len()];
    header.write(plaintext(MAX_PLAINTEXT), &mut result).unwrap();
    result[HEADER_LEN..].copy_from_slice(body);
    result
}

#[test]
fn codec_lengths_versions_and_output_atomicity() {
    for length in 0..=u16::MAX {
        let input = [22, 0, 0, (length >> 8) as u8, length as u8];
        let result = parse_header(&input, plaintext(MAX_PLAINTEXT));
        assert_eq!(
            result.is_ok(),
            length > 0 && usize::from(length) <= MAX_PLAINTEXT
        );
        let ciphertext = [23, 3, 3, (length >> 8) as u8, length as u8];
        assert_eq!(
            parse_header(
                &ciphertext,
                Limits::new(RecordKind::Ciphertext, MAX_CIPHERTEXT).unwrap()
            )
            .is_ok(),
            length > 0 && usize::from(length) <= MAX_CIPHERTEXT
        );
    }
    for version in 0..=u16::MAX {
        let header = Header {
            content_type: 22,
            legacy_version: version,
            length: 1,
        };
        assert!(header.validate(plaintext(1)).is_ok());
        let protected = Header {
            content_type: 23,
            ..header
        };
        assert_eq!(
            protected
                .validate(Limits::new(RecordKind::Ciphertext, 1).unwrap())
                .is_ok(),
            version == 0x0303
        );
    }
    for (content_type, length, valid) in [
        (20, 1, true),
        (20, 2, false),
        (21, 2, true),
        (21, 1, false),
        (22, 0, false),
        (23, 1, false),
        (0, 1, false),
        (255, 1, false),
    ] {
        assert_eq!(
            Header {
                content_type,
                legacy_version: 0,
                length
            }
            .validate(plaintext(20))
            .is_ok(),
            valid
        );
    }
    let header = Header {
        content_type: 22,
        legacy_version: 0,
        length: 1,
    };
    for size in 0..HEADER_LEN {
        let mut output = vec![0xA5; size];
        assert_eq!(
            header.write(plaintext(1), &mut output),
            Err(Error::BufferTooSmall)
        );
        assert_eq!(output, vec![0xA5; size]);
    }
    let mut output = [0xA5; 5];
    assert_eq!(
        Header {
            length: 2,
            ..header
        }
        .write(plaintext(1), &mut output),
        Err(Error::RecordOverflow)
    );
    assert_eq!(output, [0xA5; 5]);
    assert_eq!(
        Limits::new(RecordKind::Plaintext, MAX_PLAINTEXT + 1),
        Err(Error::InvalidLimit)
    );
    assert_eq!(
        Limits::new(RecordKind::Ciphertext, usize::MAX),
        Err(Error::InvalidLimit)
    );
}

#[test]
fn borrowed_parser_exact_shortages_and_tail() {
    let bytes = encoded(b"abc");
    for cut in 0..bytes.len() {
        let needed = if cut < 5 { 5 - cut } else { bytes.len() - cut };
        assert_eq!(
            parse_record(&bytes[..cut], plaintext(3)),
            Ok(Parse::Incomplete { needed })
        );
    }
    let mut coalesced = bytes.clone();
    coalesced.extend_from_slice(&encoded(b"other"));
    let Parse::Complete { value, consumed } = parse_record(&coalesced, plaintext(5)).unwrap()
    else {
        panic!()
    };
    assert_eq!(consumed, bytes.len());
    assert_eq!(value.payload, b"abc");
    assert_eq!(value.payload.as_ptr(), coalesced[5..].as_ptr());
}

fn drive_fragments(bytes: &[u8], fragment_sizes: &[usize]) {
    let limits = plaintext(13);
    let mut scratch = [0; 18];
    let mut framer = Framer::new(&mut scratch, limits).unwrap();
    let mut actual = vec![];
    let mut cursor = 0;
    for &size in fragment_sizes {
        let end = (cursor + size).min(bytes.len());
        while cursor < end {
            let progress = framer.push(&bytes[cursor..end]).unwrap();
            assert!(progress.consumed <= end - cursor);
            cursor += progress.consumed;
            assert!(framer.buffered_len() <= 18);
            if progress.status == Status::RecordReady {
                actual.extend_from_slice(framer.record().unwrap().unwrap().payload);
                assert_eq!(framer.push(&bytes[cursor..end]).unwrap().consumed, 0);
                framer.consume_record().unwrap();
            } else {
                assert!(progress.consumed > 0);
            }
        }
    }
    assert_eq!(cursor, bytes.len());
    assert_eq!(actual, b"onetwothreeabcdefghi");
    assert_eq!(framer.buffered_len(), 0);
    framer.finish_input().unwrap();
}

#[test]
fn arbitrary_fragmentation_and_coalescing() {
    let mut bytes = vec![];
    for body in [&b"one"[..], &b"twothree"[..], &b"abcdefghi"[..]] {
        bytes.extend_from_slice(&encoded(body));
    }
    // Every two-boundary partition plus uniform fragmentation/coalescing.
    for first in 0..=bytes.len() {
        for second in first..=bytes.len() {
            drive_fragments(&bytes, &[first, second - first, bytes.len() - second]);
        }
    }
    for size in 1..=bytes.len() {
        drive_fragments(&bytes, &vec![size; bytes.len()]);
    }
}

#[test]
fn framing_fails_closed_without_body_amplification() {
    let mut small = [0; 7];
    assert!(matches!(
        Framer::new(&mut small, plaintext(3)),
        Err(Error::BufferTooSmall)
    ));
    let mut scratch = [0; 8];
    let mut framer = Framer::new(&mut scratch, plaintext(3)).unwrap();
    assert_eq!(
        framer.push(&[22, 3, 3, 255, 255]),
        Err(Error::RecordOverflow)
    );
    assert_eq!(framer.buffered_len(), 5);
    assert_eq!(framer.push(&[0; 1024]), Err(Error::Failed));
    assert_eq!(framer.record(), Err(Error::Failed));
    assert_eq!(framer.consume_record(), Err(Error::Failed));
    let mut scratch = [0; 8];
    let mut framer = Framer::new(&mut scratch, plaintext(3)).unwrap();
    assert_eq!(framer.push(&[]).unwrap().consumed, 0);
    assert_eq!(framer.consume_record(), Err(Error::IncompleteRecord));
    framer.push(&[22, 3, 3, 0, 3, 1]).unwrap();
    assert_eq!(framer.finish_input(), Err(Error::IncompleteRecord));
    assert_eq!(framer.push(&[2, 3]), Err(Error::Failed));
}

#[test]
fn count_edges_and_capacity_respecting_minimality() {
    assert_eq!(record_count(0, 0), Err(Error::InvalidLimit));
    for n in [0, 1, 2, 16_383, 16_384, 16_385, usize::MAX - 1, usize::MAX] {
        for limit in [1, 2, 3, 16_384, usize::MAX] {
            let count = record_count(n, limit).unwrap();
            assert_eq!(count, n / limit + usize::from(n % limit != 0));
            // Exact capacity lower bound in wider arithmetic, no native overflow.
            assert!((count as u128) * (limit as u128) >= n as u128);
            if count > 0 {
                assert!(((count - 1) as u128) * (limit as u128) < n as u128);
            }
        }
    }
    for n in 0..200 {
        for limit in 1..40 {
            let mut schedule = ChunkSchedule::new(n, limit).unwrap();
            let count = schedule.len();
            let chunks: Vec<_> = schedule.by_ref().collect();
            assert_eq!(chunks.len(), count);
            assert_eq!(chunks.iter().sum::<usize>(), n);
            assert!(chunks.iter().all(|&v| v > 0 && v <= limit));
            assert_eq!(schedule.next(), None);
            assert_eq!(schedule.len(), 0);
        }
    }
    let mut huge = ChunkSchedule::new(usize::MAX, usize::MAX - 1).unwrap();
    assert_eq!(huge.next(), Some(usize::MAX - 1));
    assert_eq!(huge.next(), Some(1));
    assert_eq!(huge.next(), None);
}

#[test]
fn reservations_are_monotone_retired_and_direction_owned() {
    assert_eq!(WriteCounter::new(0).err(), Some(Error::InvalidLimit));
    let mut send = WriteCounter::new(2).unwrap();
    let mut receive = ReadCounter::new(3).unwrap();
    {
        let failed_crypto_attempt = send.reserve().unwrap();
        assert_eq!(failed_crypto_attempt.sequence(), 0);
    } // Cancellation retires the reservation without committing an AEAD result.
    assert_eq!(send.reserve().unwrap().sequence(), 1);
    assert_eq!(send.reserve(), Err(Error::Exhausted));
    assert_eq!(send.next_sequence(), 2);
    assert_eq!(receive.reserve().unwrap().sequence(), 0);
    send.rotate_after_fresh_keys().unwrap();
    let next = send.reserve().unwrap();
    assert_eq!((next.epoch(), next.sequence()), (1, 0));
    assert_eq!(receive.epoch(), 0);
    assert_eq!(reserve_next(u64::MAX, u64::MAX), None);
    assert_eq!(reserve_next(u64::MAX - 1, u64::MAX), Some(u64::MAX));
    assert_eq!(reserve_next(0, 0), None);
    assert_eq!(rotate_epoch(u64::MAX, u64::MAX), None);
    assert_eq!(rotate_epoch(u64::MAX - 1, u64::MAX), Some(u64::MAX));
}

#[test]
fn all_auth_transitions_and_failure_release_guards() {
    let states = [
        State::Start,
        State::HelloAccepted,
        State::IdentityVerified,
        State::SignatureVerified,
        State::Established,
        State::Failed,
    ];
    let events = [
        Event::HelloAccepted,
        Event::CertificateAndIdentityVerified,
        Event::CertificateVerifyVerified,
        Event::FinishedVerified,
        Event::Abort,
        Event::AeadFailed,
    ];
    for state in states {
        for event in events {
            let result = transition(state, event);
            assert_eq!(
                result.is_ok(),
                event as u8 >= 4 || state as u8 == event as u8
            );
            if event as u8 >= 4 {
                assert_eq!(result, Ok(State::Failed));
            }
        }
        assert!(!may_release(state, false));
        assert_eq!(may_release(state, true), state == State::Established);
    }
    let mut model = ClientAuthModel::default();
    for event in &events[..4] {
        let before = model.state();
        assert_eq!(
            model.apply(Event::FinishedVerified).is_ok(),
            before == State::SignatureVerified
        );
        if before == State::SignatureVerified {
            break;
        }
        assert_eq!(model.state(), before);
        model.apply(*event).unwrap();
    }
    assert!(model.may_release(true));
    model.apply(Event::AeadFailed).unwrap();
    assert!(!model.may_release(true));
    assert_eq!(
        model.apply(Event::HelloAccepted),
        Err(Error::UnexpectedEvent)
    );
    assert_eq!(model.state(), State::Failed);
}
