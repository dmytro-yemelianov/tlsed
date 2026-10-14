use tls_core::handshake::{
    HandshakeError, MAX_HANDSHAKE_BODY, Reassembler, Status, checked_handshake_total,
};

fn encoded(kind: u8, body: &[u8]) -> Vec<u8> {
    let n = body.len();
    let mut output = vec![kind, (n >> 16) as u8, (n >> 8) as u8, n as u8];
    output.extend_from_slice(body);
    output
}

#[test]
fn total_length_guards_and_native_edges() {
    assert_eq!(checked_handshake_total(0, 0), Some(4));
    assert_eq!(checked_handshake_total(16, 16), Some(20));
    assert_eq!(checked_handshake_total(17, 16), None);
    assert_eq!(
        checked_handshake_total(MAX_HANDSHAKE_BODY, usize::MAX),
        Some(16_777_219)
    );
    assert_eq!(
        checked_handshake_total(MAX_HANDSHAKE_BODY + 1, usize::MAX),
        None
    );
    assert_eq!(checked_handshake_total(usize::MAX, usize::MAX), None);
}

#[test]
fn every_fragmentation_with_small_work_budgets() {
    let frame = encoded(11, &[1, 2, 3, 4, 5, 6, 7]);
    for budget in 1..=frame.len() + 1 {
        for split in 0..=frame.len() {
            let mut scratch = [0_u8; 36];
            let mut reassembly = Reassembler::new(&mut scratch, 32, budget).unwrap();
            for chunk in [&frame[..split], &frame[split..]] {
                let mut offset = 0;
                loop {
                    let step = reassembly.push_fragment(&chunk[offset..], 3, true).unwrap();
                    assert!(step.consumed <= budget && step.consumed <= chunk.len() - offset);
                    offset += step.consumed;
                    assert!(reassembly.buffered_len() <= 36);
                    if offset == chunk.len() || step.status == Status::MessageReady {
                        break;
                    }
                    assert_eq!(step.status, Status::NeedWork);
                    assert!(step.consumed > 0);
                }
            }
            let message = reassembly.message().unwrap().unwrap();
            assert_eq!(message.message_type, 11);
            assert_eq!(message.encoded, frame);
            assert_eq!(message.body, &frame[4..]);
            assert_eq!(
                reassembly.push_fragment(&[99], 3, true).unwrap().consumed,
                0
            );
            reassembly.consume_message().unwrap();
            assert_eq!(reassembly.buffered_len(), 0);
            assert_eq!(reassembly.check_key_change(), Ok(()));
        }
    }
}

#[test]
fn coalesced_messages_backpressure_and_transcript_bytes() {
    let first = encoded(8, &[0, 0]);
    let second = encoded(11, &[1, 2, 3]);
    let mut input = first.clone();
    input.extend_from_slice(&second);
    let mut scratch = [0_u8; 20];
    let mut reassembly = Reassembler::new(&mut scratch, 16, 20).unwrap();
    let step = reassembly.push_fragment(&input, 0, true).unwrap();
    assert_eq!(step.consumed, first.len());
    assert_eq!(reassembly.message().unwrap().unwrap().encoded, first);
    reassembly.consume_message().unwrap();
    let step = reassembly
        .push_fragment(&input[first.len()..], 0, true)
        .unwrap();
    assert_eq!(step.consumed, second.len());
    assert_eq!(reassembly.message().unwrap().unwrap().encoded, second);
}

#[test]
fn oversized_u24_rejected_before_body_copy() {
    let mut scratch = [0x55_u8; 12];
    {
        let mut reassembly = Reassembler::new(&mut scratch, 8, 100).unwrap();
        assert_eq!(
            reassembly.push_fragment(&[11, 255, 255, 255, 9, 9], 0, true),
            Err(HandshakeError::MessageTooLarge)
        );
        assert_eq!(reassembly.buffered_len(), 4);
        assert!(reassembly.is_failed());
        assert_eq!(
            reassembly.push_fragment(&[0], 0, true),
            Err(HandshakeError::Failed)
        );
    }
    assert_eq!(scratch, [0; 12]);
}

#[test]
fn partial_message_cannot_cross_epochs_or_record_types() {
    for mode in 0..3 {
        let mut scratch = [0_u8; 20];
        let mut reassembly = Reassembler::new(&mut scratch, 16, 20).unwrap();
        reassembly
            .push_fragment(&[11, 0, 0, 4, 1], 7, true)
            .unwrap();
        let error = match mode {
            0 => reassembly.push_fragment(&[2, 3, 4], 8, true).map(|_| ()),
            1 => reassembly.note_other_record(),
            _ => reassembly.check_key_change(),
        };
        assert_eq!(
            error,
            Err(if mode == 1 {
                HandshakeError::InterleavedRecord
            } else {
                HandshakeError::EpochChanged
            })
        );
        assert!(reassembly.is_failed());
    }
}

#[test]
fn key_change_messages_require_real_record_end() {
    for kind in [1, 2, 20, 24] {
        for trailing in [false, true] {
            let mut frame = encoded(kind, &[1]);
            if trailing {
                frame.push(0);
            }
            let mut scratch = [0_u8; 20];
            let mut reassembly = Reassembler::new(&mut scratch, 16, 20).unwrap();
            assert_eq!(
                reassembly.push_fragment(&frame, 0, trailing),
                Err(HandshakeError::MisalignedKeyChange)
            );
        }
        let frame = encoded(kind, &[1]);
        let mut scratch = [0_u8; 20];
        let mut reassembly = Reassembler::new(&mut scratch, 16, 2).unwrap();
        let mut offset = 0;
        while offset < frame.len() {
            offset += reassembly
                .push_fragment(&frame[offset..], 0, true)
                .unwrap()
                .consumed;
        }
        assert!(reassembly.message().unwrap().is_some());
    }
}

#[test]
fn zero_body_syntax_and_recoverable_misuse_and_truncation() {
    let mut scratch = [0_u8; 4];
    let mut reassembly = Reassembler::new(&mut scratch, 0, 4).unwrap();
    assert_eq!(
        reassembly.consume_message(),
        Err(HandshakeError::IncompleteMessage)
    );
    assert!(!reassembly.is_failed());
    assert_eq!(
        reassembly
            .push_fragment(&[8, 0, 0, 0], 0, true)
            .unwrap()
            .status,
        Status::MessageReady
    );
    assert!(reassembly.message().unwrap().unwrap().body.is_empty());
    assert_eq!(reassembly.finish_input(), Ok(()));
    reassembly.consume_message().unwrap();
    reassembly.push_fragment(&[11, 0], 0, true).unwrap();
    assert_eq!(
        reassembly.finish_input(),
        Err(HandshakeError::IncompleteMessage)
    );
}

#[test]
fn unsupported_types_and_invalid_resource_limits() {
    for kind in [0, 3, 5, 6, 9, 254, 255] {
        let mut scratch = [0_u8; 4];
        let mut reassembly = Reassembler::new(&mut scratch, 0, 4).unwrap();
        assert_eq!(
            reassembly.push_fragment(&[kind, 0, 0, 0], 0, true),
            Err(HandshakeError::UnexpectedType)
        );
    }
    assert!(matches!(
        Reassembler::new(&mut [0; 3], 0, 1),
        Err(HandshakeError::BufferTooSmall)
    ));
    assert!(matches!(
        Reassembler::new(&mut [0; 4], 0, 0),
        Err(HandshakeError::InvalidLimit)
    ));
    assert!(matches!(
        Reassembler::new(&mut [0; 4], MAX_HANDSHAKE_BODY + 1, 1),
        Err(HandshakeError::InvalidLimit)
    ));
}
