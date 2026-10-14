#![no_main]
use libfuzzer_sys::fuzz_target;
use tls_core::handshake::{HandshakeError, Reassembler, Status};

fn encode(kind: u8, body: &[u8]) -> Vec<u8> {
    let n = body.len();
    let mut message = vec![kind, (n >> 16) as u8, (n >> 8) as u8, n as u8];
    message.extend_from_slice(body);
    message
}

fn structured(data: &[u8]) {
    let Some(controls) = data.get(..4) else {
        return;
    };
    let body = &data[4..data.len().min(259)];
    let budget = 1 + usize::from(controls[0] % 32);
    let fragment = 1 + usize::from(controls[1] % 64);
    let first_type = [4, 8, 11, 13, 15][usize::from(controls[2] % 5)];
    let second_type = [1, 2, 20, 24][usize::from(controls[3] % 4)];
    let first = encode(first_type, body);
    let second = encode(second_type, &body[..body.len() / 2]);
    let mut stream = first.clone();
    stream.extend_from_slice(&second);
    // Physical record split may be anywhere. Key-changing second message ends
    // at the final actual record boundary; both messages may span records.
    let split = usize::from(controls[2]) % (stream.len() + 1);
    let records = [&stream[..split], &stream[split..]];
    let expected = [&first[..], &second[..]];
    let mut scratch = [0xA5; 259];
    {
        let mut reassembly = Reassembler::new(&mut scratch, 255, budget).unwrap();
        let mut message_index = 0;
        for record in records {
            let mut offset = 0;
            while offset < record.len() {
                let end = offset.saturating_add(fragment).min(record.len());
                while offset < end {
                    let before = reassembly.buffered_len();
                    let progress = reassembly
                        .push_fragment(&record[offset..end], 7, end == record.len())
                        .unwrap();
                    assert!(progress.consumed <= budget && progress.consumed <= end - offset);
                    assert_eq!(reassembly.buffered_len(), before + progress.consumed);
                    assert!(reassembly.buffered_len() <= 259);
                    offset += progress.consumed;
                    if progress.status == Status::MessageReady {
                        let message = reassembly.message().unwrap().unwrap();
                        assert_eq!(message.encoded, expected[message_index]);
                        assert_eq!(message.body, &expected[message_index][4..]);
                        assert_eq!(message.message_type, expected[message_index][0]);
                        assert_eq!(
                            reassembly
                                .push_fragment(&record[offset..end], 8, end == record.len())
                                .unwrap()
                                .consumed,
                            0
                        );
                        reassembly.consume_message().unwrap();
                        message_index += 1;
                    } else {
                        assert!(progress.consumed > 0);
                    }
                }
            }
        }
        assert_eq!(message_index, 2);
        assert_eq!(reassembly.buffered_len(), 0);
        reassembly.check_key_change().unwrap();
        reassembly.note_other_record().unwrap();
        reassembly.finish_input().unwrap();
    }
    assert!(scratch.iter().all(|&byte| byte == 0));
}

fn attacker_header(data: &[u8]) {
    let Some(controls) = data.get(..2) else {
        return;
    };
    let cap = usize::from(controls[0]);
    let budget = 1 + usize::from(controls[1] % 32);
    let input = &data[2..];
    let mut scratch = [0xA5; 259];
    {
        let mut reassembly = Reassembler::new(&mut scratch, cap, budget).unwrap();
        let mut cursor = 0;
        let mut failed = false;
        while cursor < input.len() {
            match reassembly.push_fragment(&input[cursor..], 0, true) {
                Ok(progress) => {
                    assert!(
                        progress.consumed <= budget && progress.consumed <= input.len() - cursor
                    );
                    assert!(reassembly.buffered_len() <= cap + 4);
                    cursor += progress.consumed;
                    if progress.status == Status::MessageReady {
                        // Independent one-message oracle over original bytes.
                        assert!(input.len() >= 4);
                        let size = (usize::from(input[1]) << 16)
                            | (usize::from(input[2]) << 8)
                            | usize::from(input[3]);
                        assert!(size <= cap);
                        assert!(matches!(input[0], 1 | 2 | 4 | 8 | 11 | 13 | 15 | 20 | 24));
                        assert_eq!(cursor, size + 4);
                        assert_eq!(
                            reassembly.message().unwrap().unwrap().encoded,
                            &input[..cursor]
                        );
                        if matches!(input[0], 1 | 2 | 20 | 24) {
                            assert_eq!(cursor, input.len());
                        }
                        break;
                    }
                    assert!(progress.consumed > 0);
                }
                Err(error) => {
                    failed = true;
                    assert!(reassembly.is_failed());
                    assert_eq!(
                        reassembly.push_fragment(&[], 0, true),
                        Err(HandshakeError::Failed)
                    );
                    if input.len() >= 4 {
                        let size = (usize::from(input[1]) << 16)
                            | (usize::from(input[2]) << 8)
                            | usize::from(input[3]);
                        let valid_type = matches!(input[0], 1 | 2 | 4 | 8 | 11 | 13 | 15 | 20 | 24);
                        assert_eq!(
                            error,
                            if !valid_type {
                                HandshakeError::UnexpectedType
                            } else if size > cap {
                                HandshakeError::MessageTooLarge
                            } else {
                                assert!(matches!(input[0], 1 | 2 | 20 | 24));
                                assert!(input.len() > size + 4);
                                HandshakeError::MisalignedKeyChange
                            }
                        );
                    }
                    break;
                }
            }
        }
        if !failed && reassembly.message().unwrap().is_none() {
            assert_eq!(reassembly.finish_input().is_err(), !input.is_empty());
        }
    }
    assert!(scratch.iter().all(|&byte| byte == 0));
}

fn control_failures(data: &[u8]) {
    let selector = data.first().copied().unwrap_or_default();
    let mut scratch = [0xA5; 12];
    let mut reassembly = Reassembler::new(&mut scratch, 8, 1 + usize::from(selector % 16)).unwrap();
    // Force a nonempty fragmented certificate without completing it.
    let fragment = &[11, 0, 0, 4, 1][..1 + usize::from(selector % 5)];
    let mut offset = 0;
    while offset < fragment.len() {
        offset += reassembly
            .push_fragment(&fragment[offset..], 0, true)
            .unwrap()
            .consumed;
    }
    let error = match selector % 3 {
        0 => reassembly.push_fragment(&[2], 1, true).map(|_| ()),
        1 => reassembly.note_other_record(),
        _ => reassembly.check_key_change(),
    };
    assert_eq!(
        error,
        Err(if selector % 3 == 1 {
            HandshakeError::InterleavedRecord
        } else {
            HandshakeError::EpochChanged
        })
    );
    assert!(reassembly.is_failed());
    assert!(reassembly.message().is_err());
}

fuzz_target!(|data: &[u8]| {
    structured(data);
    attacker_header(data);
    control_failures(data);
});
