use tls_core::handshake::{HandshakeError, Reassembler, Status};

#[test]
fn full_loan_drop_preserves_guards_for_all_alignments_and_states() {
    for offset in 0..32 {
        for size in (4..=257).chain([1023, 1024, 1025, 16383, 16384, 16385, 65539, 65540]) {
            for state in 0..5 {
                let start = 32 + offset;
                let mut data = vec![0xa5; start + size + 32];
                let mut expected = data.clone();
                expected[start..start + size].fill(0);
                {
                    // A smaller cap does not limit the region Drop must clear.
                    let mut reassembler =
                        Reassembler::new(&mut data[start..start + size], 0, 64).unwrap();
                    match state {
                        0 => {}
                        1 => {
                            assert_eq!(
                                reassembler
                                    .push_fragment(&[11, 0], 3, false)
                                    .unwrap()
                                    .consumed,
                                2
                            );
                        }
                        2 => {
                            assert_eq!(
                                reassembler.push_fragment(&[11, 255, 255, 255], 3, true),
                                Err(HandshakeError::MessageTooLarge)
                            );
                        }
                        3 | 4 => {
                            assert_eq!(
                                reassembler
                                    .push_fragment(&[8, 0, 0, 0], 3, true)
                                    .unwrap()
                                    .status,
                                Status::MessageReady
                            );
                            if state == 3 {
                                reassembler.consume_message().unwrap();
                            }
                        }
                        _ => unreachable!(),
                    }
                }
                assert_eq!(data, expected, "size={size} offset={offset} state={state}");
            }
        }
    }
}
