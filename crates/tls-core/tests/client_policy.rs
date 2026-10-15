use tls_core::client_policy::client_phase_next;

#[test]
fn exhaustive_u8_policy_matches_complete_allowed_relation() {
    let flights = [
        (0, 2, 1),
        (1, 8, 2),
        (2, 11, 3),
        (3, 15, 4),
        (4, 20, 5),
        (5, 252, 6),
    ];
    for phase in u8::MIN..=u8::MAX {
        for message in u8::MIN..=u8::MAX {
            for verified in [false, true] {
                for retried in [false, true] {
                    let mut allowed: Vec<u8> = flights
                        .iter()
                        .filter(|(from, kind, _)| verified && *from == phase && *kind == message)
                        .map(|(_, _, to)| *to)
                        .collect();
                    if message == 255 {
                        allowed.push(7);
                    }
                    if phase == 0 && message == 253 && verified && !retried {
                        allowed.push(0);
                    }
                    assert!(allowed.len() <= 1);
                    assert_eq!(
                        client_phase_next(phase, message, verified, retried),
                        allowed.first().copied(),
                        "phase={phase} message={message} verified={verified} retried={retried}"
                    );
                }
            }
        }
    }
}

#[test]
fn complete_flight_with_retry_and_failed_evidence() {
    assert_eq!(client_phase_next(0, 253, true, false), Some(0));
    assert_eq!(client_phase_next(0, 253, true, true), None);
    let mut phase = 0;
    for kind in [2, 8, 11, 15, 20, 252] {
        assert_eq!(client_phase_next(phase, kind, false, true), None);
        phase = client_phase_next(phase, kind, true, true).unwrap();
    }
    assert_eq!(phase, 6);
    assert_eq!(client_phase_next(phase, 255, false, true), Some(7));
    for kind in [2, 8, 11, 15, 20, 252, 253] {
        assert_eq!(client_phase_next(7, kind, true, false), None);
    }
}
