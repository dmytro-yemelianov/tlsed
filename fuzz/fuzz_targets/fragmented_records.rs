#![no_main]
use libfuzzer_sys::fuzz_target;
use tls_core::framing::{Framer, Status};
use tls_core::wire::{Limits, MAX_CIPHERTEXT, Parse, RecordKind, parse_record};

fuzz_target!(|data: &[u8]| {
    let limits = Limits::new(RecordKind::Ciphertext, MAX_CIPHERTEXT).unwrap();
    let mut scratch = [0; MAX_CIPHERTEXT + 5];
    let mut framer = Framer::new(&mut scratch, limits).unwrap();
    let mut cursor = 0;
    let mut record_start = 0;
    while cursor < data.len() {
        let end = cursor
            .saturating_add(1 + usize::from(data[cursor]))
            .min(data.len());
        let progress = match framer.push(&data[cursor..end]) {
            Ok(value) => value,
            Err(_) => {
                assert!(parse_record(&data[record_start..], limits).is_err());
                assert!(framer.push(&[]).is_err());
                return;
            }
        };
        assert!(progress.consumed <= end - cursor);
        cursor += progress.consumed;
        assert!(framer.buffered_len() <= MAX_CIPHERTEXT + 5);
        if progress.status == Status::RecordReady {
            let Parse::Complete { value, consumed } =
                parse_record(&data[record_start..], limits).unwrap()
            else {
                panic!("framer completed incomplete input")
            };
            assert_eq!(value, framer.record().unwrap().unwrap());
            assert_eq!(cursor - record_start, consumed);
            assert_eq!(framer.push(&data[cursor..]).unwrap().consumed, 0);
            framer.consume_record().unwrap();
            record_start = cursor;
        } else {
            assert!(progress.consumed > 0);
        }
    }
});
