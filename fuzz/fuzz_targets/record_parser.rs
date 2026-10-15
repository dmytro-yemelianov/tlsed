#![no_main]
use libfuzzer_sys::fuzz_target;
use tls_core::wire::{
    Header, Limits, MAX_CIPHERTEXT, MAX_PLAINTEXT, Parse, RecordKind, parse_header, parse_record,
};

fuzz_target!(|data: &[u8]| {
    for (kind, maximum) in [
        (RecordKind::Plaintext, MAX_PLAINTEXT),
        (RecordKind::Ciphertext, MAX_CIPHERTEXT),
    ] {
        let cap = if data.len() >= 2 {
            usize::from(u16::from_be_bytes([data[0], data[1]])) % (maximum + 1)
        } else {
            maximum
        };
        let limits = Limits::new(kind, cap).unwrap();
        let input = data.get(2..).unwrap_or_default();
        if let Ok(Parse::Complete { value, consumed }) = parse_record(input, limits) {
            assert!(consumed <= input.len());
            assert!(value.payload.len() <= cap);
            let mut header = [0; 5];
            value.header.write(limits, &mut header).unwrap();
            // Canonical writers preserve type and size; plaintext receive version
            // is intentionally ignored rather than round-tripping raw bytes.
            assert_eq!(
                parse_header(&header, limits).unwrap(),
                Parse::Complete {
                    value: Header {
                        legacy_version: 0x0303,
                        ..value.header
                    },
                    consumed: 5
                }
            );
        }
    }
});
