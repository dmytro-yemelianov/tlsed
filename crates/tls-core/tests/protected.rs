use std::cell::{Cell, RefCell};
use std::rc::Rc;
use tls_core::protected::{
    ContentType, MAX_INNER_PLAINTEXT, ProtectedError, ProtectedReader, ProtectedWriter,
    inner_length, valid_content_type,
};
use tls_core::wire::Parse;
use tls_crypto::{AeadKey, CipherSuite, CryptoError, CryptoProvider, NONCE_LEN, TAG_LEN};
use tls_crypto_awslc::{AwsLcKey, AwsLcProvider};

const IV: [u8; 12] = [0x4D; 12];
const SUITES: [CipherSuite; 3] = [
    CipherSuite::Aes128GcmSha256,
    CipherSuite::Aes256GcmSha384,
    CipherSuite::Chacha20Poly1305Sha256,
];
fn key(suite: CipherSuite) -> AwsLcKey {
    AwsLcProvider
        .aead_key(suite, &vec![0x37; suite.key_len()])
        .unwrap()
}
fn writer(suite: CipherSuite) -> ProtectedWriter<AwsLcKey> {
    ProtectedWriter::new(
        key(suite),
        IV,
        MAX_INNER_PLAINTEXT,
        suite.sending_record_limit(),
    )
    .unwrap()
}
fn reader(suite: CipherSuite) -> ProtectedReader<AwsLcKey> {
    ProtectedReader::new(key(suite), IV, MAX_INNER_PLAINTEXT).unwrap()
}
fn sealed(
    writer: &mut ProtectedWriter<AwsLcKey>,
    content_type: ContentType,
    content: &[u8],
    padding: usize,
) -> Vec<u8> {
    let mut output = vec![0xCC; MAX_INNER_PLAINTEXT + TAG_LEN + 5];
    let length = writer
        .seal(content_type, content, padding, &mut output)
        .unwrap();
    output.truncate(length);
    output
}
fn sealed_inner(suite: CipherSuite, inner: &[u8]) -> Vec<u8> {
    let length = inner.len() + TAG_LEN;
    let mut output = vec![0; 5 + length];
    output[..3].copy_from_slice(&[23, 3, 3]);
    output[3..5].copy_from_slice(&(length as u16).to_be_bytes());
    output[5..5 + inner.len()].copy_from_slice(inner);
    let aad = output[..5].to_vec();
    key(suite)
        .seal_in_place(&IV, &aad, &mut output[5..], inner.len())
        .unwrap();
    output
}

#[test]
fn all_suites_types_padding_and_fragmented_input() {
    for suite in SUITES {
        let mut writer = writer(suite);
        let mut reader = reader(suite);
        for (content_type, content, padding) in [
            (ContentType::ApplicationData, &b""[..], 0),
            (ContentType::ApplicationData, &b"opaque application"[..], 23),
            (ContentType::Handshake, &b"\x01\x00\x00\x00"[..], 5),
            (ContentType::Alert, &b"\x01\x00"[..], 0),
        ] {
            let wire = sealed(&mut writer, content_type, content, padding);
            let before = reader.next_sequence();
            let mut output = vec![0xA5; wire.len() + 11];
            for cut in 0..wire.len() {
                assert!(matches!(
                    reader.open(&wire[..cut], &mut output),
                    Ok(Parse::Incomplete { .. })
                ));
                assert_eq!(reader.next_sequence(), before);
                assert!(output.iter().all(|&v| v == 0xA5));
            }
            let mut coalesced = wire.clone();
            coalesced.extend_from_slice(b"tail for next record");
            let Parse::Complete { value, consumed } = reader.open(&coalesced, &mut output).unwrap()
            else {
                panic!()
            };
            assert_eq!(consumed, wire.len());
            assert_eq!(value.content_type, content_type);
            assert_eq!(value.content, content);
            assert!(output[content.len()..].iter().all(|&v| v == 0));
            assert_eq!(reader.next_sequence(), before + 1);
        }
    }
}

#[test]
fn exact_aad_and_sequence_nonce_match_provider_calls() {
    for suite in SUITES {
        let mut writer = writer(suite);
        for sequence in 0_u64..5 {
            let wire = sealed(&mut writer, ContentType::ApplicationData, b"payload", 7);
            let mut nonce = IV;
            for (byte, seq) in nonce[4..].iter_mut().zip(sequence.to_be_bytes()) {
                *byte ^= seq;
            }
            let mut expected = [0; 7 + 1 + 7 + TAG_LEN];
            expected[..7].copy_from_slice(b"payload");
            expected[7] = 23;
            key(suite)
                .seal_in_place(&nonce, &wire[..5], &mut expected, 15)
                .unwrap();
            assert_eq!(&wire[5..], &expected);
            assert_eq!(&wire[..3], &[23, 3, 3]);
            assert_eq!(
                usize::from(u16::from_be_bytes([wire[3], wire[4]])),
                expected.len()
            );
        }
    }
}

#[test]
fn bounds_small_buffers_and_sender_caps_are_preflight() {
    for suite in SUITES {
        assert!(matches!(
            ProtectedWriter::new(key(suite), IV, 0, 1),
            Err(ProtectedError::InvalidLimit)
        ));
        assert!(matches!(
            ProtectedReader::new(key(suite), IV, MAX_INNER_PLAINTEXT + 1),
            Err(ProtectedError::InvalidLimit)
        ));
        assert!(matches!(
            ProtectedWriter::new(key(suite), IV, 5, 0),
            Err(ProtectedError::InvalidLimit)
        ));
        if suite.sending_record_limit() < u64::MAX {
            assert!(matches!(
                ProtectedWriter::new(key(suite), IV, 5, suite.sending_record_limit() + 1),
                Err(ProtectedError::InvalidLimit)
            ));
        }
        let mut writer = ProtectedWriter::new(key(suite), IV, 5, 2).unwrap();
        let mut output = [0xA5; 100];
        for (ty, content, padding) in [
            (ContentType::Handshake, &b""[..], 0),
            (ContentType::Alert, &b"x"[..], 0),
            (ContentType::ApplicationData, &b"abcde"[..], 0),
            (ContentType::ApplicationData, &b""[..], usize::MAX),
            (ContentType::ApplicationData, &b"a"[..], 4),
        ] {
            assert_eq!(
                writer.seal(ty, content, padding, &mut output),
                Err(ProtectedError::InvalidInner)
            );
            assert_eq!(writer.next_sequence(), 0);
            assert!(!writer.is_failed());
            assert_eq!(output, [0xA5; 100]);
        }
        for size in 0..22 {
            assert_eq!(
                writer.seal(ContentType::ApplicationData, b"", 0, &mut output[..size]),
                Err(ProtectedError::BufferTooSmall)
            );
            assert_eq!(writer.next_sequence(), 0);
            assert_eq!(output, [0xA5; 100]);
        }
        let length = writer
            .seal(ContentType::ApplicationData, b"abcd", 0, &mut output)
            .unwrap();
        assert_eq!(length, 26);
        assert!(output[length..].iter().all(|&v| v == 0xA5));
        let mut reader = ProtectedReader::new(key(suite), IV, 5).unwrap();
        let mut short = [0xAA; 20];
        assert!(matches!(
            reader.open(&output[..length], &mut short),
            Err(ProtectedError::BufferTooSmall)
        ));
        assert_eq!(reader.next_sequence(), 0);
        assert!(!reader.is_failed());
        assert_eq!(short, [0xAA; 20]);
        let mut plaintext = [0; 21];
        assert!(matches!(
            reader.open(&output[..length], &mut plaintext),
            Ok(Parse::Complete { .. })
        ));
        writer
            .seal(ContentType::ApplicationData, b"abcd", 0, &mut output)
            .unwrap();
        assert_eq!(
            writer.seal(ContentType::ApplicationData, b"abcd", 0, &mut output),
            Err(ProtectedError::Exhausted)
        );
        assert_eq!(writer.next_sequence(), 2);
        assert!(writer.is_failed());
        assert!(output.iter().all(|&v| v == 0));
    }
    for (content, padding, limit, expected) in [
        (0, 0, 1, Some(1)),
        (16384, 0, 16385, Some(16385)),
        (0, 16384, 16385, Some(16385)),
        (16384, 1, 16385, None),
        (usize::MAX, 0, 16385, None),
        (0, usize::MAX, 16385, None),
        (0, 0, 0, None),
        (0, 0, usize::MAX, None),
    ] {
        assert_eq!(inner_length(content, padding, limit), expected);
    }
    for ty in 0..=u8::MAX {
        for length in [0, 1, 2, 16384, usize::MAX] {
            assert_eq!(
                valid_content_type(ty, length),
                ty == 23 || (ty == 22 && length > 0) || (ty == 21 && length == 2)
            );
        }
    }
}

#[test]
fn full_inner_capacity_counts_type_and_padding() {
    for suite in SUITES {
        for (content, padding) in [(vec![0x7A; 16_384], 0), (vec![], 16_384)] {
            let wire = sealed(
                &mut writer(suite),
                ContentType::ApplicationData,
                &content,
                padding,
            );
            assert_eq!(wire.len(), 16_385 + 16 + 5);
            let mut output = vec![0; 16_385 + 16];
            let Parse::Complete { value, .. } = reader(suite).open(&wire, &mut output).unwrap()
            else {
                panic!()
            };
            assert_eq!(value.content, content);
        }
    }
}

#[test]
fn ciphertext_mutation_replay_and_reordering_are_terminal_and_wiped() {
    for suite in SUITES {
        let mut writer = writer(suite);
        let wire = sealed(&mut writer, ContentType::ApplicationData, b"secret", 4);
        let second = sealed(&mut writer, ContentType::ApplicationData, b"second", 0);
        for index in 0..wire.len() {
            let mut corrupt = wire.clone();
            corrupt[index] ^= 0x80;
            // A flipped length may declare incomplete input; append enough bytes
            // to force complete processing or immediate resource rejection.
            if index == 3 || index == 4 {
                corrupt.resize(16_650, 0);
            }
            let mut reader = reader(suite);
            let mut output = vec![0xA5; 16_640];
            assert!(reader.open(&corrupt, &mut output).is_err(), "byte {index}");
            assert!(reader.is_failed());
            assert!(output.iter().all(|&v| v == 0));
            assert!(matches!(
                reader.open(&wire, &mut output),
                Err(ProtectedError::Failed)
            ));
        }
        let mut receiver = reader(suite);
        let mut output = [0xA5; 100];
        assert!(matches!(
            receiver.open(&wire, &mut output),
            Ok(Parse::Complete { .. })
        ));
        assert!(receiver.open(&wire, &mut output).is_err());
        assert_eq!(receiver.next_sequence(), 2); // attempted replay retires seq1
        assert!(output.iter().all(|&v| v == 0));
        let mut receiver = reader(suite);
        assert!(receiver.open(&second, &mut output).is_err());
        assert!(receiver.is_failed());
        assert_eq!(receiver.next_sequence(), 1);
    }
}

#[test]
fn authenticated_malformed_inner_and_tight_receiving_caps() {
    for suite in SUITES {
        for inner in [
            &b"\x00"[..],
            &b"\x00\x00\x00"[..],
            &b"\x14"[..],
            &b"\x16\x00"[..],
            &b"x\x15\x00"[..],
            &b"xyz\x15"[..],
            &b"x\xFF\x00"[..],
        ] {
            let wire = sealed_inner(suite, inner);
            let mut reader = reader(suite);
            let mut output = [0xA5; 100];
            assert!(matches!(
                reader.open(&wire, &mut output),
                Err(ProtectedError::InvalidInner)
            ));
            assert_eq!(reader.next_sequence(), 1);
            assert!(reader.is_failed());
            assert!(output.iter().all(|&v| v == 0));
        }
        let wire = sealed_inner(suite, &[23, 0, 0, 0, 0]);
        let mut capped_reader = ProtectedReader::new(key(suite), IV, 4).unwrap();
        let mut output = [0xA5; 100];
        assert!(capped_reader.open(&wire, &mut output).is_err());
        assert_eq!(capped_reader.next_sequence(), 0); // configured ciphertext cap before AEAD
        assert!(output.iter().all(|&v| v == 0));
        for body_len in 0..=TAG_LEN {
            let mut wire = vec![0; 5 + body_len];
            wire[..3].copy_from_slice(&[23, 3, 3]);
            wire[3..5].copy_from_slice(&(body_len as u16).to_be_bytes());
            let mut reader = reader(suite);
            assert!(reader.open(&wire, &mut output).is_err());
            assert_eq!(reader.next_sequence(), 0);
            assert!(reader.is_failed());
        }
    }
}

// Fault injection only: these do not implement cryptography and cannot be
// selected by production code. They deliberately violate provider contracts.
#[derive(Clone, Copy)]
enum Fault {
    Error,
    WrongLength,
}
struct FaultKey {
    calls: Rc<Cell<usize>>,
    nonces: Rc<RefCell<Vec<[u8; 12]>>>,
    fault: Fault,
}
impl AeadKey for FaultKey {
    fn suite(&self) -> CipherSuite {
        CipherSuite::Aes128GcmSha256
    }
    fn seal_in_place(
        &self,
        nonce: &[u8; NONCE_LEN],
        _: &[u8],
        buffer: &mut [u8],
        _: usize,
    ) -> Result<usize, CryptoError> {
        self.calls.set(self.calls.get() + 1);
        self.nonces.borrow_mut().push(*nonce);
        buffer.fill(0x42); // simulate partial sensitive output before failure
        match self.fault {
            Fault::Error => Err(CryptoError::BackendFailure),
            Fault::WrongLength => Ok(usize::MAX),
        }
    }
    fn open_in_place(
        &self,
        nonce: &[u8; NONCE_LEN],
        _: &[u8],
        buffer: &mut [u8],
    ) -> Result<usize, CryptoError> {
        self.calls.set(self.calls.get() + 1);
        self.nonces.borrow_mut().push(*nonce);
        buffer.fill(0x42); // even a provider that fails to wipe is contained
        match self.fault {
            Fault::Error => Err(CryptoError::AuthenticationFailed),
            Fault::WrongLength => Ok(usize::MAX),
        }
    }
}
struct Observations {
    calls: Rc<Cell<usize>>,
    nonces: Rc<RefCell<Vec<[u8; 12]>>>,
}
fn fault_key(fault: Fault) -> (FaultKey, Observations) {
    let calls = Rc::new(Cell::new(0));
    let nonces = Rc::new(RefCell::new(vec![]));
    (
        FaultKey {
            calls: calls.clone(),
            nonces: nonces.clone(),
            fault,
        },
        Observations { calls, nonces },
    )
}

#[test]
fn failing_or_malformed_provider_retires_nonce_wipes_and_cannot_retry() {
    for fault in [Fault::Error, Fault::WrongLength] {
        let (key, observations) = fault_key(fault);
        let mut writer = ProtectedWriter::new(key, IV, 50, 3).unwrap();
        let mut output = [0xA5; 100];
        assert!(
            writer
                .seal(ContentType::ApplicationData, b"sensitive", 0, &mut output)
                .is_err()
        );
        assert_eq!(writer.next_sequence(), 1);
        assert!(writer.is_failed());
        assert_eq!(observations.calls.get(), 1);
        assert_eq!(&*observations.nonces.borrow(), &[IV]);
        assert!(output.iter().all(|&v| v == 0));
        output.fill(0xA5);
        assert_eq!(
            writer.seal(ContentType::ApplicationData, b"sensitive", 0, &mut output),
            Err(ProtectedError::Failed)
        );
        assert_eq!(observations.calls.get(), 1);
        assert_eq!(writer.next_sequence(), 1);
        assert!(output.iter().all(|&v| v == 0));
        let (key, observations) = fault_key(fault);
        let mut reader = ProtectedReader::new(key, IV, 50).unwrap();
        let mut wire = [0; 22];
        wire[..5].copy_from_slice(&[23, 3, 3, 0, 17]);
        output.fill(0xA5);
        assert!(reader.open(&wire, &mut output).is_err());
        assert_eq!(reader.next_sequence(), 1);
        assert!(reader.is_failed());
        assert_eq!(observations.calls.get(), 1);
        assert_eq!(&*observations.nonces.borrow(), &[IV]);
        assert!(output.iter().all(|&v| v == 0));
        output.fill(0xA5);
        assert!(matches!(
            reader.open(&wire, &mut output),
            Err(ProtectedError::Failed)
        ));
        assert_eq!(observations.calls.get(), 1);
        assert!(output.iter().all(|&v| v == 0));
    }
}

fn hex_bytes(input: &str) -> Vec<u8> {
    input
        .split_whitespace()
        .map(|byte| u8::from_str_radix(byte, 16).unwrap())
        .collect()
}

#[test]
fn rfc8448_section3_client_application_and_alert_known_answers() {
    // Published TLS 1.3 trace data, not locally generated expected ciphertext:
    // https://www.rfc-editor.org/rfc/rfc8448.txt section 3, pp13 and15-16.
    // Application keys begin at seq0, then the alert uses seq1. This checks the
    // full record codec/nonce/AAD against externally supplied wire bytes.
    let secret_key = hex_bytes("17 42 2d da 59 6e d5 d9 ac d8 90 e3 c6 3f 50 51");
    let iv: [u8; 12] = hex_bytes("5b 78 92 3d ee 08 57 90 33 e5 23 d9")
        .try_into()
        .unwrap();
    let suite = CipherSuite::Aes128GcmSha256;
    let mut writer = ProtectedWriter::new(
        AwsLcProvider.aead_key(suite, &secret_key).unwrap(),
        iv,
        MAX_INNER_PLAINTEXT,
        suite.sending_record_limit(),
    )
    .unwrap();
    let mut reader = ProtectedReader::new(
        AwsLcProvider.aead_key(suite, &secret_key).unwrap(),
        iv,
        MAX_INNER_PLAINTEXT,
    )
    .unwrap();
    let application: Vec<u8> = (0..50).collect();
    let expected_application = hex_bytes(
        "17 03 03 00 43 a2 3f 70 54 b6 2c 94 d0 af fa fe 82 28 ba 55 cb ef ac ea 42 f9 14 aa 66 bc ab 3f 2b 98 19 a8 a5 b4 6b 39 5b d5 4a 9a 20 44 1e 2b 62 97 4e 1f 5a 62 92 a2 97 70 14 bd 1e 3d ea e6 3a ee bb 21 69 49 15 e4",
    );
    let expected_alert =
        hex_bytes("17 03 03 00 13 c9 87 27 60 65 56 66 b7 4d 7f f1 15 3e fd 6d b6 d0 b0 e3");
    for (content_type, content, expected) in [
        (
            ContentType::ApplicationData,
            &application[..],
            expected_application,
        ),
        (ContentType::Alert, &[1, 0][..], expected_alert),
    ] {
        let mut wire = [0; 100];
        let length = writer.seal(content_type, content, 0, &mut wire).unwrap();
        assert_eq!(&wire[..length], expected);
        let mut output = [0; 100];
        let Parse::Complete { value, consumed } = reader.open(&expected, &mut output).unwrap()
        else {
            panic!()
        };
        assert_eq!(consumed, expected.len());
        assert_eq!(value.content_type, content_type);
        assert_eq!(value.content, content);
    }
}

struct DropObserved<K: AeadKey> {
    key: K,
    drops: Rc<Cell<usize>>,
}
impl<K: AeadKey> Drop for DropObserved<K> {
    fn drop(&mut self) {
        self.drops.set(self.drops.get() + 1);
    }
}
impl<K: AeadKey> AeadKey for DropObserved<K> {
    fn suite(&self) -> CipherSuite {
        self.key.suite()
    }
    fn seal_in_place(
        &self,
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        buffer: &mut [u8],
        plaintext_len: usize,
    ) -> Result<usize, CryptoError> {
        self.key.seal_in_place(nonce, aad, buffer, plaintext_len)
    }
    fn open_in_place(
        &self,
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        buffer: &mut [u8],
    ) -> Result<usize, CryptoError> {
        self.key.open_in_place(nonce, aad, buffer)
    }
}
fn observed<K: AeadKey>(key: K) -> (DropObserved<K>, Rc<Cell<usize>>) {
    let drops = Rc::new(Cell::new(0));
    (
        DropObserved {
            key,
            drops: drops.clone(),
        },
        drops,
    )
}

#[test]
fn terminal_failure_immediately_drops_key_once_preflight_retains_it() {
    let suite = CipherSuite::Aes128GcmSha256;
    let (key, drops) = observed(key(suite));
    let mut writer = ProtectedWriter::new(key, IV, 8, 1).unwrap();
    let mut output = [0xA5; 64];
    assert_eq!(
        writer.seal(ContentType::Handshake, b"", 0, &mut output),
        Err(ProtectedError::InvalidInner)
    );
    assert_eq!(
        writer.seal(ContentType::ApplicationData, b"", 0, &mut output[..1]),
        Err(ProtectedError::BufferTooSmall)
    );
    assert_eq!(drops.get(), 0);
    writer
        .seal(ContentType::ApplicationData, b"", 0, &mut output)
        .unwrap();
    assert_eq!(drops.get(), 0);
    assert_eq!(
        writer.seal(ContentType::ApplicationData, b"", 0, &mut output),
        Err(ProtectedError::Exhausted)
    );
    assert_eq!(drops.get(), 1);
    drop(writer);
    assert_eq!(drops.get(), 1);

    let wire = sealed(
        &mut self::writer(suite),
        ContentType::ApplicationData,
        b"sensitive",
        0,
    );
    let (key, drops) = observed(self::key(suite));
    let mut receiver = ProtectedReader::new(key, IV, MAX_INNER_PLAINTEXT).unwrap();
    assert!(matches!(
        receiver.open(&wire[..2], &mut output),
        Ok(Parse::Incomplete { .. })
    ));
    assert!(matches!(
        receiver.open(&wire, &mut output[..1]),
        Err(ProtectedError::BufferTooSmall)
    ));
    assert_eq!(drops.get(), 0);
    assert!(matches!(
        receiver.open(&wire, &mut output),
        Ok(Parse::Complete { .. })
    ));
    assert_eq!(drops.get(), 0);
    assert!(receiver.open(&wire, &mut output).is_err());
    assert_eq!(drops.get(), 1);
    assert!(output.iter().all(|&v| v == 0));
    assert!(receiver.open(&wire, &mut output).is_err());
    drop(receiver);
    assert_eq!(drops.get(), 1);

    for malformed in [vec![20, 3, 3, 0, 1, 1], sealed_inner(suite, &[0])] {
        let (key, drops) = observed(self::key(suite));
        let mut receiver = ProtectedReader::new(key, IV, MAX_INNER_PLAINTEXT).unwrap();
        assert!(receiver.open(&malformed, &mut output).is_err());
        assert_eq!(drops.get(), 1);
        drop(receiver);
        assert_eq!(drops.get(), 1);
    }
    for fault in [Fault::Error, Fault::WrongLength] {
        let (key, _) = fault_key(fault);
        let (key, drops) = observed(key);
        let mut writer = ProtectedWriter::new(key, IV, 8, 1).unwrap();
        assert!(
            writer
                .seal(ContentType::ApplicationData, b"secret", 0, &mut output)
                .is_err()
        );
        assert_eq!(drops.get(), 1);
        assert_eq!(writer.next_sequence(), 1);
        drop(writer);
        assert_eq!(drops.get(), 1);
        let (key, _) = fault_key(fault);
        let (key, drops) = observed(key);
        let mut receiver = ProtectedReader::new(key, IV, MAX_INNER_PLAINTEXT).unwrap();
        assert!(receiver.open(&wire, &mut output).is_err());
        assert_eq!(drops.get(), 1);
        assert_eq!(receiver.next_sequence(), 1);
        drop(receiver);
        assert_eq!(drops.get(), 1);
    }
    // Successful ownership still destroys a retained key on normal Drop.
    let (key, drops) = observed(self::key(suite));
    let writer = ProtectedWriter::new(key, IV, 8, 1).unwrap();
    assert_eq!(drops.get(), 0);
    drop(writer);
    assert_eq!(drops.get(), 1);
}
