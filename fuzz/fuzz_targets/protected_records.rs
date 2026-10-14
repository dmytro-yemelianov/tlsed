#![no_main]
use libfuzzer_sys::fuzz_target;
use tls_core::protected::{
    ContentType, MAX_INNER_PLAINTEXT, ProtectedError, ProtectedReader, ProtectedWriter,
};
use tls_core::wire::Parse;
use tls_crypto::{CipherSuite, CryptoProvider, TAG_LEN};
use tls_crypto_awslc::{AwsLcKey, AwsLcProvider};

// Deterministic isolated test fixtures only. Reinitializing keys/IVs between
// fuzz cases is not a production usage pattern or proof of global key freshness.
const IV: [u8; 12] = [0x4D; 12];
fn key(suite: CipherSuite) -> AwsLcKey {
    AwsLcProvider
        .aead_key(suite, &[0x37; 32][..suite.key_len()])
        .unwrap()
}
fn reader(suite: CipherSuite, limit: usize) -> ProtectedReader<AwsLcKey> {
    ProtectedReader::new(key(suite), IV, limit).unwrap()
}

fuzz_target!(|data: &[u8]| {
    let Some(controls) = data.get(..5) else {
        return;
    };
    let suite = [
        CipherSuite::Aes128GcmSha256,
        CipherSuite::Aes256GcmSha384,
        CipherSuite::Chacha20Poly1305Sha256,
    ][usize::from(controls[0] % 3)];
    let limit =
        1 + usize::from(u16::from_be_bytes([controls[1], controls[2]])) % MAX_INNER_PLAINTEXT;
    let content = &data[5..data.len().min(5 + limit - 1)];
    let available_padding = limit - content.len() - 1;
    let padding = usize::from(controls[3]) % (available_padding + 1);
    let mut writer = ProtectedWriter::new(key(suite), IV, limit, 2).unwrap();
    let mut wire = [0xA5; MAX_INNER_PLAINTEXT + TAG_LEN + 5];
    let expected_len = 5 + content.len() + 1 + padding + TAG_LEN;
    let short_len = usize::from(controls[4]) % expected_len;
    assert_eq!(
        writer.seal(
            ContentType::ApplicationData,
            content,
            padding,
            &mut wire[..short_len]
        ),
        Err(ProtectedError::BufferTooSmall)
    );
    assert_eq!(writer.next_sequence(), 0);
    assert!(wire.iter().all(|&byte| byte == 0xA5));
    let length = writer
        .seal(ContentType::ApplicationData, content, padding, &mut wire)
        .unwrap();
    assert_eq!(length, expected_len);
    assert_eq!(writer.next_sequence(), 1);
    let mut receiver = reader(suite, limit);
    let mut output = [0xA5; MAX_INNER_PLAINTEXT + TAG_LEN];
    let cut = usize::from(controls[4]) % length;
    assert!(matches!(
        receiver.open(&wire[..cut], &mut output),
        Ok(Parse::Incomplete { .. })
    ));
    assert_eq!(receiver.next_sequence(), 0);
    assert!(output.iter().all(|&byte| byte == 0xA5));
    assert!(matches!(
        receiver.open(&wire[..length], &mut output[..length - 6]),
        Err(ProtectedError::BufferTooSmall)
    ));
    assert_eq!(receiver.next_sequence(), 0);
    assert!(!receiver.is_failed());
    assert!(output.iter().all(|&byte| byte == 0xA5));
    let Parse::Complete { value, consumed } = receiver.open(&wire[..length], &mut output).unwrap()
    else {
        panic!("valid protected record incomplete")
    };
    assert_eq!(consumed, length);
    assert_eq!(value.content_type, ContentType::ApplicationData);
    assert_eq!(value.content, content);
    assert!(output[content.len()..].iter().all(|&byte| byte == 0));
    // Replay must use the next nonce and fail without leaving previous plaintext.
    assert!(receiver.open(&wire[..length], &mut output).is_err());
    assert!(receiver.is_failed());
    assert_eq!(receiver.next_sequence(), 2);
    assert!(output.iter().all(|&byte| byte == 0));
    // Change one ciphertext/tag byte, ensuring a complete but unauthentic record.
    let mutation = 5 + usize::from(controls[4]) % (length - 5);
    wire[mutation] ^= 1 << (controls[3] % 8);
    let mut receiver = reader(suite, limit);
    output.fill(0xA5);
    assert!(receiver.open(&wire[..length], &mut output).is_err());
    assert!(receiver.is_failed());
    assert_eq!(receiver.next_sequence(), 1);
    assert!(output.iter().all(|&byte| byte == 0));
    output.fill(0xA5);
    assert!(matches!(
        receiver.open(&wire[..length], &mut output),
        Err(ProtectedError::Failed)
    ));
    assert!(output.iter().all(|&byte| byte == 0));
    // Arbitrary advertised wire lengths/type/version are independently exercised.
    let mut receiver = reader(suite, limit);
    output.fill(0xA5);
    match receiver.open(&data[5..], &mut output) {
        Ok(Parse::Incomplete { .. }) => {
            assert_eq!(receiver.next_sequence(), 0);
            assert!(!receiver.is_failed());
            assert!(output.iter().all(|&byte| byte == 0xA5));
        }
        Ok(Parse::Complete { value, consumed }) => {
            assert!(consumed <= data.len() - 5);
            assert!(value.content.len() < limit);
            assert!(matches!(
                value.content_type,
                ContentType::ApplicationData | ContentType::Handshake | ContentType::Alert
            ));
        }
        Err(_) => {
            assert!(receiver.is_failed());
            assert!(output.iter().all(|&byte| byte == 0));
        }
    }
});
