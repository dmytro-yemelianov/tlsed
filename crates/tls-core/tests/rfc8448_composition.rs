//! Published record/transcript/key-schedule composition, not a TLS endpoint or PKI test.
use tls_core::handshake::{Reassembler, Status};
use tls_core::key_schedule::HandshakeSecrets;
use tls_core::protected::{ContentType, MAX_INNER_PLAINTEXT, ProtectedReader, ProtectedWriter};
use tls_core::transcript::Transcript;
use tls_core::wire::Parse;
use tls_crypto::{CipherSuite, CryptoProvider, HandshakeCryptoProvider, HashAlgorithm};
use tls_crypto_awslc::AwsLcProvider;

fn hex(text: &str) -> Vec<u8> {
    text.split_whitespace()
        .map(|octet| u8::from_str_radix(octet, 16).unwrap())
        .collect()
}

#[test]
fn published_hello_retry_request_transcript_hash() {
    let ch1 = hex(include_str!("fixtures/rfc8448_hrr_client_hello1.hex"));
    let hrr = hex(include_str!("fixtures/rfc8448_hrr.hex"));
    let ch2 = hex(include_str!("fixtures/rfc8448_hrr_client_hello2.hex"));
    let sh = hex(include_str!("fixtures/rfc8448_hrr_server_hello.hex"));
    let mut context = AwsLcProvider.hash_context(HashAlgorithm::Sha256).unwrap();
    // Constructor must clear previously supplied context history as well.
    tls_crypto::HashContext::update(&mut context, b"discarded prefix").unwrap();
    let mut transcript = Transcript::new(context, 512, 4096, 16).unwrap();
    transcript.append(&ch1).unwrap();
    transcript.apply_hello_retry_request(&hrr).unwrap();
    transcript.append(&ch2).unwrap();
    transcript.append(&sh).unwrap();
    assert_eq!(transcript.message_count(), 4);
    assert_eq!(
        transcript.hashed_bytes(),
        (180 + 36 + 176 + 512 + 123) as u64
    );
    assert_eq!(
        transcript.snapshot().unwrap().as_bytes(),
        hex(
            "8a a8 e8 28 ec 2f 8a 88 4f ec 95 a3 13 9d e0 1c 15 a3 da a7 ff 5b fc 3f 4b fc c2 1b 43 8d 7b f8"
        )
    );
    // Exact published §5 hash is independent of the implementation/provider.
    // Full P256 share/HRR negotiation semantics remain endpoint work.
}

#[test]
fn published_transcript_derives_record_keys_and_verifies_finished() {
    let suite = CipherSuite::Aes128GcmSha256;
    let mut transcript = Transcript::new(
        AwsLcProvider.hash_context(HashAlgorithm::Sha256).unwrap(),
        441,
        4096,
        16,
    )
    .unwrap();
    transcript
        .append(&hex(include_str!("fixtures/rfc8448_client_hello.hex")))
        .unwrap();
    transcript
        .append(&hex(include_str!("fixtures/rfc8448_server_hello.hex")))
        .unwrap();
    let hello = transcript.snapshot().unwrap();
    assert_eq!(
        hello.as_bytes(),
        hex(
            "86 0c 06 ed c0 78 58 ee 8e 78 f0 e7 42 8c 58 ed d6 b4 3f 2c a3 e6 e9 5f 02 ed 06 3c f0 e1 ca d8"
        )
    );
    // Published validated DHE result; this test does not implement key agreement.
    let shared = hex(
        "8b d4 05 4f b5 5b 9d 63 fd fb ac f9 f0 4b 9f 0d 35 e6 d6 3f 53 75 63 ef d4 62 72 90 0f 89 49 2d",
    );
    let handshake =
        HandshakeSecrets::derive(&AwsLcProvider, suite, &shared, hello.as_bytes()).unwrap();
    let material = handshake.server.key_material(&AwsLcProvider).unwrap();
    let mut reader = ProtectedReader::new(
        AwsLcProvider.aead_key(suite, material.key_bytes()).unwrap(),
        material.iv_bytes().try_into().unwrap(),
        MAX_INNER_PLAINTEXT,
    )
    .unwrap();
    drop(material);
    let record = hex(include_str!("fixtures/rfc8448_server_handshake_record.hex"));
    let mut plaintext = [0xa5; 679];
    let Parse::Complete { value, consumed } = reader.open(&record, &mut plaintext).unwrap() else {
        panic!("published complete record must open with derived key");
    };
    assert_eq!(consumed, record.len());
    assert_eq!(value.content_type, ContentType::Handshake);
    let mut scratch = [0; 445];
    let mut messages = Reassembler::new(&mut scratch, 441, 17).unwrap();
    let mut offset = 0;
    let mut finished_verified = false;
    while offset < value.content.len() {
        let progress = messages
            .push_fragment(&value.content[offset..], 0, true)
            .unwrap();
        offset += progress.consumed;
        if progress.status == Status::MessageReady {
            let message = messages.message().unwrap().unwrap();
            if message.message_type == 20 {
                let before_finished = transcript.snapshot().unwrap();
                handshake
                    .server
                    .verify_finished(&AwsLcProvider, before_finished.as_bytes(), message.body)
                    .unwrap();
                let mut wrong_hash = before_finished.as_bytes().to_vec();
                wrong_hash[0] ^= 1;
                assert!(
                    handshake
                        .server
                        .verify_finished(&AwsLcProvider, &wrong_hash, message.body,)
                        .is_err()
                );
                let mut wrong_tag = message.body.to_vec();
                wrong_tag[0] ^= 1;
                assert!(
                    handshake
                        .server
                        .verify_finished(&AwsLcProvider, before_finished.as_bytes(), &wrong_tag,)
                        .is_err()
                );
                finished_verified = true;
            }
            transcript.append(message.encoded).unwrap();
            messages.consume_message().unwrap();
        }
    }
    assert!(finished_verified);
    messages.check_key_change().unwrap();
    let through_server_finished = transcript.snapshot().unwrap();
    assert_eq!(
        through_server_finished.as_bytes(),
        hex(
            "96 08 10 2a 0f 1c cc 6d b6 25 0b 7b 7e 41 7b 1a 00 0e aa da 3d aa e4 77 7a 76 86 c9 ff 83 df 13"
        )
    );
    let transition = handshake
        .into_application(&AwsLcProvider, through_server_finished.as_bytes())
        .unwrap();
    let mut client_finished = [0; 32];
    transition
        .client_handshake
        .sign_finished(
            &AwsLcProvider,
            through_server_finished.as_bytes(),
            &mut client_finished,
        )
        .unwrap();
    assert_eq!(
        client_finished.as_slice(),
        hex(
            "a8 ec 43 6d 67 76 34 ae 52 5a c1 fc eb e1 1a 03 9e c1 76 94 fa c6 e9 85 27 b6 42 f2 ed d5 ce 61"
        )
    );
    let mut encoded_finished = vec![20, 0, 0, 32];
    encoded_finished.extend_from_slice(&client_finished);
    transcript.append(&encoded_finished).unwrap();
    transcript.freeze().unwrap();
    let material = transition
        .application
        .client
        .key_material(&AwsLcProvider)
        .unwrap();
    let mut writer = ProtectedWriter::new(
        AwsLcProvider.aead_key(suite, material.key_bytes()).unwrap(),
        material.iv_bytes().try_into().unwrap(),
        MAX_INNER_PLAINTEXT,
        suite.sending_record_limit(),
    )
    .unwrap();
    drop(material);
    let application: Vec<u8> = (0..50).collect();
    let mut wire = [0; 72];
    let length = writer
        .seal(ContentType::ApplicationData, &application, 0, &mut wire)
        .unwrap();
    assert_eq!(
        &wire[..length],
        hex(
            "17 03 03 00 43 a2 3f 70 54 b6 2c 94 d0 af fa fe 82 28 ba 55 cb ef ac ea 42 f9 14 aa 66 bc ab 3f 2b 98 19 a8 a5 b4 6b 39 5b d5 4a 9a 20 44 1e 2b 62 97 4e 1f 5a 62 92 a2 97 70 14 bd 1e 3d ea e6 3a ee bb 21 69 49 15 e4"
        )
    );
    // Certificate bytes above are opaque, historical data. No identity gate or
    // application release permission is asserted by this component regression.
}
