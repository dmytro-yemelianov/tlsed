#![no_main]
use libfuzzer_sys::fuzz_target;
use tls_core::key_schedule::{
    MAX_HKDF_LABEL, encode_hkdf_label, expand_label, hkdf_label_encoded_len,
};
use tls_core::transcript::{HELLO_RETRY_REQUEST_RANDOM, Phase, Transcript, TranscriptError};
use tls_crypto::{CryptoProvider, HandshakeCryptoProvider, HashAlgorithm, HashContext};
use tls_crypto_awslc::{AwsLcHashContext, AwsLcProvider};

fn frame(kind: u8, body: &[u8]) -> Vec<u8> {
    let mut out = vec![
        kind,
        ((body.len() >> 16) & 255) as u8,
        ((body.len() >> 8) & 255) as u8,
        (body.len() & 255) as u8,
    ];
    out.extend_from_slice(body);
    out
}
fn retry() -> Vec<u8> {
    let mut body = vec![3, 3];
    body.extend_from_slice(&HELLO_RETRY_REQUEST_RANDOM);
    body.extend_from_slice(&[0, 0x13, 1, 0, 0, 6, 0, 43, 0, 2, 3, 4]);
    frame(2, &body)
}
fn hash(alg: HashAlgorithm, input: &[u8]) -> Vec<u8> {
    let mut output = vec![0; alg.output_len()];
    AwsLcProvider.hash(alg, input, &mut output).unwrap();
    output
}
fn valid_encoded(input: &[u8], cap: usize) -> bool {
    let Some(header) = input.get(..4) else {
        return false;
    };
    let size =
        (usize::from(header[1]) << 16) | (usize::from(header[2]) << 8) | usize::from(header[3]);
    size <= cap && input.len() == size + 4 && matches!(header[0], 1 | 2 | 8 | 11 | 13 | 15 | 20)
}

fn preloaded_context(alg: HashAlgorithm, input: &[u8]) -> AwsLcHashContext {
    let mut context = AwsLcProvider.hash_context(alg).unwrap();
    context.update(&input[..input.len().min(64)]).unwrap();
    context
}

fn rejected_phase(transcript: &Transcript<AwsLcHashContext>, before: Phase) {
    let expected = if matches!(before, Phase::Failed | Phase::Frozen) {
        before
    } else {
        Phase::Failed
    };
    assert!(transcript.phase() == expected);
}

fn streaming_trace(data: &[u8], alg: HashAlgorithm) {
    let controls = [
        data.first().copied().unwrap_or_default(),
        data.get(1).copied().unwrap_or_default(),
        data.get(2).copied().unwrap_or_default(),
        data.get(3).copied().unwrap_or_default(),
    ];
    let cap = usize::from(controls[1] % 128);
    let byte_cap = 4 + u64::from(u16::from_be_bytes([controls[2], controls[3]]));
    let message_cap = 1 + u64::from(controls[0] % 16);
    let mut transcript =
        Transcript::new(preloaded_context(alg, data), cap, byte_cap, message_cap).unwrap();
    let mut history = vec![];
    let mut expected_work = 0_u64;
    let mut expected_messages = 0_u64;
    let mut cursor = data.len().min(4);
    for _ in 0..32 {
        let Some(&control) = data.get(cursor) else {
            break;
        };
        cursor += 1;
        let take = usize::from(control % 65).min(data.len() - cursor);
        let body = &data[cursor..cursor + take];
        cursor += take;
        let before = transcript.phase();
        match control % 4 {
            0 => {
                let kind = [1, 2, 8, 11, 13, 15, 20, 4, 24, 254, 0][usize::from(control / 4) % 11];
                let mut encoded = frame(kind, body);
                if control & 0x80 != 0 {
                    encoded[1..4].copy_from_slice(&[255, 255, 255]);
                }
                let legal = matches!(
                    (before, kind),
                    (Phase::BeforeClientHello, 1)
                        | (Phase::AwaitServerHello | Phase::AwaitFinalServerHello, 2)
                        | (Phase::AwaitRetryClientHello, 1)
                        | (Phase::Handshake, 8 | 11 | 13 | 15 | 20)
                );
                let is_retry =
                    kind == 2 && encoded.get(6..38) == Some(HELLO_RETRY_REQUEST_RANDOM.as_slice());
                let budget = expected_work + encoded.len() as u64 <= byte_cap
                    && expected_messages < message_cap;
                let result = transcript.append(&encoded);
                if result.is_ok() {
                    assert!(legal && valid_encoded(&encoded, cap) && budget && !is_retry);
                    history.extend_from_slice(&encoded);
                    expected_work += encoded.len() as u64;
                    expected_messages += 1;
                } else {
                    rejected_phase(&transcript, before);
                    assert!(
                        matches!(before, Phase::Failed | Phase::Frozen)
                            || !legal
                            || !valid_encoded(&encoded, cap)
                            || !budget
                    );
                }
            }
            1 => {
                let result = transcript.snapshot();
                match result {
                    Ok(digest) => {
                        assert!(!matches!(before, Phase::Failed | Phase::Frozen));
                        assert!(
                            digest.algorithm() == alg && digest.as_bytes() == hash(alg, &history)
                        );
                        assert!(transcript.phase() == before);
                    }
                    Err(error) => assert!(matches!(
                        (before, error),
                        (Phase::Failed, TranscriptError::Failed)
                            | (Phase::Frozen, TranscriptError::Frozen)
                    )),
                }
            }
            2 => {
                let mut hrr = retry();
                if control & 0x80 != 0 {
                    hrr[6] ^= 1;
                }
                let work = hrr.len() as u64 + 4 + alg.output_len() as u64;
                let legal = before == Phase::AwaitServerHello
                    && expected_messages == 1
                    && !transcript.retried();
                let syntax = valid_encoded(&hrr, cap)
                    && hrr.get(6..38) == Some(HELLO_RETRY_REQUEST_RANDOM.as_slice());
                let budget = expected_work + work <= byte_cap && expected_messages < message_cap;
                let result = transcript.apply_hello_retry_request(&hrr);
                if result.is_ok() {
                    assert!(legal && syntax && budget);
                    let mut rewritten = frame(254, &hash(alg, &history));
                    rewritten.extend_from_slice(&hrr);
                    history = rewritten;
                    expected_work += work;
                    expected_messages += 1;
                    assert!(
                        transcript.phase() == Phase::AwaitRetryClientHello && transcript.retried()
                    );
                } else {
                    rejected_phase(&transcript, before);
                    assert!(
                        matches!(before, Phase::Failed | Phase::Frozen)
                            || !legal
                            || !syntax
                            || !budget
                    );
                }
            }
            _ => match transcript.freeze() {
                Ok(digest) => {
                    assert!(before == Phase::Handshake);
                    assert!(digest.as_bytes() == hash(alg, &history));
                    assert!(transcript.phase() == Phase::Frozen);
                }
                Err(_) => assert!(before != Phase::Handshake),
            },
        }
        assert!(
            transcript.hashed_bytes() == expected_work
                && transcript.message_count() == expected_messages
        );
        assert!(expected_work <= byte_cap && expected_messages <= message_cap);
        if !matches!(transcript.phase(), Phase::Failed | Phase::Frozen) {
            assert!(transcript.snapshot().unwrap().as_bytes() == hash(alg, &history));
        }
    }
}

fn valid_retry_flow(data: &[u8], alg: HashAlgorithm) {
    let body = &data[..data.len().min(64)];
    let ch1 = frame(1, body);
    let hrr = retry();
    let ch2 = frame(1, &body[..body.len() / 2]);
    let sh = frame(2, &body[..body.len().min(32)]);
    let mut transcript = Transcript::new(preloaded_context(alg, data), 128, 4096, 32).unwrap();
    transcript.append(&ch1).unwrap();
    transcript.apply_hello_retry_request(&hrr).unwrap();
    let mut history = frame(254, &hash(alg, &ch1));
    history.extend_from_slice(&hrr);
    for encoded in [&ch2, &sh, &frame(8, body), &frame(20, &[0x37; 32])] {
        transcript.append(encoded).unwrap();
        history.extend_from_slice(encoded);
        assert!(transcript.snapshot().unwrap().as_bytes() == hash(alg, &history));
    }
    assert!(transcript.hashed_bytes() == (ch1.len() + history.len()) as u64);
    assert!(transcript.message_count() == 6);
    assert!(transcript.freeze().unwrap().as_bytes() == hash(alg, &history));
    assert!(matches!(
        transcript.snapshot(),
        Err(TranscriptError::Frozen)
    ));
    assert!(matches!(
        transcript.append(&ch1),
        Err(TranscriptError::Frozen)
    ));
}

fn labels(data: &[u8], alg: HashAlgorithm) {
    let label_len = usize::from(data.first().copied().unwrap_or_default());
    let context_len = usize::from(data.get(1).copied().unwrap_or_default());
    let output_len = usize::from(u16::from_be_bytes([
        data.get(2).copied().unwrap_or_default(),
        data.get(3).copied().unwrap_or_default(),
    ]));
    let mut label = [0x31; 255];
    let mut context = [0x52; 255];
    for (index, byte) in data.iter().skip(4).take(255).enumerate() {
        label[index] = *byte;
        context[index] = byte.wrapping_add(1);
    }
    let label = &label[..label_len];
    let context = &context[..context_len];
    let capacity = usize::from(data.get(4).copied().unwrap_or_default()) * 3;
    let capacity = capacity.min(MAX_HKDF_LABEL + 1);
    let mut encoded = [0xA5; MAX_HKDF_LABEL + 1];
    let result = encode_hkdf_label(output_len, label, context, &mut encoded[..capacity]);
    let expected = hkdf_label_encoded_len(output_len, label_len, context_len);
    match result {
        Ok(length) => {
            assert!(Some(length) == expected && length <= capacity);
            assert!(usize::from(u16::from_be_bytes([encoded[0], encoded[1]])) == output_len);
            assert!(usize::from(encoded[2]) == 6 + label_len);
            assert!(&encoded[3..9] == b"tls13 " && &encoded[9..9 + label_len] == label);
            assert!(
                usize::from(encoded[9 + label_len]) == context_len
                    && &encoded[10 + label_len..length] == context
            );
        }
        Err(_) => {
            assert!(expected.is_none_or(|length| length > capacity));
            assert!(encoded[..capacity].iter().all(|&byte| byte == 0));
        }
    }
    // Fixed deterministic test PRK only. Never log derived material or use these
    // repeated independent fixture derivations as a global freshness claim.
    let prk = [0x37; 48];
    let prk = &prk[..alg.output_len()];
    let mut output = [0xA5; 64];
    let length = output_len % 65;
    let result = expand_label(
        &AwsLcProvider,
        alg,
        prk,
        label,
        context,
        &mut output[..length],
    );
    if result.is_ok() {
        let mut info = [0; MAX_HKDF_LABEL];
        let size = encode_hkdf_label(length, label, context, &mut info).unwrap();
        let mut expected = [0; 64];
        AwsLcProvider
            .hkdf_expand(alg, prk, &info[..size], &mut expected[..length])
            .unwrap();
        assert!(output[..length] == expected[..length]);
    } else {
        assert!(output[..length].iter().all(|&byte| byte == 0));
    }
    output.fill(0xA5);
    assert!(
        expand_label(
            &AwsLcProvider,
            alg,
            &prk[..prk.len() - 1],
            label,
            context,
            &mut output
        )
        .is_err()
    );
    assert!(output.iter().all(|&byte| byte == 0));
}

fuzz_target!(|data: &[u8]| {
    let alg = if data.first().copied().unwrap_or_default() & 1 == 0 {
        HashAlgorithm::Sha256
    } else {
        HashAlgorithm::Sha384
    };
    streaming_trace(data, alg);
    valid_retry_flow(data, alg);
    labels(data, alg);
});
