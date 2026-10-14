use std::cell::Cell;
use std::rc::Rc;
use tls_core::transcript::{HELLO_RETRY_REQUEST_RANDOM, Phase, Transcript, TranscriptError};
use tls_crypto::{
    CryptoError, CryptoProvider, HandshakeCryptoProvider, HashAlgorithm, HashContext,
};
use tls_crypto_awslc::AwsLcProvider;

fn frame(kind: u8, body: &[u8]) -> Vec<u8> {
    let len = body.len();
    let mut encoded = vec![kind, (len >> 16) as u8, (len >> 8) as u8, len as u8];
    encoded.extend_from_slice(body);
    encoded
}

fn retry() -> Vec<u8> {
    let mut body = vec![3, 3];
    body.extend_from_slice(&HELLO_RETRY_REQUEST_RANDOM);
    // Minimal syntactic ServerHello tail; full extension negotiation is future FSM work.
    body.extend_from_slice(&[0, 0x13, 1, 0, 0, 6, 0, 43, 0, 2, 3, 4]);
    frame(2, &body)
}

fn expected(algorithm: HashAlgorithm, input: &[u8]) -> Vec<u8> {
    let mut out = vec![0; algorithm.output_len()];
    AwsLcProvider.hash(algorithm, input, &mut out).unwrap();
    out
}

#[test]
fn streaming_order_headers_snapshots_and_freeze() {
    for algorithm in [HashAlgorithm::Sha256, HashAlgorithm::Sha384] {
        let context = AwsLcProvider.hash_context(algorithm).unwrap();
        let mut transcript = Transcript::new(context, 4096, 10000, 16).unwrap();
        assert_eq!(
            transcript.snapshot().unwrap().as_bytes(),
            expected(algorithm, b"")
        );
        let messages = [
            frame(1, &[1, 2]),
            frame(2, &[3, 4]),
            frame(8, &[0, 0]),
            frame(20, &[5; 32]),
        ];
        let mut all = Vec::new();
        for encoded in &messages {
            transcript.append(encoded).unwrap();
            all.extend_from_slice(encoded);
            let first = transcript.snapshot().unwrap();
            let second = transcript.snapshot().unwrap();
            assert_eq!(first.algorithm(), algorithm);
            assert_eq!(first.as_bytes(), expected(algorithm, &all));
            assert_eq!(first.as_bytes(), second.as_bytes());
        }
        assert_eq!(transcript.message_count(), 4);
        assert_eq!(transcript.hashed_bytes(), all.len() as u64);
        assert_eq!(
            transcript.freeze().unwrap().as_bytes(),
            expected(algorithm, &all)
        );
        assert_eq!(transcript.phase(), Phase::Frozen);
        assert_eq!(
            transcript.append(&frame(20, &[1])),
            Err(TranscriptError::Frozen)
        );
        assert!(matches!(
            transcript.snapshot(),
            Err(TranscriptError::Frozen)
        ));
    }
}

#[test]
fn constructor_discards_preexisting_provider_history() {
    for algorithm in [HashAlgorithm::Sha256, HashAlgorithm::Sha384] {
        let mut context = AwsLcProvider.hash_context(algorithm).unwrap();
        context.update(b"hidden previous hash history").unwrap();
        let mut transcript = Transcript::new(context, 4096, 10000, 16).unwrap();
        assert_eq!(transcript.hashed_bytes(), 0);
        assert_eq!(transcript.message_count(), 0);
        assert_eq!(
            transcript.snapshot().unwrap().as_bytes(),
            expected(algorithm, b"")
        );
        let ch = frame(1, &[1, 2, 3]);
        let hrr = retry();
        transcript.append(&ch).unwrap();
        assert_eq!(
            transcript.snapshot().unwrap().as_bytes(),
            expected(algorithm, &ch)
        );
        transcript.apply_hello_retry_request(&hrr).unwrap();
        let mut rewritten = frame(254, &expected(algorithm, &ch));
        rewritten.extend_from_slice(&hrr);
        assert_eq!(
            transcript.snapshot().unwrap().as_bytes(),
            expected(algorithm, &rewritten)
        );
    }
}

#[test]
fn hrr_rewrites_exact_encoded_history_for_both_hashes() {
    for algorithm in [HashAlgorithm::Sha256, HashAlgorithm::Sha384] {
        let context = AwsLcProvider.hash_context(algorithm).unwrap();
        let mut transcript = Transcript::new(context, 4096, 10000, 16).unwrap();
        let ch1 = frame(1, &[10, 20, 30]);
        let hrr = retry();
        transcript.append(&ch1).unwrap();
        let mut rewritten = frame(254, &expected(algorithm, &ch1));
        rewritten.extend_from_slice(&hrr);
        transcript.apply_hello_retry_request(&hrr).unwrap();
        assert!(transcript.retried());
        assert_eq!(transcript.phase(), Phase::AwaitRetryClientHello);
        assert_eq!(transcript.message_count(), 2);
        assert_eq!(
            transcript.snapshot().unwrap().as_bytes(),
            expected(algorithm, &rewritten)
        );
        assert_eq!(
            transcript.hashed_bytes(),
            (ch1.len() + rewritten.len()) as u64
        );
        let ch2 = frame(1, &[11, 22, 33]);
        let sh = frame(2, &[44, 55]);
        transcript.append(&ch2).unwrap();
        transcript.append(&sh).unwrap();
        rewritten.extend_from_slice(&ch2);
        rewritten.extend_from_slice(&sh);
        assert_eq!(
            transcript.snapshot().unwrap().as_bytes(),
            expected(algorithm, &rewritten)
        );
        assert_eq!(
            transcript.apply_hello_retry_request(&hrr),
            Err(TranscriptError::UnexpectedStage)
        );
        assert_eq!(transcript.phase(), Phase::Failed);
    }
}

#[test]
fn hrr_legacy_version_is_ignored_after_endpoint_version_selection() {
    for version in [0_u16, 0x0301, 0xffff] {
        let algorithm = HashAlgorithm::Sha256;
        let mut transcript = Transcript::new(
            AwsLcProvider.hash_context(algorithm).unwrap(),
            4096,
            10000,
            16,
        )
        .unwrap();
        let ch = frame(1, &[1, 2]);
        let mut hrr = retry();
        hrr[4..6].copy_from_slice(&version.to_be_bytes());
        transcript.append(&ch).unwrap();
        transcript.apply_hello_retry_request(&hrr).unwrap();
        let mut history = frame(254, &expected(algorithm, &ch));
        history.extend_from_slice(&hrr);
        assert_eq!(
            transcript.snapshot().unwrap().as_bytes(),
            expected(algorithm, &history)
        );
    }
}

#[test]
fn malformed_extra_and_post_handshake_bytes_never_advance() {
    for input in [
        vec![],
        vec![1, 0, 0],
        vec![1, 0, 0, 2, 1],
        vec![1, 0, 0, 0, 1],
        frame(254, &[1]),
        frame(4, &[1]),
        frame(24, &[1]),
        frame(5, &[]),
    ] {
        let context = AwsLcProvider.hash_context(HashAlgorithm::Sha256).unwrap();
        let mut transcript = Transcript::new(context, 16, 100, 10).unwrap();
        assert_eq!(
            transcript.append(&input),
            Err(TranscriptError::InvalidMessage)
        );
        assert_eq!(transcript.message_count(), 0);
        assert_eq!(transcript.hashed_bytes(), 0);
        assert_eq!(transcript.phase(), Phase::Failed);
        assert!(matches!(
            transcript.snapshot(),
            Err(TranscriptError::Failed)
        ));
    }
}

#[test]
fn resource_caps_and_hello_order_poison_before_hash_progress() {
    for limit in [false, true] {
        let context = AwsLcProvider.hash_context(HashAlgorithm::Sha256).unwrap();
        let mut transcript = Transcript::new(
            context,
            8,
            if limit { 100 } else { 5 },
            if limit { 1 } else { 10 },
        )
        .unwrap();
        let ch = frame(1, &[0]);
        transcript.append(&ch).unwrap();
        assert_eq!(
            transcript.append(&frame(2, &[1])),
            Err(TranscriptError::ResourceLimit)
        );
        assert_eq!(transcript.message_count(), 1);
        assert_eq!(transcript.hashed_bytes(), 5);
    }
    for first in [frame(2, &[0]), frame(8, &[0])] {
        let context = AwsLcProvider.hash_context(HashAlgorithm::Sha256).unwrap();
        let mut transcript = Transcript::new(context, 8, 100, 10).unwrap();
        assert_eq!(
            transcript.append(&first),
            Err(TranscriptError::UnexpectedStage)
        );
    }
    let context = AwsLcProvider.hash_context(HashAlgorithm::Sha256).unwrap();
    let mut transcript = Transcript::new(context, 2, 100, 10).unwrap();
    assert_eq!(
        transcript.append(&frame(1, &[0, 1, 2])),
        Err(TranscriptError::InvalidMessage)
    );
}

#[test]
fn retry_wrong_stage_sentinel_direct_append_and_budget_are_rejected() {
    for mode in 0..4 {
        let context = AwsLcProvider.hash_context(HashAlgorithm::Sha256).unwrap();
        let mut transcript =
            Transcript::new(context, 100, if mode == 3 { 60 } else { 1000 }, 10).unwrap();
        if mode != 0 {
            transcript.append(&frame(1, &[1])).unwrap();
        }
        let mut hrr = retry();
        let failure = match mode {
            0 => transcript.apply_hello_retry_request(&hrr),
            1 => {
                hrr[6] ^= 1;
                transcript.apply_hello_retry_request(&hrr)
            }
            2 => transcript.append(&hrr),
            _ => transcript.apply_hello_retry_request(&hrr),
        };
        assert_eq!(
            failure,
            Err(match mode {
                0 => TranscriptError::UnexpectedStage,
                1 => TranscriptError::InvalidMessage,
                2 => TranscriptError::RetryRequiresRewrite,
                _ => TranscriptError::ResourceLimit,
            })
        );
        assert_eq!(transcript.phase(), Phase::Failed);
    }
}

struct FailingContext {
    dropped: Rc<Cell<usize>>,
    fail_reset: bool,
    change_algorithm: bool,
    algorithm: HashAlgorithm,
}
impl Drop for FailingContext {
    fn drop(&mut self) {
        self.dropped.set(self.dropped.get() + 1);
    }
}
impl HashContext for FailingContext {
    fn algorithm(&self) -> HashAlgorithm {
        self.algorithm
    }
    fn update(&mut self, _: &[u8]) -> Result<(), CryptoError> {
        Err(CryptoError::BackendFailure)
    }
    fn snapshot(&self, output: &mut [u8]) -> Result<(), CryptoError> {
        output.fill(0x55);
        Err(CryptoError::BackendFailure)
    }
    fn reset(&mut self) -> Result<(), CryptoError> {
        if self.fail_reset {
            Err(CryptoError::BackendFailure)
        } else {
            if self.change_algorithm {
                self.algorithm = HashAlgorithm::Sha384;
            }
            Ok(())
        }
    }
}

#[test]
fn constructor_retires_failed_or_algorithm_changing_context() {
    for fail_reset in [false, true] {
        let dropped = Rc::new(Cell::new(0));
        let result = Transcript::new(
            FailingContext {
                dropped: dropped.clone(),
                fail_reset,
                change_algorithm: !fail_reset,
                algorithm: HashAlgorithm::Sha256,
            },
            16,
            100,
            10,
        );
        assert!(matches!(result, Err(error) if error == if fail_reset {
            TranscriptError::Crypto(CryptoError::BackendFailure)
        } else { TranscriptError::ProviderAlgorithm }));
        assert_eq!(dropped.get(), 1);
    }
}

#[test]
fn provider_errors_retire_context_once_and_never_return_partial_digest() {
    for snapshot in [false, true] {
        let dropped = Rc::new(Cell::new(0));
        let mut transcript = Transcript::new(
            FailingContext {
                dropped: dropped.clone(),
                fail_reset: false,
                change_algorithm: false,
                algorithm: HashAlgorithm::Sha256,
            },
            16,
            100,
            10,
        )
        .unwrap();
        if snapshot {
            assert!(matches!(
                transcript.snapshot(),
                Err(TranscriptError::Crypto(CryptoError::BackendFailure))
            ));
        } else {
            assert_eq!(
                transcript.append(&frame(1, &[1])),
                Err(TranscriptError::Crypto(CryptoError::BackendFailure))
            );
        }
        assert_eq!(transcript.phase(), Phase::Failed);
        assert_eq!(dropped.get(), 1);
        assert_eq!(
            transcript.append(&frame(1, &[1])),
            Err(TranscriptError::Failed)
        );
        drop(transcript);
        assert_eq!(dropped.get(), 1);
    }
}
