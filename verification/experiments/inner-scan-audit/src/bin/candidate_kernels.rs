//! Kernel timing for candidate replacements of the inner scan and the tail wipe.
//! Each candidate is checked against the production expression before timing.
//! The end-to-end effect is measured separately on patched `tls-core` variants
//! built by `candidates.py`.
use std::hint::black_box;
use std::time::Instant;

use bytemuck::pod_align_to_mut;
use tls_core::protected::{
    ContentType, MAX_INNER_PLAINTEXT, ProtectedError, ProtectedReader, ProtectedWriter,
};
use tls_crypto::{CipherSuite, CryptoProvider, NONCE_LEN};
use tls_crypto_awslc::{AwsLcKey, AwsLcProvider};
use zeroize::Zeroize;

const SUITE: CipherSuite = CipherSuite::Aes128GcmSha256;
const IV: [u8; NONCE_LEN] = [0x4D; NONCE_LEN];
const RECORD_OUTPUT: usize = 16_401;

const KERNEL_BYTES: usize = 4 << 20;
const SAMPLES: usize = 60;
const WARMUPS: usize = 5;

type Scan = fn(&[u8]) -> Option<usize>;
type Wipe = fn(&mut [u8]);
type Batch = Box<dyn Fn(usize) -> u128>;

/// Verbatim production expression from `decode_inner` (protected.rs:86-89).
fn scan_production(inner: &[u8]) -> Option<usize> {
    inner.iter().rposition(|&byte| byte != 0)
}

/// Skip zero blocks from the end, then scan the last nonzero block bytewise.
fn scan_blocks<const B: usize>(inner: &[u8]) -> Option<usize> {
    let mut end = inner.len();
    while end >= B && inner[end - B..end] == [0u8; B] {
        end -= B;
    }
    inner[..end].iter().rposition(|&byte| byte != 0)
}

fn scan_block8(inner: &[u8]) -> Option<usize> {
    scan_blocks::<8>(inner)
}
fn scan_block16(inner: &[u8]) -> Option<usize> {
    scan_blocks::<16>(inner)
}
fn scan_block32(inner: &[u8]) -> Option<usize> {
    scan_blocks::<32>(inner)
}
fn scan_block64(inner: &[u8]) -> Option<usize> {
    scan_blocks::<64>(inner)
}

/// Verbatim production expression from the tail wipe (protected.rs:321).
fn wipe_production(bytes: &mut [u8]) {
    bytes.zeroize();
}

/// Same aligned-u128 pattern as `Reassembler::drop` (handshake.rs:258-261).
fn wipe_aligned(bytes: &mut [u8]) {
    let (head, words, tail) = pod_align_to_mut::<u8, u128>(bytes);
    head.zeroize();
    words.zeroize();
    tail.zeroize();
}

fn validate_scans() {
    let candidates: [(&str, Scan); 4] = [
        ("block8", scan_block8),
        ("block16", scan_block16),
        ("block32", scan_block32),
        ("block64", scan_block64),
    ];
    let mut state = 0x243F_6A88_85A3_08D3_u64;
    let mut next = move || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    for len in (0..=300).chain([1_023, 1_024, 4_095, 4_096, 16_383, 16_384, 16_385]) {
        let mut cases = vec![vec![0u8; len]];
        let step = if len <= 300 { 1 } else { 97 };
        for pos in (0..len).step_by(step) {
            for value in [1u8, 0x80] {
                let mut bytes = vec![0u8; len];
                bytes[pos] = value;
                cases.push(bytes);
            }
        }
        for _ in 0..200 {
            let mut bytes = vec![0u8; len];
            if len > 0 {
                for _ in 0..(next() % 8) {
                    let pos = (next() as usize) % len;
                    bytes[pos] = (next() as u8) | 1;
                }
            }
            cases.push(bytes);
        }
        for bytes in &cases {
            let expected = scan_production(bytes);
            for &(name, scan) in &candidates {
                assert_eq!(scan(bytes), expected, "{name} len={len}");
            }
        }
    }
}

fn validate_wipes() {
    for offset in 0..32 {
        for size in (0..=257).chain([1_023, 1_024, 1_025, 16_383, 16_384, 16_385, 16_400, 16_401]) {
            let start = 16 + offset;
            let mut expected = vec![0xa5u8; start + size + 32];
            expected[start..start + size].fill(0);
            let mut data = vec![0xa5u8; start + size + 32];
            wipe_aligned(&mut data[start..start + size]);
            assert_eq!(data, expected, "wipe_aligned size={size} offset={offset}");
        }
    }
}

/// Scan `zeros` trailing zero bytes after a valid type byte, `iterations` times.
fn scan_batch(scan: Scan, zeros: usize, iterations: usize) -> u128 {
    let mut inner = vec![0u8; zeros + 2];
    inner[0] = 0x42;
    inner[1] = 0x17;
    let start = Instant::now();
    for _ in 0..iterations {
        black_box(scan(black_box(&inner)));
    }
    start.elapsed().as_nanos()
}

fn wipe_batch(wipe: Wipe, len: usize, iterations: usize) -> u128 {
    let mut buffer = vec![0xA5u8; len];
    let start = Instant::now();
    for _ in 0..iterations {
        wipe(black_box(&mut buffer[..]));
    }
    start.elapsed().as_nanos()
}

fn batches() -> Vec<(String, usize, Batch)> {
    let scans: [(&str, Scan); 5] = [
        ("production", scan_production),
        ("block8", scan_block8),
        ("block16", scan_block16),
        ("block32", scan_block32),
        ("block64", scan_block64),
    ];
    let wipes: [(&str, Wipe); 2] = [("production", wipe_production), ("aligned", wipe_aligned)];
    let mut out: Vec<(String, usize, Batch)> = Vec::new();
    for zeros in [0usize, 1_023, 4_095, 16_383] {
        for &(name, scan) in &scans {
            let batch: Batch = Box::new(move |n| scan_batch(scan, zeros, n));
            out.push((format!("scan_{name}_{zeros}"), zeros + 2, batch));
        }
    }
    for len in [17usize, 16_400, 16_401] {
        for &(name, wipe) in &wipes {
            let batch: Batch = Box::new(move |n| wipe_batch(wipe, len, n));
            out.push((format!("wipe_{name}_{len}"), len, batch));
        }
    }
    let reopen: Batch = Box::new(failed_reopen_batch);
    out.push(("failed_reopen_16401".into(), RECORD_OUTPUT, reopen));
    out
}

fn key() -> AwsLcKey {
    AwsLcProvider.aead_key(SUITE, &[0x37; 16]).unwrap()
}

/// A reader already in the terminal failed state, plus a record it would reject.
/// The failed state is reached once; every later `open` only reaches the `failed` branch.
fn failed_reader() -> (ProtectedReader<AwsLcKey>, Vec<u8>) {
    let mut writer =
        ProtectedWriter::new(key(), IV, MAX_INNER_PLAINTEXT, SUITE.sending_record_limit()).unwrap();
    let body = vec![0x5A; 16_384];
    let mut wire = vec![0; RECORD_OUTPUT + 5];
    let length = writer
        .seal(ContentType::ApplicationData, &body, 0, &mut wire)
        .unwrap();
    wire.truncate(length);
    let last = wire.len() - 1;
    wire[last] ^= 0x01;
    (ProtectedReader::new(key(), IV, MAX_INNER_PLAINTEXT).unwrap(), wire)
}

/// Each call on a failed reader wipes the caller's output (protected.rs `open` -> `fail`).
fn failed_reopen_batch(iterations: usize) -> u128 {
    let (mut reader, wire) = failed_reader();
    let mut out = vec![0xA5u8; RECORD_OUTPUT];
    assert!(reader.open(&wire, &mut out).is_err());
    let start = Instant::now();
    for _ in 0..iterations {
        black_box(reader.open(black_box(&wire), black_box(&mut out[..])).is_err());
    }
    start.elapsed().as_nanos()
}

fn validate_failed_reopen() {
    let (mut reader, wire) = failed_reader();
    let mut out = vec![0xA5u8; RECORD_OUTPUT];
    let first = reader.open(&wire, &mut out).map(|_| ());
    assert!(matches!(first, Err(ProtectedError::Crypto(_))), "first open: {first:?}");
    assert!(out.iter().all(|&b| b == 0), "first failure left output bytes");
    out.fill(0xA5);
    let second = reader.open(&wire, &mut out).map(|_| ());
    assert_eq!(second, Err(ProtectedError::Failed), "reopen");
    assert!(out.iter().all(|&b| b == 0), "reopen left output bytes");
}

fn main() {
    let repeat: usize = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "0".into())
        .parse()
        .unwrap();
    validate_scans();
    validate_wipes();
    validate_failed_reopen();
    let batches = batches();
    println!("group,name,sample,iterations,elapsed_ns,bytes_per_op");
    for sample in 0..SAMPLES + WARMUPS {
        for step in 0..batches.len() {
            let (name, bytes, run) = &batches[(repeat + sample + step) % batches.len()];
            let iterations = (KERNEL_BYTES / bytes).max(256);
            let elapsed = run(iterations);
            if sample >= WARMUPS {
                println!(
                    "candidate,{name},{},{iterations},{elapsed},{bytes}",
                    sample - WARMUPS
                );
            }
        }
    }
}
