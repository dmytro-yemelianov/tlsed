//! Timing and sampling targets for `ProtectedReader::open` on long, padded, and
//! corrupted records. The reader and AES-128-GCM are the production code. The
//! `Kernel` variants run verbatim copies of the inner scan and tail wipe from
//! `protected.rs` so their cost can be separated from AEAD work.
use std::hint::black_box;
use std::time::{Duration, Instant};

use tls_core::protected::{
    ContentType, MAX_INNER_PLAINTEXT, ProtectedError, ProtectedReader, ProtectedWriter,
};
use tls_core::wire::{HEADER_LEN, Parse};
use tls_crypto::{AeadKey, CipherSuite, CryptoError, CryptoProvider, NONCE_LEN, TAG_LEN};
use tls_crypto_awslc::{AwsLcKey, AwsLcProvider};
use zeroize::Zeroize;

const SUITE: CipherSuite = CipherSuite::Aes128GcmSha256;
const IV: [u8; NONCE_LEN] = [0x4D; NONCE_LEN];
/// Scratch for sealing. Reads use the active prefix `wire.len() - HEADER_LEN`,
/// exactly as `tls-client/src/lib.rs` passes `plain[..record.len() - 5]`.
const OUTPUT_LEN: usize = 16_645;
const RECORDS: usize = 512;
const SAMPLES: usize = 60;
const WARMUPS: usize = 5;
const KERNEL_BYTES: usize = 4 << 20;

#[derive(Clone, Copy)]
enum Target {
    /// Authenticated record; `content` bytes followed by type and `padding` zeros.
    Valid { content: usize, padding: usize },
    /// Flipped tag byte: AEAD fails before any inner-plaintext scan.
    TagFailure { content: usize },
    /// Authenticated inner with invalid type byte after `padding` zeros.
    InnerFailure { padding: usize },
}

const CASES: [(&str, Target); 8] = [
    (
        "short",
        Target::Valid {
            content: 1,
            padding: 0,
        },
    ),
    (
        "long",
        Target::Valid {
            content: 16_384,
            padding: 0,
        },
    ),
    (
        "pad1k",
        Target::Valid {
            content: 1,
            padding: 1_023,
        },
    ),
    (
        "pad4k",
        Target::Valid {
            content: 1,
            padding: 4_095,
        },
    ),
    (
        "padmax",
        Target::Valid {
            content: 1,
            padding: 16_383,
        },
    ),
    ("tag_short", Target::TagFailure { content: 1 }),
    ("tag_long", Target::TagFailure { content: 16_384 }),
    ("inner_padmax", Target::InnerFailure { padding: 16_383 }),
];

#[derive(Clone, Copy)]
enum Kernel {
    /// `decode_inner` step: `rposition(nonzero)` over `zeros` trailing zero bytes.
    Scan(usize),
    /// `output[content_len..].zeroize()` over `len` bytes.
    Zeroize(usize),
    /// Copy ciphertext into the caller buffer.
    Copy,
    /// Copy ciphertext and authenticate/decrypt it in place.
    Open,
}

/// Zeroize sizes are active-prefix lengths: long tail 16,401 - 16,384 = 17;
/// max-padding tail 16,401 - 1 = 16,400; failure wipes the whole 16,401 B prefix.
const KERNELS: [(&str, Kernel, usize); 11] = [
    ("scan_zeros_0", Kernel::Scan(0), 0),
    ("scan_zeros_1023", Kernel::Scan(1_023), 0),
    ("scan_zeros_4095", Kernel::Scan(4_095), 0),
    ("scan_zeros_16383", Kernel::Scan(16_383), 0),
    ("zeroize_tail_17", Kernel::Zeroize(17), 0),
    ("zeroize_tail_16400", Kernel::Zeroize(16_400), 0),
    ("zeroize_prefix_16401", Kernel::Zeroize(16_401), 0),
    ("copy_record_18", Kernel::Copy, 1),
    ("open_record_18", Kernel::Open, 1),
    ("copy_record_16401", Kernel::Copy, 16_384),
    ("open_record_16401", Kernel::Open, 16_384),
];

fn key() -> AwsLcKey {
    AwsLcProvider.aead_key(SUITE, &[0x37; 16]).unwrap()
}

fn reader() -> ProtectedReader<AwsLcKey> {
    ProtectedReader::new(key(), IV, MAX_INNER_PLAINTEXT).unwrap()
}

fn writer() -> ProtectedWriter<AwsLcKey> {
    ProtectedWriter::new(key(), IV, MAX_INNER_PLAINTEXT, SUITE.sending_record_limit()).unwrap()
}

fn seal_with(writer: &mut ProtectedWriter<AwsLcKey>, body: &[u8], padding: usize) -> Vec<u8> {
    let mut wire = vec![0; OUTPUT_LEN];
    let length = writer
        .seal(ContentType::ApplicationData, body, padding, &mut wire)
        .unwrap();
    wire.truncate(length);
    wire
}

/// Authenticated record whose last nonzero inner byte is an invalid type.
/// Built with the raw AEAD key because the writer accepts only valid types.
fn inner_failure_wire(padding: usize) -> Vec<u8> {
    let inner_len = 2 + padding;
    let mut inner = vec![0u8; inner_len];
    inner[0] = 0x42;
    inner[1] = 0x55;
    let length = inner_len + TAG_LEN;
    let mut wire = vec![0; HEADER_LEN + length];
    wire[..3].copy_from_slice(&[23, 3, 3]);
    wire[3..5].copy_from_slice(&(length as u16).to_be_bytes());
    wire[HEADER_LEN..HEADER_LEN + inner_len].copy_from_slice(&inner);
    let aad = wire[..HEADER_LEN].to_vec();
    key()
        .seal_in_place(&IV, &aad, &mut wire[HEADER_LEN..], inner_len)
        .unwrap();
    wire
}

/// Each sample needs fresh readers that start at sequence 0, so one record per
/// case is reused for every batch. Failure cases clone one record.
fn records(target: Target) -> Vec<Vec<u8>> {
    match target {
        Target::Valid { content, padding } => {
            let body = vec![0x5A; content];
            let mut writer = writer();
            (0..RECORDS)
                .map(|_| seal_with(&mut writer, &body, padding))
                .collect()
        }
        Target::TagFailure { content } => {
            let body = vec![0x5A; content];
            let mut wire = seal_with(&mut writer(), &body, 0);
            let last = wire.len() - 1;
            wire[last] ^= 0x01;
            vec![wire; RECORDS]
        }
        Target::InnerFailure { padding } => vec![inner_failure_wire(padding); RECORDS],
    }
}

/// Checks each case before timing: valid records open to the expected content,
/// and failures return the expected error and leave no output bytes behind.
fn validate(name: &str, target: Target, records: &[Vec<u8>]) {
    let mut out = vec![0xA5; OUTPUT_LEN];
    let active = records[0].len() - HEADER_LEN;
    match target {
        Target::Valid { content, .. } => {
            let mut reader = reader();
            for wire in records {
                let prefix = &mut out[..wire.len() - HEADER_LEN];
                match reader.open(wire, prefix) {
                    Ok(Parse::Complete { value, consumed }) => {
                        assert_eq!(value.content_type, ContentType::ApplicationData, "{name}");
                        assert_eq!(value.content.len(), content, "{name}");
                        assert!(value.content.iter().all(|&b| b == 0x5A), "{name}");
                        assert_eq!(consumed, wire.len(), "{name}");
                    }
                    _ => panic!("{name}: valid record did not open"),
                }
            }
        }
        Target::TagFailure { .. } => {
            let outcome = reader().open(&records[0], &mut out[..active]).map(|_| ());
            assert_eq!(
                outcome,
                Err(ProtectedError::Crypto(CryptoError::AuthenticationFailed)),
                "{name}"
            );
            assert!(
                out[..active].iter().all(|&b| b == 0),
                "{name}: output not wiped"
            );
        }
        Target::InnerFailure { .. } => {
            let outcome = reader().open(&records[0], &mut out[..active]).map(|_| ());
            assert_eq!(outcome, Err(ProtectedError::InvalidInner), "{name}");
            assert!(
                out[..active].iter().all(|&b| b == 0),
                "{name}: output not wiped"
            );
        }
    }
}

/// Times one batch of `records.len()` operations. Reader setup and key creation
/// happen before the timer starts; the reader drop happens after it stops.
fn run_case(target: Target, records: &[Vec<u8>], out: &mut [u8]) -> u128 {
    match target {
        Target::Valid { .. } => {
            let mut reader = reader();
            let start = Instant::now();
            for wire in records {
                let prefix = &mut out[..wire.len() - HEADER_LEN];
                black_box(reader.open(black_box(wire.as_slice()), prefix).is_ok());
            }
            start.elapsed().as_nanos()
        }
        Target::TagFailure { .. } | Target::InnerFailure { .. } => {
            let mut readers: Vec<_> = records.iter().map(|_| reader()).collect();
            let start = Instant::now();
            for (reader, wire) in readers.iter_mut().zip(records) {
                let prefix = &mut out[..wire.len() - HEADER_LEN];
                black_box(reader.open(black_box(wire.as_slice()), prefix).is_ok());
            }
            start.elapsed().as_nanos()
        }
    }
}

/// Verbatim from `decode_inner` (protected.rs:88), applied to a `zeros`-byte
/// zero run after a valid type byte. Buffer setup is outside the timer.
fn scan_batch(zeros: usize, iterations: usize) -> u128 {
    let mut inner = vec![0u8; zeros + 2];
    inner[0] = 0x42;
    inner[1] = 0x17;
    let start = Instant::now();
    for _ in 0..iterations {
        black_box(black_box(&inner).iter().rposition(|&byte| byte != 0));
    }
    start.elapsed().as_nanos()
}

/// Verbatim from `output[content_len..].zeroize()` (protected.rs:321).
fn zeroize_batch(len: usize, iterations: usize) -> u128 {
    let mut buffer = vec![0xA5u8; len];
    let start = Instant::now();
    for _ in 0..iterations {
        black_box(&mut buffer[..]).zeroize();
    }
    start.elapsed().as_nanos()
}

/// Copy `wire`'s payload into a reusable buffer, optionally followed by in-place open.
fn copy_or_open(wire: &[u8], iterations: usize, open: bool) -> u128 {
    let key = key();
    let aad = &wire[..HEADER_LEN];
    let pristine = &wire[HEADER_LEN..];
    let mut buffer = pristine.to_vec();
    let start = Instant::now();
    for _ in 0..iterations {
        buffer.copy_from_slice(black_box(pristine));
        if open {
            let result = key.open_in_place(&IV, black_box(aad), black_box(buffer.as_mut_slice()));
            black_box(result.is_ok());
        }
    }
    start.elapsed().as_nanos()
}

fn run_kernel(kernel: Kernel, wire: &[u8], iterations: usize) -> u128 {
    match kernel {
        Kernel::Scan(zeros) => scan_batch(zeros, iterations),
        Kernel::Zeroize(len) => zeroize_batch(len, iterations),
        Kernel::Copy => copy_or_open(wire, iterations, false),
        Kernel::Open => copy_or_open(wire, iterations, true),
    }
}

fn kernel_bytes(kernel: Kernel, wire: &[u8]) -> usize {
    match kernel {
        Kernel::Scan(zeros) => zeros + 2,
        Kernel::Zeroize(len) => len,
        Kernel::Copy | Kernel::Open => wire.len(),
    }
}

fn bench(repeat: usize) {
    let cases: Vec<_> = CASES
        .iter()
        .map(|&(name, target)| {
            let records = records(target);
            validate(name, target, &records);
            (name, target, records)
        })
        .collect();
    let kernels: Vec<_> = KERNELS
        .iter()
        .map(|&(name, kernel, content)| {
            let wire = match kernel {
                Kernel::Copy | Kernel::Open => records(Target::Valid {
                    content,
                    padding: 0,
                })
                .swap_remove(0),
                _ => Vec::new(),
            };
            (name, kernel, wire)
        })
        .collect();

    let mut out = vec![0xA5; OUTPUT_LEN];
    println!("group,name,sample,iterations,elapsed_ns,bytes_per_op");
    for sample in 0..SAMPLES + WARMUPS {
        for step in 0..cases.len() {
            let (name, target, records) = &cases[(repeat + sample + step) % cases.len()];
            let elapsed = run_case(*target, records, &mut out);
            if sample >= WARMUPS {
                println!(
                    "case,{name},{},{},{elapsed},0",
                    sample - WARMUPS,
                    records.len()
                );
            }
        }
        for step in 0..kernels.len() {
            let (name, kernel, wire) = &kernels[(repeat + sample + step) % kernels.len()];
            let bytes = kernel_bytes(*kernel, wire);
            let iterations = (KERNEL_BYTES / bytes).max(256);
            let elapsed = run_kernel(*kernel, wire, iterations);
            if sample >= WARMUPS {
                println!(
                    "kernel,{name},{},{iterations},{elapsed},{bytes}",
                    sample - WARMUPS
                );
            }
        }
    }
}

/// Runs one case in a loop for `seconds` so an external sampler can attach.
fn profile(name: &str, seconds: u64) {
    let &(_, target) = CASES
        .iter()
        .find(|(case, _)| *case == name)
        .unwrap_or_else(|| panic!("unknown case {name}"));
    let records = records(target);
    validate(name, target, &records);
    let deadline = Instant::now() + Duration::from_secs(seconds);
    let mut out = vec![0xA5; OUTPUT_LEN];
    let mut batches = 0u64;
    while Instant::now() < deadline {
        black_box(run_case(target, &records, &mut out));
        batches += 1;
    }
    eprintln!("{name}: {batches} batches of {RECORDS}");
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>()
        .as_slice()
    {
        ["bench", repeat] => bench(repeat.parse().unwrap()),
        ["loop", name, seconds] => profile(name, seconds.parse().unwrap()),
        _ => {
            eprintln!("usage: tlsed-inner-scan-audit bench <repeat> | loop <case> <seconds>");
            std::process::exit(2);
        }
    }
}
