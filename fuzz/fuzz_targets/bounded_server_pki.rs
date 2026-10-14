#![no_main]
use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;
use tls_pki::{
    CertificateDer, ChainLimits, PkiError, RevocationPolicy, ServerName, ServerVerifier, UnixTime,
};

const BASE_CA: &[u8] = include_bytes!("../../crates/tls-bench/fixtures/ca.der");
const BASE_LEAF: &[u8] = include_bytes!("../../crates/tls-bench/fixtures/server.der");
const KU_ROOT: &[u8] = include_bytes!("../../crates/tls-pki/tests/fixtures/ku-root.der");
const GOOD: &[u8] = include_bytes!("../../crates/tls-pki/tests/fixtures/ku-intermediate-good.der");
const BAD: &[u8] = include_bytes!("../../crates/tls-pki/tests/fixtures/ku-intermediate-bad.der");
const ABSENT: &[u8] =
    include_bytes!("../../crates/tls-pki/tests/fixtures/ku-intermediate-absent.der");
const LEAF: &[u8] = include_bytes!("../../crates/tls-pki/tests/fixtures/ku-leaf-good.der");
const NONCANONICAL: &[u8] =
    include_bytes!("../../crates/tls-pki/tests/fixtures/ku-noncanonical.der");
const UNKNOWN: &[u8] = include_bytes!("../../crates/tls-pki/tests/fixtures/ku-unknown-bit.der");
const TRUNCATED: &[u8] =
    include_bytes!("../../crates/tls-pki/tests/fixtures/ku-truncated-high-bits.der");

fn verifiers() -> &'static [ServerVerifier; 5] {
    static VERIFIERS: OnceLock<[ServerVerifier; 5]> = OnceLock::new();
    VERIFIERS.get_or_init(|| {
        // Fixed harness configuration only: no input bytes become a root.
        // Last three explicitly trust a fixed self-signed negative test fixture
        // only to reach its leaf KU parser after native signature validation.
        [BASE_CA, KU_ROOT, NONCANONICAL, UNKNOWN, TRUNCATED].map(|root| {
            ServerVerifier::new(
                &[CertificateDer::from(root)],
                ChainLimits::new(4, 2048, 4096).unwrap(),
                RevocationPolicy::NoRevocationData,
            )
            .unwrap()
        })
    })
}
fn signature() -> &'static [u8] {
    static SIGNATURE: OnceLock<Vec<u8>> = OnceLock::new();
    SIGNATURE.get_or_init(|| {
        // Public fixture signature: OpenSSL3.6.5 SHA256 with committed baseline
        // P256 test key, over server-CV domain and 32 bytes0x42. No signing/logging
        // of secret material occurs inside this target.
        let hex = "3044022053e43efcd46020c02cb85ac67c3c89c177fba090cae9418b0b371807f6982d5102204f2c0a1e236bb60cf6f205b7e45b6d886470cf11cfa98196f13ac457a9518850";
        hex.as_bytes().as_chunks::<2>().0.iter().map(|pair|
            u8::from_str_radix(std::str::from_utf8(pair).unwrap(),16).unwrap()).collect()
    })
}

fuzz_target!(|input: &[u8]| {
    // Input and verification caps independently bound work. At most four
    // submitted certificates,2048 bytes each and4096 aggregate reach parsers.
    let input = &input[..input.len().min(8192)];
    let Some(c) = input.get(..9) else {
        return;
    };
    let raw = &input[9..];
    let mode = c[0] % 12;
    let (profile, leaf, issuers): (usize, &[u8], Vec<&[u8]>) = match mode {
        0 => (0, BASE_LEAF, vec![]),
        1 => (1, LEAF, vec![GOOD]),
        2 => (1, LEAF, vec![BAD]),
        3 => (1, LEAF, vec![BAD, GOOD]),
        4 => (
            1,
            include_bytes!("../../crates/tls-pki/tests/fixtures/ku-leaf-absent.der"),
            vec![ABSENT],
        ),
        5 => (
            1,
            include_bytes!("../../crates/tls-pki/tests/fixtures/ku-leaf-bad.der"),
            vec![GOOD],
        ),
        6 => (
            1,
            include_bytes!("../../crates/tls-pki/tests/fixtures/ku-leaf-trailing.der"),
            vec![GOOD],
        ),
        7 => (0, &raw[..raw.len().min(4096)], vec![]),
        8 => (2, NONCANONICAL, vec![]),
        9 => (3, UNKNOWN, vec![]),
        10 => (4, TRUNCATED, vec![]),
        _ => (1, LEAF, vec![&raw[..raw.len().min(4096)]]),
    };
    let mut mutated = leaf.to_vec();
    for i in 0..usize::from(c[1] % 5) {
        if mutated.is_empty() {
            break;
        }
        let offset = (usize::from(u16::from_be_bytes([c[3], c[4]])) + i * 31) % mutated.len();
        mutated[offset] ^= 1 << ((usize::from(c[2]) + i) % 8);
    }
    if c[2] & 0x80 != 0 {
        mutated.truncate(usize::from(c[3]) % (mutated.len() + 1));
    }
    let mut chain: Vec<_> = std::iter::once(CertificateDer::from(mutated.as_slice()))
        .chain(issuers.iter().map(|bytes| CertificateDer::from(*bytes)))
        .collect();
    // Extra certificates test count bounds without handing more than four to
    // native verification; local construction is still at most five entries.
    if c[8] & 1 != 0 {
        while chain.len() < 5 {
            chain.push(CertificateDer::from(BASE_LEAF));
        }
    }
    if c[8] & 2 != 0 {
        chain.clear();
    }
    let now = UnixTime::since_unix_epoch(std::time::Duration::from_secs(
        [1792022400, 1577836800, 2208988800][usize::from(c[5] % 3)],
    ));
    let name =
        ServerName::try_from(["localhost", "wrong.invalid", "127.0.0.1"][usize::from(c[6] % 3)])
            .unwrap();
    let result = verifiers()[profile].verify_server_certificate(&chain, &name, now);
    let unchanged =
        c[1] % 5 == 0 && c[2] & 0x80 == 0 && c[5] % 3 == 0 && c[6] % 3 == 0 && c[8] & 3 == 0;
    if unchanged {
        match mode {
            0 | 1 | 3 | 4 => assert!(result.is_ok()),
            2 => assert!(matches!(result, Err(PkiError::MissingKeyCertSign))),
            5 => assert!(matches!(result, Err(PkiError::MissingDigitalSignature))),
            6 => assert!(matches!(result, Err(PkiError::TrailingKeyUsageData(_)))),
            8..=10 => assert!(matches!(result, Err(PkiError::InvalidKeyUsageEncoding(_)))),
            _ => {}
        }
    }
    if let Ok(verified) = result {
        let mut hash = [0x42; 48];
        let hash_len = [32, 48, 31][usize::from(c[7] % 3)];
        let mut sig = match c[7] / 3 % 3 {
            0 => signature().to_vec(),
            1 => {
                let mut sig = signature().to_vec();
                sig[0] ^= 1;
                sig
            }
            _ => raw[..raw.len().min(1025)].to_vec(),
        };
        if c[7] & 0x80 != 0 {
            hash[0] ^= 1;
        }
        let scheme = if c[7] & 0x40 != 0 { 0x0401 } else { 0x0403 };
        let cv = verified.verify_certificate_verify(scheme, &hash[..hash_len], &sig);
        if mode == 0 && unchanged && c[7] == 0 {
            assert!(cv.is_ok());
        }
        // A CV result by itself never authorizes application data in this harness.
        sig.fill(0);
    }
});
