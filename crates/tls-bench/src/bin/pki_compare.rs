//! Fixed-input PKI comparison. Policies differ: tls-pki adds strict KeyUsage.
use rustls::pki_types::{
    CertificateDer, ServerName, SignatureVerificationAlgorithm, TrustAnchor, UnixTime,
};
use std::hint::black_box;
use std::time::{Duration, Instant};
use tls_pki::{ChainLimits, PkiError, RevocationPolicy, ServerVerifier};

const CA: &[u8] = include_bytes!("../../fixtures/ca.der");
const LEAF: &[u8] = include_bytes!("../../fixtures/server.der");
// Keep certificate issuer algorithms identical to the strict adapter. TLS
// CertificateVerify's smaller scheme whitelist is not this path's workload.
static ALGORITHMS: &[&dyn SignatureVerificationAlgorithm] = &[
    webpki::aws_lc_rs::ECDSA_P256_SHA256,
    webpki::aws_lc_rs::ECDSA_P384_SHA384,
    webpki::aws_lc_rs::ECDSA_P521_SHA512,
    webpki::aws_lc_rs::ED25519,
    webpki::aws_lc_rs::RSA_PKCS1_2048_8192_SHA256,
    webpki::aws_lc_rs::RSA_PKCS1_2048_8192_SHA384,
    webpki::aws_lc_rs::RSA_PKCS1_2048_8192_SHA512,
    webpki::aws_lc_rs::RSA_PKCS1_2048_8192_SHA256_ABSENT_PARAMS,
    webpki::aws_lc_rs::RSA_PKCS1_2048_8192_SHA384_ABSENT_PARAMS,
    webpki::aws_lc_rs::RSA_PKCS1_2048_8192_SHA512_ABSENT_PARAMS,
    webpki::aws_lc_rs::RSA_PSS_2048_8192_SHA256_LEGACY_KEY,
    webpki::aws_lc_rs::RSA_PSS_2048_8192_SHA384_LEGACY_KEY,
    webpki::aws_lc_rs::RSA_PSS_2048_8192_SHA512_LEGACY_KEY,
];
#[derive(Clone, Copy)]
enum Expected {
    Valid,
    WrongName,
    InvalidSignature,
}
struct Case {
    workload: &'static str,
    leaf: CertificateDer<'static>,
    name: ServerName<'static>,
    expected: Expected,
}
struct Context {
    anchors: Vec<TrustAnchor<'static>>,
    strict: ServerVerifier,
    now: UnixTime,
}
impl Context {
    fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let roots = [CertificateDer::from(CA)];
        Ok(Self {
            anchors: vec![webpki::anchor_from_trusted_cert(&roots[0])?.to_owned()],
            strict: ServerVerifier::new(
                &roots,
                ChainLimits::default(),
                RevocationPolicy::NoRevocationData,
            )?,
            now: UnixTime::since_unix_epoch(Duration::from_secs(1792022400)),
        })
    }
    fn native(&self, case: &Case) -> Result<(), webpki::Error> {
        let leaf = webpki::EndEntityCert::try_from(black_box(&case.leaf))?;
        leaf.verify_for_usage(
            ALGORITHMS,
            &self.anchors,
            &[],
            self.now,
            webpki::KeyUsage::server_auth(),
            None,
            None,
        )?;
        leaf.verify_is_valid_for_subject_name(black_box(&case.name))
    }
    fn strict(&self, case: &Case) -> Result<(), PkiError> {
        self.strict
            .verify_server_certificate(
                black_box(std::slice::from_ref(&case.leaf)),
                black_box(&case.name),
                self.now,
            )
            .map(|verified| {
                black_box(verified);
            })
    }
}
fn cases() -> Vec<Case> {
    let mut invalid_signature = LEAF.to_vec();
    *invalid_signature.last_mut().unwrap() ^= 1;
    vec![
        Case {
            workload: "pki_valid",
            leaf: CertificateDer::from(LEAF),
            name: ServerName::try_from("localhost").unwrap(),
            expected: Expected::Valid,
        },
        Case {
            workload: "pki_wrong_name",
            leaf: CertificateDer::from(LEAF),
            name: ServerName::try_from("wrong.invalid").unwrap(),
            expected: Expected::WrongName,
        },
        Case {
            workload: "pki_invalid_signature",
            leaf: CertificateDer::from(invalid_signature),
            name: ServerName::try_from("localhost").unwrap(),
            expected: Expected::InvalidSignature,
        },
    ]
}
fn expected(result: Result<(), webpki::Error>, outcome: Expected) -> bool {
    matches!(
        (result, outcome),
        (Ok(()), Expected::Valid)
            | (
                Err(webpki::Error::CertNotValidForName(_)),
                Expected::WrongName
            )
            | (
                Err(webpki::Error::InvalidSignatureForPublicKey),
                Expected::InvalidSignature
            )
    )
}
fn run(context: &Context, case: &Case, strict: bool) {
    let result = if strict {
        match context.strict(case) {
            Ok(()) => Ok(()),
            Err(PkiError::WebPki(error)) => Err(error),
            Err(error) => panic!("unexpected strict policy failure: {error}"),
        }
    } else {
        context.native(case)
    };
    assert!(
        expected(black_box(result), case.expected),
        "unexpected validation result in {}",
        case.workload
    );
}
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    let mut samples = 30;
    let mut iterations = 100;
    let mut warmup = 10;
    let mut args = args.iter();
    while let Some(flag) = args.next() {
        let value: usize = args.next().ok_or("missing numeric option value")?.parse()?;
        match flag.as_str() {
            "--samples" => samples = value,
            "--iterations" => iterations = value,
            "--warmup" => warmup = value,
            _ => return Err(format!("unknown option: {flag}").into()),
        }
    }
    if samples == 0 || iterations == 0 {
        return Err("samples and iterations must be positive".into());
    }
    let context = Context::new()?;
    let cases = cases();
    eprintln!(
        "PKI policy difference: tls_pki_strict_key_usage adds bounded preflight and strict maintained-parser leaf/issuer KeyUsage checks; webpki_native_policy omits this supplement. Fixed P256 leaf/CA, DNS/time/serverAuth/certificate algorithms/no-revocation are shared. Root parsing and configuration are outside timing; each operation includes leaf parse, path and identity verification, not CertificateVerify or handshake."
    );
    for case in &cases {
        for strict in [false, true] {
            for _ in 0..warmup {
                run(&context, case, strict);
            }
        }
    }
    println!("implementation,workload,direction,payload_bytes,iterations,sample,elapsed_ns");
    for case in &cases {
        for sample in 0..samples {
            // Alternate implementation order across samples to reduce order bias.
            for strict in if sample % 2 == 0 {
                [false, true]
            } else {
                [true, false]
            } {
                let start = Instant::now();
                for _ in 0..iterations {
                    run(&context, case, strict);
                }
                let elapsed = start.elapsed().as_nanos();
                let implementation = if strict {
                    "tls_pki_strict_key_usage"
                } else {
                    "webpki_native_policy"
                };
                println!(
                    "{implementation},{},server_identity,{},{iterations},{sample},{elapsed}",
                    case.workload,
                    case.leaf.as_ref().len()
                );
            }
        }
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn both_policies_accept_valid_and_reject_exact_negative_causes() {
        let context = Context::new().unwrap();
        for case in cases() {
            run(&context, &case, false);
            run(&context, &case, true);
        }
    }
}
