//! Bounded maintained Web PKI server verification, outside formal TLS proofs.
//! Explicit DNS/IP reference identity, trust roots and supplied validation time.
use rustls_pki_types::SignatureVerificationAlgorithm;
pub use rustls_pki_types::{CertificateDer, ServerName, UnixTime};
pub use webpki::Error as WebPkiError;
pub use x509_parser::error::X509Error;
use x509_parser::nom::Parser;
use x509_parser::prelude::FromDer;

/// Explicit current policy. No CRL/OCSP processing or revocation assertion.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RevocationPolicy {
    NoRevocationData,
}

/// Caps are checked before any external parse/path/signature verification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ChainLimits {
    max_certificates: usize,
    max_certificate_bytes: usize,
    max_total_bytes: usize,
}
impl ChainLimits {
    pub fn new(
        max_certificates: usize,
        max_certificate_bytes: usize,
        max_total_bytes: usize,
    ) -> Result<Self, PkiError> {
        if max_certificates == 0 || max_certificate_bytes == 0 || max_total_bytes == 0 {
            return Err(PkiError::InvalidLimits);
        }
        Ok(Self {
            max_certificates,
            max_certificate_bytes,
            max_total_bytes,
        })
    }
    fn check(self, chain: &[CertificateDer<'_>]) -> Result<(), PkiError> {
        if chain.len() > self.max_certificates {
            return Err(PkiError::TooManyCertificates {
                actual: chain.len(),
                limit: self.max_certificates,
            });
        }
        let mut total = 0usize;
        for (index, cert) in chain.iter().enumerate() {
            if cert.as_ref().len() > self.max_certificate_bytes {
                return Err(PkiError::CertificateTooLarge {
                    index,
                    actual: cert.as_ref().len(),
                    limit: self.max_certificate_bytes,
                });
            }
            total = total
                .checked_add(cert.as_ref().len())
                .ok_or(PkiError::ChainBytesExceeded {
                    limit: self.max_total_bytes,
                })?;
            if total > self.max_total_bytes {
                return Err(PkiError::ChainBytesExceeded {
                    limit: self.max_total_bytes,
                });
            }
        }
        Ok(())
    }
}
impl Default for ChainLimits {
    fn default() -> Self {
        Self {
            max_certificates: 8,
            max_certificate_bytes: 65536,
            max_total_bytes: 262144,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CertificateRole {
    Leaf,
    IssuingIntermediate,
}

/// Native typed errors are preserved; no generic "invalid certificate" masking.
#[derive(Clone, Debug, PartialEq)]
pub enum PkiError {
    InvalidLimits,
    NoTrustAnchors,
    EmptyChain,
    TooManyCertificates {
        actual: usize,
        limit: usize,
    },
    CertificateTooLarge {
        index: usize,
        actual: usize,
        limit: usize,
    },
    ChainBytesExceeded {
        limit: usize,
    },
    UnsupportedSignatureScheme(u16),
    InvalidTranscriptHashLength(usize),
    SignatureTooLarge(usize),
    WebPki(WebPkiError),
    X509Parser {
        role: CertificateRole,
        source: X509Error,
    },
    TrailingCertificateData(CertificateRole),
    TrailingKeyUsageData(CertificateRole),
    InvalidKeyUsageEncoding(CertificateRole),
    MissingDigitalSignature,
    MissingKeyCertSign,
}
impl std::fmt::Display for PkiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for PkiError {}
impl From<WebPkiError> for PkiError {
    fn from(error: WebPkiError) -> Self {
        Self::WebPki(error)
    }
}

// Certificate issuer signatures are distinct from TLS handshake schemes. Modern
// RSA PKCS#1 certificate signatures are allowed here, never CertificateVerify.
static CERTIFICATE_SIGNATURE_ALGORITHMS: &[&dyn SignatureVerificationAlgorithm] = &[
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

/// Immutable verifier owning explicitly supplied anchors. No system root loading,
/// name inference, clock access, insecure compatibility flag or network access.
pub struct ServerVerifier {
    anchors: Vec<rustls_pki_types::TrustAnchor<'static>>,
    limits: ChainLimits,
    revocation: RevocationPolicy,
}
impl ServerVerifier {
    pub fn new(
        roots: &[CertificateDer<'_>],
        limits: ChainLimits,
        revocation: RevocationPolicy,
    ) -> Result<Self, PkiError> {
        if roots.is_empty() {
            return Err(PkiError::NoTrustAnchors);
        }
        limits.check(roots)?;
        let anchors = roots
            .iter()
            .map(|root| webpki::anchor_from_trusted_cert(root).map(|anchor| anchor.to_owned()))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            anchors,
            limits,
            revocation,
        })
    }
    /// `chain` is leaf first, then candidate intermediates. The caller supplies
    /// trusted reference identity and time; no clock-availability claim is made.
    pub fn verify_server_certificate<'a>(
        &self,
        chain: &'a [CertificateDer<'a>],
        reference: &ServerName<'_>,
        now: UnixTime,
    ) -> Result<VerifiedServerCert<'a>, PkiError> {
        if chain.is_empty() {
            return Err(PkiError::EmptyChain);
        }
        self.limits.check(chain)?;
        let leaf = webpki::EndEntityCert::try_from(&chain[0])?;
        let revocation = match self.revocation {
            RevocationPolicy::NoRevocationData => None,
        };
        let rejected_path = std::cell::RefCell::new(None);
        let verify_path = |path: &webpki::VerifiedPath<'_>| {
            // Check only actually selected issuing intermediates, never extra
            // peer-supplied certificates or the separate trust anchor. The native
            // callback rejects this candidate and lets webpki try other paths.
            for intermediate in path.intermediate_certificates() {
                if let Err(error) = check_key_usage(
                    intermediate.der().as_ref(),
                    CertificateRole::IssuingIntermediate,
                ) {
                    rejected_path.replace(Some(error));
                    // This internal rejection marker is replaced by the typed
                    // strict-policy cause if no acceptable path succeeds.
                    return Err(WebPkiError::UnknownIssuer);
                }
            }
            Ok(())
        };
        if let Err(error) = leaf.verify_for_usage(
            CERTIFICATE_SIGNATURE_ALGORITHMS,
            &self.anchors,
            &chain[1..],
            now,
            webpki::KeyUsage::server_auth(),
            revocation,
            Some(&verify_path),
        ) {
            // Preserve native fatal resource-budget errors even if an earlier
            // cryptographically valid candidate failed the strict KU policy.
            if matches!(
                error,
                WebPkiError::MaximumSignatureChecksExceeded
                    | WebPkiError::MaximumPathBuildCallsExceeded
                    | WebPkiError::MaximumNameConstraintComparisonsExceeded
            ) {
                return Err(error.into());
            }
            return Err(rejected_path.into_inner().unwrap_or_else(|| error.into()));
        }
        check_key_usage(chain[0].as_ref(), CertificateRole::Leaf)?;
        leaf.verify_is_valid_for_subject_name(reference)?;
        Ok(VerifiedServerCert {
            leaf,
            der: chain[0].as_ref(),
        })
    }
}

/// A chain+DNS/IP verified leaf at the caller's supplied time. Construction is
/// private; this is not a complete handshake/Finished authentication token.
pub struct VerifiedServerCert<'a> {
    leaf: webpki::EndEntityCert<'a>,
    der: &'a [u8],
}
impl VerifiedServerCert<'_> {
    /// Copy only this already verified leaf into an owned token. Path, identity,
    /// time and strict KeyUsage were checked before this token could be created.
    /// Allocation is bounded by the original configured certificate limit.
    pub fn to_owned(&self) -> OwnedVerifiedServerCert {
        OwnedVerifiedServerCert {
            der: CertificateDer::from(self.der.to_vec()),
        }
    }

    /// Verify the server CertificateVerify domain with a maintained algorithm.
    /// The caller must also enforce that the scheme was offered and the hash is
    /// the authentic negotiated transcript through Certificate (including HRR).
    pub fn verify_certificate_verify(
        &self,
        scheme: u16,
        transcript_hash: &[u8],
        signature: &[u8],
    ) -> Result<(), PkiError> {
        verify_certificate_verify(&self.leaf, scheme, transcript_hash, signature)
    }
}

/// An owned leaf whose chain, identity and supplied time were already verified.
/// Only VerifiedServerCert::to_owned can construct it; no untrusted DER entry
/// point exists. This does not authenticate Finished or a complete handshake.
/// No Clone/Debug implementation is supplied.
///
/// ```compile_fail
/// use tls_pki::{CertificateDer, OwnedVerifiedServerCert};
/// let token = OwnedVerifiedServerCert { der: CertificateDer::from(vec![0]) };
/// ```
pub struct OwnedVerifiedServerCert {
    der: CertificateDer<'static>,
}
impl OwnedVerifiedServerCert {
    /// Parse the privately owned, previously verified leaf and verify the same
    /// CertificateVerify domain. No chain/name/time check is repeated here.
    /// The original validation context must still belong to this handshake.
    pub fn verify_certificate_verify(
        &self,
        scheme: u16,
        transcript_hash: &[u8],
        signature: &[u8],
    ) -> Result<(), PkiError> {
        let leaf = webpki::EndEntityCert::try_from(&self.der)?;
        verify_certificate_verify(&leaf, scheme, transcript_hash, signature)
    }
}

fn verify_certificate_verify(
    leaf: &webpki::EndEntityCert<'_>,
    scheme: u16,
    transcript_hash: &[u8],
    signature: &[u8],
) -> Result<(), PkiError> {
    let algorithm = match scheme {
        0x0403 => webpki::aws_lc_rs::ECDSA_P256_SHA256,
        0x0804 => webpki::aws_lc_rs::RSA_PSS_2048_8192_SHA256_LEGACY_KEY,
        0x0805 => webpki::aws_lc_rs::RSA_PSS_2048_8192_SHA384_LEGACY_KEY,
        0x0806 => webpki::aws_lc_rs::RSA_PSS_2048_8192_SHA512_LEGACY_KEY,
        0x0807 => webpki::aws_lc_rs::ED25519,
        _ => return Err(PkiError::UnsupportedSignatureScheme(scheme)),
    };
    if !matches!(transcript_hash.len(), 32 | 48) {
        return Err(PkiError::InvalidTranscriptHashLength(transcript_hash.len()));
    }
    if signature.len() > 1024 {
        return Err(PkiError::SignatureTooLarge(signature.len()));
    }
    const CONTEXT: &[u8] = b"TLS 1.3, server CertificateVerify";
    let mut message = [0; 64 + 33 + 1 + 48];
    message[..64].fill(0x20);
    message[64..64 + CONTEXT.len()].copy_from_slice(CONTEXT);
    let start = 64 + CONTEXT.len() + 1; // already-zero separator
    message[start..start + transcript_hash.len()].copy_from_slice(transcript_hash);
    leaf.verify_signature(
        algorithm,
        &message[..start + transcript_hash.len()],
        signature,
    )?;
    Ok(())
}

fn check_key_usage(der: &[u8], role: CertificateRole) -> Result<(), PkiError> {
    let parser_error = |source| PkiError::X509Parser { role, source };
    let (remainder, certificate) = x509_parser::certificate::X509CertificateParser::new()
        .with_deep_parse_extensions(false)
        .parse(der)
        .map_err(|error| parser_error(X509Error::from(error)))?;
    if !remainder.is_empty() {
        return Err(PkiError::TrailingCertificateData(role));
    }
    let extension = certificate
        .get_extension_unique(&x509_parser::oid_registry::OID_X509_EXT_KEY_USAGE)
        .map_err(parser_error)?;
    let Some(extension) = extension else {
        return Ok(());
    };
    // Explicit FromDer is needed: generic deep extension parsing can discard
    // the extension parser's remainder. Reject trailing extension bytes here.
    let (remainder, usage) = x509_parser::asn1_rs::BitString::from_der(extension.value)
        .map_err(|error| parser_error(X509Error::from(error)))?;
    if !remainder.is_empty() {
        return Err(PkiError::TrailingKeyUsageData(role));
    }
    // RFC5280 named KeyUsage bits are 0..=8. Use maintained ASN.1 fields,
    // not the KeyUsage helper's arbitrary-length-to-u16 folding. X.690 DER
    // named-bit encoding removes trailing zeros and unused counts are 0..=7.
    let bytes = usage.data.as_ref();
    let Some(&last) = bytes.last() else {
        return Err(PkiError::InvalidKeyUsageEncoding(role));
    };
    if usage.unused_bits > 7
        || bytes.len() > 2
        || last == 0
        || bytes.len() * 8 - usize::from(usage.unused_bits) > 9
        || last.trailing_zeros() != u32::from(usage.unused_bits)
    {
        return Err(PkiError::InvalidKeyUsageEncoding(role));
    }
    match role {
        CertificateRole::Leaf if !usage.is_set(0) => Err(PkiError::MissingDigitalSignature),
        CertificateRole::IssuingIntermediate if !usage.is_set(5) => {
            Err(PkiError::MissingKeyCertSign)
        }
        _ => Ok(()),
    }
}
