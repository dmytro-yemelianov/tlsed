use aws_lc_rs::{rand::SystemRandom, signature};
use tls_pki::{
    CertificateDer, ChainLimits, PkiError, RevocationPolicy, ServerName, ServerVerifier, UnixTime,
    WebPkiError,
};

const CA: &[u8] = include_bytes!("../../tls-bench/fixtures/ca.der");
const LEAF: &[u8] = include_bytes!("../../tls-bench/fixtures/server.der");
const EC_KEY: &[u8] = include_bytes!("../../tls-bench/fixtures/server-key.der");
fn cert(bytes: &[u8]) -> CertificateDer<'_> {
    CertificateDer::from(bytes)
}
fn now() -> UnixTime {
    UnixTime::since_unix_epoch(std::time::Duration::from_secs(1792022400))
}
fn verifier(roots: &[CertificateDer<'_>], limits: ChainLimits) -> ServerVerifier {
    ServerVerifier::new(roots, limits, RevocationPolicy::NoRevocationData).unwrap()
}
fn reference() -> ServerName<'static> {
    ServerName::try_from("localhost").unwrap()
}
fn signed_message(role: &[u8], hash: &[u8]) -> Vec<u8> {
    let mut message = vec![0x20; 64];
    message.extend_from_slice(role);
    message.push(0);
    message.extend_from_slice(hash);
    message
}

#[test]
fn baseline_chain_and_dns_identity_at_explicit_time() {
    let roots = [cert(CA)];
    let chain = [cert(LEAF)];
    verifier(&roots, ChainLimits::default())
        .verify_server_certificate(&chain, &reference(), now())
        .unwrap();
}

#[test]
fn wrong_dns_and_ip_preserve_native_name_errors() {
    let roots = [cert(CA)];
    let chain = [cert(LEAF)];
    let verifier = verifier(&roots, ChainLimits::default());
    for name in ["wrong.invalid", "127.0.0.1"] {
        assert!(matches!(
            verifier.verify_server_certificate(&chain, &ServerName::try_from(name).unwrap(), now()),
            Err(PkiError::WebPki(WebPkiError::CertNotValidForName(_)))
        ));
    }
}

#[test]
fn ip_san_success_and_common_name_never_substitutes_for_san() {
    let ip = include_bytes!("fixtures/ip.der");
    let roots = [cert(ip)];
    let chain = [cert(ip)];
    let verifier = verifier(&roots, ChainLimits::default());
    verifier
        .verify_server_certificate(&chain, &ServerName::try_from("127.0.0.1").unwrap(), now())
        .unwrap();
    assert!(matches!(
        verifier.verify_server_certificate(&chain, &reference(), now()),
        Err(PkiError::WebPki(WebPkiError::CertNotValidForName(_)))
    ));
    let cn = include_bytes!("fixtures/cn_only.der");
    let roots = [cert(cn)];
    let chain = [cert(cn)];
    assert!(matches!(
        default_verifier(&roots).verify_server_certificate(&chain, &reference(), now()),
        Err(PkiError::WebPki(WebPkiError::CertNotValidForName(_)))
    ));
}
fn default_verifier(roots: &[CertificateDer<'_>]) -> ServerVerifier {
    verifier(roots, ChainLimits::default())
}

#[test]
fn wrong_root_expiry_and_not_yet_valid_preserve_native_errors() {
    let wrong_roots = [cert(LEAF)];
    let chain = [cert(LEAF)];
    assert!(matches!(
        verifier(&wrong_roots, ChainLimits::default()).verify_server_certificate(
            &chain,
            &reference(),
            now()
        ),
        Err(PkiError::WebPki(WebPkiError::UnknownIssuer))
    ));
    let roots = [cert(CA)];
    let verifier = verifier(&roots, ChainLimits::default());
    assert!(matches!(
        verifier.verify_server_certificate(
            &chain,
            &reference(),
            UnixTime::since_unix_epoch(std::time::Duration::from_secs(1577836800))
        ),
        Err(PkiError::WebPki(WebPkiError::CertNotValidYet { .. }))
    ));
    assert!(matches!(
        verifier.verify_server_certificate(
            &chain,
            &reference(),
            UnixTime::since_unix_epoch(std::time::Duration::from_secs(2208988800))
        ),
        Err(PkiError::WebPki(WebPkiError::CertExpired { .. }))
    ));
}

#[test]
fn invalid_der_and_changed_chain_signature_preserve_native_errors() {
    let roots = [cert(CA)];
    let verifier = verifier(&roots, ChainLimits::default());
    let invalid = [cert(&[0])];
    assert_eq!(
        verifier
            .verify_server_certificate(&invalid, &reference(), now())
            .err(),
        Some(PkiError::WebPki(WebPkiError::TrailingData(
            webpki::DerTypeId::SignedData
        )))
    );
    let mut changed = LEAF.to_vec();
    *changed.last_mut().unwrap() ^= 1;
    let changed = [cert(&changed)];
    assert!(matches!(
        verifier.verify_server_certificate(&changed, &reference(), now()),
        Err(PkiError::WebPki(WebPkiError::InvalidSignatureForPublicKey))
    ));
    let ca_leaf = [cert(CA)];
    assert!(matches!(
        verifier.verify_server_certificate(&ca_leaf, &reference(), now()),
        Err(PkiError::WebPki(WebPkiError::CaUsedAsEndEntity))
    ));
}

#[test]
fn chain_limits_precede_external_der_and_signature_operations() {
    assert_eq!(ChainLimits::new(0, 1, 1), Err(PkiError::InvalidLimits));
    assert!(matches!(
        ServerVerifier::new(
            &[],
            ChainLimits::default(),
            RevocationPolicy::NoRevocationData
        ),
        Err(PkiError::NoTrustAnchors)
    ));
    let roots = [cert(CA)];
    let valid = [cert(LEAF)];
    let verifier = verifier(&roots, ChainLimits::new(1, 1024, 2048).unwrap());
    assert!(matches!(
        verifier.verify_server_certificate(&[], &reference(), now()),
        Err(PkiError::EmptyChain)
    ));
    let invalid = [cert(&[0]), cert(&[0])];
    assert!(matches!(
        verifier.verify_server_certificate(&invalid, &reference(), now()),
        Err(PkiError::TooManyCertificates {
            actual: 2,
            limit: 1
        })
    ));
    // Native parsing would reject this DER; our per-certificate cap wins first.
    let too_large = [0; 1025];
    let too_large = [cert(&too_large)];
    assert!(matches!(
        verifier.verify_server_certificate(&too_large, &reference(), now()),
        Err(PkiError::CertificateTooLarge {
            index: 0,
            actual: 1025,
            limit: 1024
        })
    ));
    let total_limit = ChainLimits::new(2, 1024, CA.len()).unwrap();
    let verifier = default_verifier(&roots);
    verifier
        .verify_server_certificate(&valid, &reference(), now())
        .unwrap();
    let bounded =
        ServerVerifier::new(&roots, total_limit, RevocationPolicy::NoRevocationData).unwrap();
    let combined = [cert(LEAF), cert(CA)];
    assert!(matches!(
        bounded.verify_server_certificate(&combined, &reference(), now()),
        Err(PkiError::ChainBytesExceeded { .. })
    ));
}

#[test]
fn ecdsa_certificate_verify_binds_server_context_hash_and_scheme() {
    let roots = [cert(CA)];
    let chain = [cert(LEAF)];
    let verifier = verifier(&roots, ChainLimits::default());
    let verified = verifier
        .verify_server_certificate(&chain, &reference(), now())
        .unwrap();
    let signer =
        signature::EcdsaKeyPair::from_pkcs8(&signature::ECDSA_P256_SHA256_ASN1_SIGNING, EC_KEY)
            .unwrap();
    for hash in [vec![1; 32], vec![1; 48]] {
        let message = signed_message(b"TLS 1.3, server CertificateVerify", &hash);
        let signature = signer.sign(&SystemRandom::new(), &message).unwrap();
        verified
            .verify_certificate_verify(0x0403, &hash, signature.as_ref())
            .unwrap();
        let mut wrong_hash = hash.clone();
        wrong_hash[0] ^= 1;
        assert!(matches!(
            verified.verify_certificate_verify(0x0403, &wrong_hash, signature.as_ref()),
            Err(PkiError::WebPki(WebPkiError::InvalidSignatureForPublicKey))
        ));
        let client_message = signed_message(b"TLS 1.3, client CertificateVerify", &hash);
        let client_signature = signer.sign(&SystemRandom::new(), &client_message).unwrap();
        assert!(matches!(
            verified.verify_certificate_verify(0x0403, &hash, client_signature.as_ref()),
            Err(PkiError::WebPki(WebPkiError::InvalidSignatureForPublicKey))
        ));
        let mut bad_signature = signature.as_ref().to_vec();
        *bad_signature.last_mut().unwrap() ^= 1;
        assert!(matches!(
            verified.verify_certificate_verify(0x0403, &hash, &bad_signature),
            Err(PkiError::WebPki(WebPkiError::InvalidSignatureForPublicKey))
        ));
    }
    assert!(matches!(
        verified.verify_certificate_verify(0x0804, &[1; 32], &[0; 256]),
        Err(PkiError::WebPki(
            WebPkiError::UnsupportedSignatureAlgorithmForPublicKeyContext(_)
        ))
    ));
    for scheme in [0x0401, 0x0809, 0x0503, 0xffff] {
        assert_eq!(
            verified.verify_certificate_verify(scheme, &[1; 32], &[]),
            Err(PkiError::UnsupportedSignatureScheme(scheme))
        );
    }
    assert_eq!(
        verified.verify_certificate_verify(0x0403, &[1; 31], &[]),
        Err(PkiError::InvalidTranscriptHashLength(31))
    );
    assert_eq!(
        verified.verify_certificate_verify(0x0403, &[1; 32], &[0; 1025]),
        Err(PkiError::SignatureTooLarge(1025))
    );
}

#[test]
fn ed25519_certificate_verify_and_rsa_pss_rsae_all_hashes() {
    let leaf = include_bytes!("fixtures/ed25519.der");
    let roots = [cert(leaf)];
    let chain = [cert(leaf)];
    let verifier = verifier(&roots, ChainLimits::default());
    let verified = verifier
        .verify_server_certificate(&chain, &reference(), now())
        .unwrap();
    let signer = signature::Ed25519KeyPair::from_pkcs8_maybe_unchecked(include_bytes!(
        "fixtures/ed25519-key.der"
    ))
    .unwrap();
    let hash = [0x41; 32];
    let message = signed_message(b"TLS 1.3, server CertificateVerify", &hash);
    let sig = signer.sign(&message);
    verified
        .verify_certificate_verify(0x0807, &hash, sig.as_ref())
        .unwrap();
    let leaf = include_bytes!("fixtures/rsa.der");
    let roots = [cert(leaf)];
    let chain = [cert(leaf)];
    let verifier = default_verifier(&roots);
    let verified = verifier
        .verify_server_certificate(&chain, &reference(), now())
        .unwrap();
    let signer = signature::RsaKeyPair::from_pkcs8(include_bytes!("fixtures/rsa-key.der")).unwrap();
    for (scheme, algorithm) in [
        (0x0804, &signature::RSA_PSS_SHA256),
        (0x0805, &signature::RSA_PSS_SHA384),
        (0x0806, &signature::RSA_PSS_SHA512),
    ] {
        let mut sig = vec![0; signer.public_modulus_len()];
        signer
            .sign(algorithm, &SystemRandom::new(), &message, &mut sig)
            .unwrap();
        verified
            .verify_certificate_verify(scheme, &hash, &sig)
            .unwrap();
        sig[0] ^= 1;
        assert!(matches!(
            verified.verify_certificate_verify(scheme, &hash, &sig),
            Err(PkiError::WebPki(WebPkiError::InvalidSignatureForPublicKey))
        ));
    }
}

#[test]
fn client_only_eku_is_rejected_for_server_authentication() {
    let leaf = include_bytes!("fixtures/client-only.der");
    let roots = [cert(leaf)];
    let chain = [cert(leaf)];
    assert!(matches!(
        default_verifier(&roots).verify_server_certificate(&chain, &reference(), now()),
        Err(PkiError::WebPki(WebPkiError::RequiredEkuNotFoundContext(_)))
    ));
}

const KU_ROOT: &[u8] = include_bytes!("fixtures/ku-root.der");
const KU_GOOD_ISSUER: &[u8] = include_bytes!("fixtures/ku-intermediate-good.der");
const KU_BAD_ISSUER: &[u8] = include_bytes!("fixtures/ku-intermediate-bad.der");
const KU_ABSENT_ISSUER: &[u8] = include_bytes!("fixtures/ku-intermediate-absent.der");
const KU_GOOD_LEAF: &[u8] = include_bytes!("fixtures/ku-leaf-good.der");

#[test]
fn strict_key_usage_rejects_leaf_without_digital_signature() {
    let roots = [cert(KU_ROOT)];
    let chain = [
        cert(include_bytes!("fixtures/ku-leaf-bad.der")),
        cert(KU_GOOD_ISSUER),
    ];
    assert_eq!(
        default_verifier(&roots)
            .verify_server_certificate(&chain, &reference(), now())
            .err(),
        Some(PkiError::MissingDigitalSignature)
    );
}

#[test]
fn strict_key_usage_rejects_issuing_intermediate_without_key_cert_sign() {
    let roots = [cert(KU_ROOT)];
    let chain = [cert(KU_GOOD_LEAF), cert(KU_BAD_ISSUER)];
    assert_eq!(
        default_verifier(&roots)
            .verify_server_certificate(&chain, &reference(), now())
            .err(),
        Some(PkiError::MissingKeyCertSign)
    );
}

#[test]
fn absent_key_usage_is_unrestricted_and_trust_anchor_is_separate() {
    // This root deliberately has digitalSignature and lacks keyCertSign. It is
    // the explicit trust anchor, not a certificate in the issuing path.
    let roots = [cert(KU_ROOT)];
    let verifier = default_verifier(&roots);
    let good = [cert(KU_GOOD_LEAF), cert(KU_GOOD_ISSUER)];
    verifier
        .verify_server_certificate(&good, &reference(), now())
        .unwrap();
    let missing = [
        cert(include_bytes!("fixtures/ku-leaf-absent.der")),
        cert(KU_ABSENT_ISSUER),
    ];
    verifier
        .verify_server_certificate(&missing, &reference(), now())
        .unwrap();
}

#[test]
fn strict_path_callback_ignores_unused_certificates_and_retries_alternatives() {
    let roots = [cert(KU_ROOT)];
    let verifier = default_verifier(&roots);
    // Same subject/key, different valid root-signed intermediates: reject the
    // first candidate's KU, then let native path building choose the good one.
    let alternatives = [
        cert(KU_GOOD_LEAF),
        cert(KU_BAD_ISSUER),
        cert(KU_GOOD_ISSUER),
    ];
    verifier
        .verify_server_certificate(&alternatives, &reference(), now())
        .unwrap();
    let unused = [
        cert(KU_GOOD_LEAF),
        cert(KU_GOOD_ISSUER),
        cert(KU_BAD_ISSUER),
    ];
    verifier
        .verify_server_certificate(&unused, &reference(), now())
        .unwrap();
}

#[test]
fn strict_key_usage_rejects_trailing_extension_der_bytes() {
    let roots = [cert(KU_ROOT)];
    let chain = [
        cert(include_bytes!("fixtures/ku-leaf-trailing.der")),
        cert(KU_GOOD_ISSUER),
    ];
    assert_eq!(
        default_verifier(&roots)
            .verify_server_certificate(&chain, &reference(), now())
            .err(),
        Some(PkiError::TrailingKeyUsageData(
            tls_pki::CertificateRole::Leaf
        ))
    );
}

#[test]
fn named_key_usage_rejects_noncanonical_and_unknown_or_truncated_bits() {
    for bytes in [
        include_bytes!("fixtures/ku-noncanonical.der").as_slice(),
        include_bytes!("fixtures/ku-unknown-bit.der").as_slice(),
        include_bytes!("fixtures/ku-truncated-high-bits.der").as_slice(),
    ] {
        let roots = [cert(bytes)];
        let chain = [cert(bytes)];
        assert_eq!(
            default_verifier(&roots)
                .verify_server_certificate(&chain, &reference(), now())
                .err(),
            Some(PkiError::InvalidKeyUsageEncoding(
                tls_pki::CertificateRole::Leaf
            ))
        );
    }
}

#[test]
fn owned_verified_leaf_survives_chain_storage_and_verifies_same_domain() {
    let owned = {
        let roots = [CertificateDer::from(CA.to_vec())];
        let chain = [CertificateDer::from(LEAF.to_vec())];
        let verifier = default_verifier(&roots);
        verifier
            .verify_server_certificate(&chain, &reference(), now())
            .unwrap()
            .to_owned()
    }; // Chain, anchors and verifier storage have all been dropped.
    let signer =
        signature::EcdsaKeyPair::from_pkcs8(&signature::ECDSA_P256_SHA256_ASN1_SIGNING, EC_KEY)
            .unwrap();
    let hash = [0x51; 32];
    let message = signed_message(b"TLS 1.3, server CertificateVerify", &hash);
    let sig = signer.sign(&SystemRandom::new(), &message).unwrap();
    owned
        .verify_certificate_verify(0x0403, &hash, sig.as_ref())
        .unwrap();
    let mut tampered = sig.as_ref().to_vec();
    *tampered.last_mut().unwrap() ^= 1;
    assert!(matches!(
        owned.verify_certificate_verify(0x0403, &hash, &tampered),
        Err(PkiError::WebPki(WebPkiError::InvalidSignatureForPublicKey))
    ));
    assert_eq!(
        owned.verify_certificate_verify(0x0401, &hash, sig.as_ref()),
        Err(PkiError::UnsupportedSignatureScheme(0x0401))
    );
}
