use tls_crypto::{CryptoError, EphemeralKeyExchange, KeyExchangeProvider, NamedGroup};
use tls_crypto_awslc::AwsLcProvider;

fn hex(text: &str) -> Vec<u8> {
    text.as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

#[test]
fn fresh_pairs_agree_for_both_groups_and_correct_share_formats() {
    assert_eq!(NamedGroup::X25519.wire_code(), 0x001d);
    assert_eq!(NamedGroup::Secp256r1.wire_code(), 0x0017);
    for group in [NamedGroup::X25519, NamedGroup::Secp256r1] {
        let a = AwsLcProvider.start_key_exchange(group).unwrap();
        let b = AwsLcProvider.start_key_exchange(group).unwrap();
        assert_eq!(a.group(), group);
        assert_eq!(b.group(), group);
        assert_eq!(a.public_key().len(), group.public_key_len());
        assert_eq!(b.public_key().len(), group.public_key_len());
        assert_eq!(group.shared_secret_len(), 32);
        if group == NamedGroup::Secp256r1 {
            assert_eq!(a.public_key()[0], 4);
            assert_eq!(b.public_key()[0], 4);
        }
        // Observed separate generated shares, not a proof of RNG/key freshness.
        assert_ne!(a.public_key(), b.public_key());
        let share_a = a.public_key().to_vec();
        let share_b = b.public_key().to_vec();
        let mut secret_a = [0xa5; 32];
        let mut secret_b = [0xa5; 32];
        a.complete(&share_b, &mut secret_a).unwrap();
        b.complete(&share_a, &mut secret_b).unwrap();
        assert!(
            secret_a == secret_b,
            "both owners must derive the same secret"
        );
        // Never Debug-print fresh secret values, even on an assertion failure.
        secret_a.fill(0);
        secret_b.fill(0);
    }
}

#[test]
fn wrong_peer_lengths_and_exact_output_lengths_wipe_all_supplied_bytes() {
    for group in [NamedGroup::X25519, NamedGroup::Secp256r1] {
        for size in [
            0,
            group.public_key_len() - 1,
            group.public_key_len() + 1,
            4096,
        ] {
            let key = AwsLcProvider.start_key_exchange(group).unwrap();
            let mut output = [0xa5; 32];
            assert_eq!(
                key.complete(&vec![0; size], &mut output),
                Err(CryptoError::InvalidKey)
            );
            assert_eq!(output, [0; 32]);
        }
        let peer = AwsLcProvider.start_key_exchange(group).unwrap();
        for size in [0, 1, 31, 33, 128] {
            let key = AwsLcProvider.start_key_exchange(group).unwrap();
            let mut output = vec![0xa5; size];
            assert_eq!(
                key.complete(peer.public_key(), &mut output),
                Err(CryptoError::InvalidLength)
            );
            assert!(output.iter().all(|byte| *byte == 0));
        }
    }
}

#[test]
fn x25519_rejects_low_order_zero_result_shares_and_wipes() {
    let mut one = [0; 32];
    one[0] = 1;
    let mut p_minus_one = [0xff; 32];
    p_minus_one[0] = 0xec;
    p_minus_one[31] = 0x7f;
    for share in [[0; 32], one, p_minus_one] {
        let key = AwsLcProvider
            .start_key_exchange(NamedGroup::X25519)
            .unwrap();
        let mut output = [0xa5; 32];
        assert_eq!(
            key.complete(&share, &mut output),
            Err(CryptoError::InvalidKey)
        );
        assert_eq!(output, [0; 32]);
    }
}

#[test]
fn p256_rejects_compressed_hybrid_infinity_and_invalid_points() {
    let peer = AwsLcProvider
        .start_key_exchange(NamedGroup::Secp256r1)
        .unwrap();
    for prefix in [0, 2, 3, 6, 7] {
        let mut share = peer.public_key().to_vec();
        share[0] = prefix;
        let key = AwsLcProvider
            .start_key_exchange(NamedGroup::Secp256r1)
            .unwrap();
        let mut output = [0xa5; 32];
        assert_eq!(
            key.complete(&share, &mut output),
            Err(CryptoError::InvalidKey)
        );
        assert_eq!(output, [0; 32]);
    }
    let mut invalid = [0; 65];
    invalid[0] = 4;
    let key = AwsLcProvider
        .start_key_exchange(NamedGroup::Secp256r1)
        .unwrap();
    let mut output = [0xa5; 32];
    assert_eq!(
        key.complete(&invalid, &mut output),
        Err(CryptoError::InvalidKey)
    );
    assert_eq!(output, [0; 32]);
    let mut compressed = vec![2];
    compressed.extend_from_slice(&peer.public_key()[1..33]);
    let key = AwsLcProvider
        .start_key_exchange(NamedGroup::Secp256r1)
        .unwrap();
    output.fill(0xa5);
    assert_eq!(
        key.complete(&compressed, &mut output),
        Err(CryptoError::InvalidKey)
    );
    assert_eq!(output, [0; 32]);
}

#[test]
fn rfc7748_section_6_1_native_known_answer() {
    // Deterministic import exists on maintained PrivateKey, not public
    // EphemeralPrivateKey. Test native primitive vectors independently; the
    // production wrapper exposes only fresh generation and consuming agreement.
    use aws_lc_rs::agreement;
    let alice = agreement::PrivateKey::from_private_key(
        &agreement::X25519,
        &hex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"),
    )
    .unwrap();
    let bob = agreement::PrivateKey::from_private_key(
        &agreement::X25519,
        &hex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"),
    )
    .unwrap();
    let alice_public = hex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
    let bob_public = hex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
    let expected = hex("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");
    assert_eq!(alice.compute_public_key().unwrap().as_ref(), alice_public);
    assert_eq!(bob.compute_public_key().unwrap().as_ref(), bob_public);
    for (private, peer) in [(&alice, &bob_public), (&bob, &alice_public)] {
        agreement::agree(
            private,
            agreement::UnparsedPublicKey::new(&agreement::X25519, peer),
            CryptoError::InvalidKey,
            |secret| {
                assert_eq!(secret, expected);
                Ok(())
            },
        )
        .unwrap();
    }
}
