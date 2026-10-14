use tls_crypto::{AeadKey, CipherSuite, CryptoError, CryptoProvider, HashAlgorithm, TAG_LEN};
use tls_crypto_awslc::AwsLcProvider;

fn hex(text: &str) -> Vec<u8> {
    let bytes: Vec<_> = text.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    assert_eq!(bytes.len() % 2, 0);
    bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            let digit = |b: u8| (b as char).to_digit(16).unwrap() as u8;
            digit(pair[0]) * 16 + digit(pair[1])
        })
        .collect()
}
const SUITES: [CipherSuite; 3] = [
    CipherSuite::Aes128GcmSha256,
    CipherSuite::Aes256GcmSha384,
    CipherSuite::Chacha20Poly1305Sha256,
];

fn aead_vector(
    suite: CipherSuite,
    key_bytes: &[u8],
    nonce: &[u8; 12],
    aad: &[u8],
    plaintext: &[u8],
    expected: &[u8],
) {
    let key = AwsLcProvider.aead_key(suite, key_bytes).unwrap();
    // Suffix proves encryption uses only the selected plaintext+tag range.
    let mut buffer = vec![0xa5; plaintext.len() + TAG_LEN + 7];
    buffer[..plaintext.len()].copy_from_slice(plaintext);
    let size = key
        .seal_in_place(nonce, aad, &mut buffer, plaintext.len())
        .unwrap();
    assert_eq!(size, expected.len());
    assert_eq!(&buffer[..size], expected);
    assert_eq!(&buffer[size..], &[0xa5; 7]);
    let recovered = key.open_in_place(nonce, aad, &mut buffer[..size]).unwrap();
    assert_eq!(recovered, plaintext.len());
    assert_eq!(&buffer[..recovered], plaintext);
}

#[test]
fn aes_gcm_zero_key_known_answers() {
    // GCM specification submission test cases 1/2; mirrored in upstream
    // BoringSSL cipher_test.txt with its original NIST source URL.
    aead_vector(
        CipherSuite::Aes128GcmSha256,
        &[0; 16],
        &[0; 12],
        &[],
        &[],
        &hex("58e2fccefa7e3061367f1d57a4e7455a"),
    );
    aead_vector(
        CipherSuite::Aes128GcmSha256,
        &[0; 16],
        &[0; 12],
        &[],
        &[0; 16],
        &hex("0388dace60b6a392f328c2b971b2fe78 ab6e47d42cec13bdf53a67b21257bddf"),
    );
    aead_vector(
        CipherSuite::Aes256GcmSha384,
        &[0; 32],
        &[0; 12],
        &[],
        &[],
        &hex("530f8afbc74536b9a963b4f1c4cb738b"),
    );
    aead_vector(
        CipherSuite::Aes256GcmSha384,
        &[0; 32],
        &[0; 12],
        &[],
        &[0; 16],
        &hex("cea7403d4d606b6e074ec5d3baf39d18 d0d1c8a799996bf0265b98b5d48ab919"),
    );
}

#[test]
fn nist_published_gcm_examples_1_and_2() {
    // NIST AES_GCM.pdf GCM-AES128 examples 1/2 (128-bit tags).
    let key = hex("FEFFE9928665731C6D6A8F9467308308");
    let nonce = hex("CAFEBABEFACEDBADDECAF888").try_into().unwrap();
    aead_vector(
        CipherSuite::Aes128GcmSha256,
        &key,
        &nonce,
        &[],
        &[],
        &hex("3247184B3C4F69A44DBCD22887BBB418"),
    );
    let plaintext = hex(
        "D9313225F88406E5A55909C5AFF5269A86A7A9531534F7DA2E4C303D8A318A721C3C0C95956809532FCF0E2449A6B525B16AEDF5AA0DE657BA637B391AAFD255",
    );
    let expected = hex(
        "42831EC2217774244B7221B784D0D49CE3AA212F2C02A4E035C17E2329ACA12E21D514B25466931C7D8F6A5AAC84AA051BA30B396A0AAC973D58E091473F59854D5C2AF327CD64A62CF35ABD2BA6FAB4",
    );
    aead_vector(
        CipherSuite::Aes128GcmSha256,
        &key,
        &nonce,
        &[],
        &plaintext,
        &expected,
    );
}

#[test]
fn rfc8439_section_2_8_2_aead() {
    let key: Vec<_> = (0x80..=0x9f).collect();
    let nonce: [u8; 12] = hex("070000004041424344454647").try_into().unwrap();
    let aad = hex("50515253c0c1c2c3c4c5c6c7");
    let plaintext = hex(
        "4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e",
    );
    let expected = hex(
        "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b6116 1ae10b594f09e26a7e902ecbd0600691",
    );
    aead_vector(
        CipherSuite::Chacha20Poly1305Sha256,
        &key,
        &nonce,
        &aad,
        &plaintext,
        &expected,
    );
}

fn hkdf_vector(ikm: &[u8], salt: &[u8], info: &[u8], prk: &str, okm: &str) {
    let mut extracted = [0; 32];
    AwsLcProvider
        .hkdf_extract(HashAlgorithm::Sha256, salt, ikm, &mut extracted)
        .unwrap();
    assert_eq!(extracted.as_slice(), hex(prk));
    let expected = hex(okm);
    let mut output = vec![0; expected.len()];
    AwsLcProvider
        .hkdf_expand(HashAlgorithm::Sha256, &extracted, info, &mut output)
        .unwrap();
    assert_eq!(output, expected);
}

#[test]
fn rfc5869_appendix_a_sha256_vectors() {
    hkdf_vector(
        &[0x0b; 22],
        &hex("000102030405060708090a0b0c"),
        &hex("f0f1f2f3f4f5f6f7f8f9"),
        "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5",
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
    );
    hkdf_vector(
        &(0x00..=0x4f).collect::<Vec<_>>(),
        &(0x60..=0xaf).collect::<Vec<_>>(),
        &(0xb0..=0xff).collect::<Vec<_>>(),
        "06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244",
        "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87",
    );
    hkdf_vector(
        &[0x0b; 22],
        &[],
        &[],
        "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04",
        "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8",
    );
}

#[test]
fn sha256_sha384_abc_known_answers() {
    for (algorithm, expected) in [
        (
            HashAlgorithm::Sha256,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        ),
        (
            HashAlgorithm::Sha384,
            "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7",
        ),
    ] {
        let mut output = vec![0; algorithm.output_len()];
        AwsLcProvider.hash(algorithm, b"abc", &mut output).unwrap();
        assert_eq!(output, hex(expected));
    }
}

#[test]
fn every_suite_authenticates_ciphertext_aad_nonce_and_wipes_errors() {
    for suite in SUITES {
        let key = AwsLcProvider
            .aead_key(suite, &vec![0x41; suite.key_len()])
            .unwrap();
        let nonce = [0x24; 12];
        let aad = b"authenticated header";
        let mut sealed = vec![0x7f; 64 + TAG_LEN];
        key.seal_in_place(&nonce, aad, &mut sealed, 64).unwrap();
        for mode in 0..4 {
            let mut damaged = sealed.clone();
            let mut wrong_nonce = nonce;
            let associated: &[u8] = if mode == 2 { b"wrong header" } else { aad };
            if mode == 0 {
                damaged[0] ^= 1;
            }
            if mode == 1 {
                damaged[64] ^= 1;
            }
            if mode == 3 {
                wrong_nonce[0] ^= 1;
            }
            assert_eq!(
                key.open_in_place(&wrong_nonce, associated, &mut damaged),
                Err(CryptoError::AuthenticationFailed)
            );
            assert!(damaged.iter().all(|b| *b == 0));
        }
        for n in 0..TAG_LEN {
            let mut short = vec![0xa5; n];
            assert_eq!(
                key.open_in_place(&nonce, aad, &mut short),
                Err(CryptoError::InvalidLength)
            );
            assert!(short.iter().all(|b| *b == 0));
        }
        let mut tag_only = [0xa5; TAG_LEN];
        assert_eq!(
            key.open_in_place(&nonce, aad, &mut tag_only),
            Err(CryptoError::AuthenticationFailed)
        );
        assert_eq!(tag_only, [0; TAG_LEN]);
    }
}

#[test]
fn capabilities_and_seal_key_length_guards() {
    for suite in SUITES {
        assert!(AwsLcProvider.supports(suite));
        assert!(matches!(
            AwsLcProvider.aead_key(suite, &[]),
            Err(CryptoError::InvalidKey)
        ));
        assert!(matches!(
            AwsLcProvider.aead_key(suite, &vec![0; suite.key_len() + 1]),
            Err(CryptoError::InvalidKey)
        ));
        let key = AwsLcProvider
            .aead_key(suite, &vec![0; suite.key_len()])
            .unwrap();
        assert_eq!(key.suite(), suite);
        for size in [usize::MAX, 17, 1] {
            let mut buffer = [0xa5; TAG_LEN];
            assert_eq!(
                key.seal_in_place(&[0; 12], &[], &mut buffer, size),
                Err(CryptoError::InvalidLength)
            );
            assert_eq!(buffer, [0; TAG_LEN]);
        }
    }
}

#[test]
fn secret_output_length_guards_and_expand_limits() {
    for algorithm in [HashAlgorithm::Sha256, HashAlgorithm::Sha384] {
        let len = algorithm.output_len();
        for size in [0, len - 1, len + 1] {
            let mut output = vec![0xa5; size];
            assert_eq!(
                AwsLcProvider.hash(algorithm, b"abc", &mut output),
                Err(CryptoError::InvalidLength)
            );
            assert!(output.iter().all(|b| *b == 0));
            output.fill(0xa5);
            assert_eq!(
                AwsLcProvider.hkdf_extract(algorithm, b"salt", b"ikm", &mut output),
                Err(CryptoError::InvalidLength)
            );
            assert!(output.iter().all(|b| *b == 0));
        }
        for prk_len in [0, len - 1, len + 1] {
            let mut output = [0xa5; 64];
            assert_eq!(
                AwsLcProvider.hkdf_expand(algorithm, &vec![0; prk_len], &[], &mut output),
                Err(CryptoError::InvalidKey)
            );
            assert_eq!(output, [0; 64]);
        }
        let mut maximum = vec![0; 255 * len];
        AwsLcProvider
            .hkdf_expand(algorithm, &vec![0; len], b"info", &mut maximum)
            .unwrap();
        let mut excessive = vec![0xa5; 255 * len + 1];
        assert_eq!(
            AwsLcProvider.hkdf_expand(algorithm, &vec![0; len], b"info", &mut excessive),
            Err(CryptoError::InvalidLength)
        );
        assert!(excessive.iter().all(|b| *b == 0));
        AwsLcProvider
            .hkdf_expand(algorithm, &vec![0; len], &[], &mut [])
            .unwrap();
    }
}

#[test]
fn sha384_extract_expand_matches_native_opaque_extract() {
    // Same-backend cross-check, separate from published SHA256 known answers.
    struct Length(usize);
    impl aws_lc_rs::hkdf::KeyType for Length {
        fn len(&self) -> usize {
            self.0
        }
    }
    let mut extracted = [0; 48];
    let mut adapter = [0; 80];
    let mut native = [0; 80];
    AwsLcProvider
        .hkdf_extract(
            HashAlgorithm::Sha384,
            b"salt",
            b"input key material",
            &mut extracted,
        )
        .unwrap();
    AwsLcProvider
        .hkdf_expand(HashAlgorithm::Sha384, &extracted, b"info", &mut adapter)
        .unwrap();
    let salt = aws_lc_rs::hkdf::Salt::new(aws_lc_rs::hkdf::HKDF_SHA384, b"salt");
    let prk = salt.extract(b"input key material");
    let info = [b"info".as_slice()];
    prk.expand(&info, Length(80))
        .unwrap()
        .fill(&mut native)
        .unwrap();
    assert_eq!(adapter, native);
}

#[test]
fn secure_random_smoke() {
    let mut output = [0; 32];
    AwsLcProvider.fill_random(&mut output).unwrap();
    AwsLcProvider.fill_random(&mut []).unwrap();
    // No probabilistic assertions or claims of statistically tested entropy.
}

#[test]
fn streaming_hash_snapshot_update_reset_and_output_guards() {
    use tls_crypto::{HandshakeCryptoProvider, HashContext};
    for algorithm in [HashAlgorithm::Sha256, HashAlgorithm::Sha384] {
        let mut context = AwsLcProvider.hash_context(algorithm).unwrap();
        assert_eq!(context.algorithm(), algorithm);
        let mut snapshot = vec![0; algorithm.output_len()];
        let mut expected = vec![0; algorithm.output_len()];
        context.update(b"a").unwrap();
        context.update(b"b").unwrap();
        context.snapshot(&mut snapshot).unwrap();
        AwsLcProvider.hash(algorithm, b"ab", &mut expected).unwrap();
        assert_eq!(snapshot, expected);
        context.update(b"c").unwrap();
        context.snapshot(&mut snapshot).unwrap();
        AwsLcProvider
            .hash(algorithm, b"abc", &mut expected)
            .unwrap();
        assert_eq!(snapshot, expected);
        let mut wrong = [0xa5; 1];
        assert_eq!(
            context.snapshot(&mut wrong),
            Err(CryptoError::InvalidLength)
        );
        assert_eq!(wrong, [0]);
        context.snapshot(&mut snapshot).unwrap();
        assert_eq!(snapshot, expected);
        context.reset().unwrap();
        context.snapshot(&mut snapshot).unwrap();
        AwsLcProvider.hash(algorithm, b"", &mut expected).unwrap();
        assert_eq!(snapshot, expected);
        context.update(b"abc").unwrap();
        context.snapshot(&mut snapshot).unwrap();
        AwsLcProvider
            .hash(algorithm, b"abc", &mut expected)
            .unwrap();
        assert_eq!(snapshot, expected);
    }
}

#[test]
fn rfc4231_hmac_case1_and_native_verification() {
    use tls_crypto::HandshakeCryptoProvider;
    for (algorithm, expected) in [
        (
            HashAlgorithm::Sha256,
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
        ),
        (
            HashAlgorithm::Sha384,
            "afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59cfaea9ea9076ede7f4af152e8b2fa9cb6",
        ),
    ] {
        let key = [0x0b; 20];
        let mut tag = vec![0; algorithm.output_len()];
        AwsLcProvider
            .hmac_sign(algorithm, &key, b"Hi There", &mut tag)
            .unwrap();
        assert_eq!(tag, hex(expected));
        AwsLcProvider
            .hmac_verify(algorithm, &key, b"Hi There", &tag)
            .unwrap();
        assert_eq!(
            AwsLcProvider.hmac_verify(algorithm, &key, b"modified", &tag),
            Err(CryptoError::AuthenticationFailed)
        );
        assert_eq!(
            AwsLcProvider.hmac_verify(algorithm, b"different key", b"Hi There", &tag),
            Err(CryptoError::AuthenticationFailed)
        );
        tag[0] ^= 1;
        assert_eq!(
            AwsLcProvider.hmac_verify(algorithm, &key, b"Hi There", &tag),
            Err(CryptoError::AuthenticationFailed)
        );
        assert_eq!(
            AwsLcProvider.hmac_verify(algorithm, &key, b"Hi There", &tag[..tag.len() - 1]),
            Err(CryptoError::InvalidLength)
        );
        let mut wrong = [0xa5; 1];
        assert_eq!(
            AwsLcProvider.hmac_sign(algorithm, &key, b"Hi There", &mut wrong),
            Err(CryptoError::InvalidLength)
        );
        assert_eq!(wrong, [0]);
    }
}
