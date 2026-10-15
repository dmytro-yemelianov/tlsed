use std::cell::RefCell;
use tls_core::key_schedule::{
    HandshakeSecrets, KeyScheduleError, MAX_HKDF_LABEL, encode_hkdf_label, expand_label,
    hkdf_label_encoded_len,
};
use tls_crypto::{
    CipherSuite, CryptoError, CryptoProvider, HandshakeCryptoProvider, HashAlgorithm,
};
use tls_crypto_awslc::{AwsLcHashContext, AwsLcKey, AwsLcProvider};

fn hex(input: &str) -> Vec<u8> {
    let bytes: Vec<_> = input.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    assert_eq!(bytes.len() % 2, 0, "hex fixture contains a dangling nibble");
    bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u8::from_str_radix(core::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}
const HELLO_HASH: &str = "860c06edc07858ee8e78f0e7428c58edd6b43f2ca3e6e95f02ed063cf0e1cad8";
const SERVER_FINISHED_HASH: &str =
    "9608102a0f1ccc6db6250b7b7e417b1a000eaada3daae4777a7686c9ff83df13";
const SHARED: &str = "8bd4054fb55b9d63fdfbacf9f04b9f0d35e6d63f537563efd46272900f89492d";

#[derive(Default)]
struct Recorded {
    extracts: RefCell<Vec<Vec<u8>>>,
    expands: RefCell<Vec<(Vec<u8>, Vec<u8>)>>,
}
// Public deterministic RFC/test fixture secrets only; production providers must
// never log these values. This wrapper observes actual orchestration calls.
impl CryptoProvider for Recorded {
    type Key = AwsLcKey;
    fn supports(&self, suite: CipherSuite) -> bool {
        AwsLcProvider.supports(suite)
    }
    fn aead_key(&self, suite: CipherSuite, key: &[u8]) -> Result<Self::Key, CryptoError> {
        AwsLcProvider.aead_key(suite, key)
    }
    fn fill_random(&self, output: &mut [u8]) -> Result<(), CryptoError> {
        AwsLcProvider.fill_random(output)
    }
    fn hash(&self, alg: HashAlgorithm, input: &[u8], output: &mut [u8]) -> Result<(), CryptoError> {
        AwsLcProvider.hash(alg, input, output)
    }
    fn hkdf_extract(
        &self,
        alg: HashAlgorithm,
        salt: &[u8],
        ikm: &[u8],
        output: &mut [u8],
    ) -> Result<(), CryptoError> {
        AwsLcProvider.hkdf_extract(alg, salt, ikm, output)?;
        self.extracts.borrow_mut().push(output.to_vec());
        Ok(())
    }
    fn hkdf_expand(
        &self,
        alg: HashAlgorithm,
        prk: &[u8],
        info: &[u8],
        output: &mut [u8],
    ) -> Result<(), CryptoError> {
        AwsLcProvider.hkdf_expand(alg, prk, info, output)?;
        let end = 3 + usize::from(info.get(2).copied().unwrap_or_default());
        self.expands.borrow_mut().push((
            info.get(9..end).unwrap_or_default().to_vec(),
            output.to_vec(),
        ));
        Ok(())
    }
}
impl HandshakeCryptoProvider for Recorded {
    type Hasher = AwsLcHashContext;
    fn hash_context(&self, alg: HashAlgorithm) -> Result<Self::Hasher, CryptoError> {
        AwsLcProvider.hash_context(alg)
    }
    fn hmac_sign(
        &self,
        alg: HashAlgorithm,
        key: &[u8],
        input: &[u8],
        output: &mut [u8],
    ) -> Result<(), CryptoError> {
        AwsLcProvider.hmac_sign(alg, key, input, output)
    }
    fn hmac_verify(
        &self,
        alg: HashAlgorithm,
        key: &[u8],
        input: &[u8],
        tag: &[u8],
    ) -> Result<(), CryptoError> {
        AwsLcProvider.hmac_verify(alg, key, input, tag)
    }
}
impl Recorded {
    fn assert_expand(&self, label: &[u8], nth: usize, expected: &str) {
        assert_eq!(
            self.expands
                .borrow()
                .iter()
                .filter(|(actual, _)| actual == label)
                .nth(nth)
                .unwrap()
                .1,
            hex(expected)
        );
    }
}

#[test]
fn rfc8448_section3_full_no_psk_chain_keys_ivs_and_finished() {
    // Independently published intermediates from RFC8448 section3, pp4-13:
    // https://www.rfc-editor.org/rfc/rfc8448.txt. Expected values are not generated
    // by this implementation or its provider. Certificate validity is unrelated.
    let provider = Recorded::default();
    let hs = HandshakeSecrets::derive(
        &provider,
        CipherSuite::Aes128GcmSha256,
        &hex(SHARED),
        &hex(HELLO_HASH),
    )
    .unwrap();
    assert_eq!(
        provider.extracts.borrow()[0],
        hex("33ad0a1c607ec03b09e6cd9893680ce210adf300aa1f2660e1b22e10f170f92a")
    );
    assert_eq!(
        provider.extracts.borrow()[1],
        hex("1dc826e93606aa6fdc0aadc12f741b01046aa6b99f691ed221a9f0ca043fbeac")
    );
    provider.assert_expand(
        b"derived",
        0,
        "6f2615a108c702c5678f54fc9dbab69716c076189c48250cebeac3576c3611ba",
    );
    provider.assert_expand(
        b"c hs traffic",
        0,
        "b3eddb126e067f35a780b3abf45e2d8f3b1a950738f52e9600746a0e27a55a21",
    );
    provider.assert_expand(
        b"s hs traffic",
        0,
        "b67b7d690cc16c4e75e54213cb2d37b4e9c912bcded9105d42befd59d391ad38",
    );
    let client_key = hs.client.key_material(&provider).unwrap();
    let server_key = hs.server.key_material(&provider).unwrap();
    assert_eq!(
        client_key.key_bytes(),
        hex("dbfaa693d1762c5b666af5d950258d01")
    );
    assert_eq!(client_key.iv_bytes(), hex("5bd3c71b836e0b76bb73265f"));
    assert_eq!(
        server_key.key_bytes(),
        hex("3fce516009c21727d0f2e4e86ee403bc")
    );
    assert_eq!(server_key.iv_bytes(), hex("5d313eb2671276ee13000b30"));
    let mut before_server_finished = Vec::new();
    // RFC transcript CH..SH digest cannot extend directly. The published server
    // pre-Finished hash is recomputed using actual CH/SH plus existing flight
    // fixture; exact CH/SH are extracted below as hexadecimal message fixtures.
    before_server_finished.extend_from_slice(&hex("010000c00303cb34ecb1e78163ba1c38c6dacb196a6dffa21a8d9912ec18a2ef6283024dece7000006130113031302010000910000000b0009000006736572766572ff01000100000a00140012001d0017001800190100010101020103010400230000003300260024001d002099381de560e4bd43d23d8e435a7dbafeb3c06e51c13cae4d5413691e529aaf2c002b0003020304000d0020001e040305030603020308040805080604010501060102010402050206020202002d00020101001c00024001"));
    before_server_finished.extend_from_slice(&hex("020000560303a6af06a4121860dc5e6e60249cd34c95930c8ac5cb1434dac155772ed3e2692800130100002e00330024001d0020c9828876112095fe66762bdbf7c672e156d6cc253b833df1dd69b1b04e751f0f002b00020304"));
    let flight = hex(include_str!(
        "fixtures/rfc8448_server_handshake_payload.hex"
    ));
    before_server_finished.extend_from_slice(&flight[..621]);
    let mut server_hash = [0; 32];
    provider
        .hash(
            HashAlgorithm::Sha256,
            &before_server_finished,
            &mut server_hash,
        )
        .unwrap();
    let mut finished = [0; 32];
    hs.server
        .sign_finished(&provider, &server_hash, &mut finished)
        .unwrap();
    assert_eq!(
        finished,
        hex("9b9b141d906337fbd2cbdce71df4deda4ab42c309572cb7fffee5454b78f0718").as_slice()
    );
    hs.server
        .verify_finished(&provider, &server_hash, &finished)
        .unwrap();
    provider.assert_expand(
        b"finished",
        0,
        "008d3b66f816ea559f96b537e885c31fc068bf492c652f01f288a1d8cdc19fc8",
    );
    let transition = hs
        .into_application(&provider, &hex(SERVER_FINISHED_HASH))
        .unwrap();
    assert_eq!(
        provider.extracts.borrow()[2],
        hex("18df06843d13a08bf2a449844c5f8a478001bc4d4c627984d5a41da8d0402919")
    );
    provider.assert_expand(
        b"derived",
        1,
        "43de77e0c77713859a944db9db2590b53190a65b3ee2e4f12dd7a0bb7ce254b4",
    );
    provider.assert_expand(
        b"c ap traffic",
        0,
        "9e40646ce79a7f9dc05af8889bce6552875afa0b06df0087f792ebb7c17504a5",
    );
    provider.assert_expand(
        b"s ap traffic",
        0,
        "a11af9f05531f856ad47116b45a950328204b4f44bfb6b3a4b4f1f3fcb631643",
    );
    assert_eq!(
        transition.application.exporter.as_bytes(),
        hex("fe22f881176eda18eb8f44529e6792c50c9a3f89452f68d8ae311b4309d3cf50")
    );
    let client_key = transition
        .application
        .client
        .key_material(&provider)
        .unwrap();
    let server_key = transition
        .application
        .server
        .key_material(&provider)
        .unwrap();
    assert_eq!(
        client_key.key_bytes(),
        hex("17422dda596ed5d9acd890e3c63f5051")
    );
    assert_eq!(client_key.iv_bytes(), hex("5b78923dee08579033e523d9"));
    assert_eq!(
        server_key.key_bytes(),
        hex("9f02283b6c9c07efc26bb9f2ac92e356")
    );
    assert_eq!(server_key.iv_bytes(), hex("cf782b88dd83549aadf1e984"));
    transition
        .client_handshake
        .sign_finished(&provider, &hex(SERVER_FINISHED_HASH), &mut finished)
        .unwrap();
    assert_eq!(
        finished,
        hex("a8ec436d677634ae525ac1fcebe11a039ec17694fac6e98527b642f2edd5ce61").as_slice()
    );
    transition
        .client_handshake
        .verify_finished(&provider, &hex(SERVER_FINISHED_HASH), &finished)
        .unwrap();
    provider.assert_expand(
        b"finished",
        2,
        "b80ad01015fb2f0bd65ff7d4da5d6bf83f84821d1f87fdc7d3c75b5a7b42d9c4",
    );
}

#[test]
fn sha384_independent_cryptography_openssl_fixture() {
    // Generated with maintained Python cryptography50.0.2/OpenSSL4.0.3,
    // independently of AWSLC; reproducible generator in docs/KEY_SCHEDULE.md.
    let shared: Vec<u8> = (0..32).collect();
    let hs = HandshakeSecrets::derive(
        &AwsLcProvider,
        CipherSuite::Aes256GcmSha384,
        &shared,
        &[0x31; 48],
    )
    .unwrap();
    let c = hs.client.key_material(&AwsLcProvider).unwrap();
    let s = hs.server.key_material(&AwsLcProvider).unwrap();
    assert_eq!(
        c.key_bytes(),
        hex("197cc5f81ce7b4421f87bf5ad559d17a570b9535e0d6c8086cdf31b2c54808d4")
    );
    assert_eq!(c.iv_bytes(), hex("983c7fcbc9653fb8ada04154"));
    assert_eq!(
        s.key_bytes(),
        hex("670a25cf962ff7fb6c60244727218417480f7c70370be68d599580b3494a83da")
    );
    assert_eq!(s.iv_bytes(), hex("c7411625000116733e37d5a8"));
    let mut finished = [0; 48];
    hs.server
        .sign_finished(&AwsLcProvider, &[0x52; 48], &mut finished)
        .unwrap();
    assert_eq!(finished,hex("44eb8159388c43cd9dd2411d5c852e6d80a240f66317b1f22d44d20eb09d1b5b313c7ddb23fd8657c3fb08bec8036c2f").as_slice());
    let transition = hs.into_application(&AwsLcProvider, &[0x52; 48]).unwrap();
    let c = transition
        .application
        .client
        .key_material(&AwsLcProvider)
        .unwrap();
    let s = transition
        .application
        .server
        .key_material(&AwsLcProvider)
        .unwrap();
    assert_eq!(
        c.key_bytes(),
        hex("cdea5c4a68adf81425c009ef44c123bd76c39b8d7340e1f5513245056762eb4d")
    );
    assert_eq!(c.iv_bytes(), hex("eb0b1dcbe99e875db01391ab"));
    assert_eq!(
        s.key_bytes(),
        hex("fdc3edd19a8f7f39f36a13f1078add87d24487a76c6acf03cc395259621f9927")
    );
    assert_eq!(s.iv_bytes(), hex("f59e212548f872713f128dd2"));
    assert_eq!(
        transition.application.exporter.as_bytes(),
        hex(
            "ef84951c87fea1b4a601189c8a2e8cacbfcdbe2c6b434992ad4db8ef8f1564d06be3b04e4c1e73b8a464a1452b7a2984"
        )
    );
    let updated = transition
        .application
        .client
        .into_sending()
        .update(&AwsLcProvider)
        .unwrap();
    assert_eq!(updated.epoch(), 1);
    assert_eq!(
        updated.key_material(&AwsLcProvider).unwrap().key_bytes(),
        hex("6f3293e37c3f077b4a3a46e4ff1fa9fb607b658da54f67f5d7f51c3693596c3d")
    );
}

#[test]
fn label_codec_edges_exact_bytes_small_buffers_and_wiping() {
    for out in [0, 1, 65535, 65536, usize::MAX] {
        for label in [0, 1, 249, 250, usize::MAX] {
            for context in [0, 1, 255, 256, usize::MAX] {
                let expected = if out <= 65535 && (1..=249).contains(&label) && context <= 255 {
                    Some(10 + label + context)
                } else {
                    None
                };
                assert_eq!(hkdf_label_encoded_len(out, label, context), expected);
            }
        }
    }
    let mut output = [0xA5; MAX_HKDF_LABEL + 3];
    let len = encode_hkdf_label(16, b"key", b"", &mut output).unwrap();
    assert_eq!(&output[..len], hex("001009746c733133206b657900"));
    assert!(output[len..].iter().all(|&b| b == 0xA5));
    assert_eq!(
        encode_hkdf_label(65535, &[0x31; 249], &[0x42; 255], &mut output),
        Ok(514)
    );
    for size in 0..13 {
        output.fill(0xA5);
        assert_eq!(
            encode_hkdf_label(16, b"key", b"", &mut output[..size]),
            Err(KeyScheduleError::BufferTooSmall)
        );
        assert!(output[..size].iter().all(|&b| b == 0));
    }
    for (out, label, context) in [
        (65536, &b"key"[..], &b""[..]),
        (16, &b""[..], &b""[..]),
        (16, &[1; 250][..], &b""[..]),
        (16, &b"key"[..], &[1; 256][..]),
    ] {
        output.fill(0xA5);
        assert_eq!(
            encode_hkdf_label(out, label, context, &mut output),
            Err(KeyScheduleError::InvalidLabel)
        );
        assert!(output.iter().all(|&b| b == 0));
    }
}

#[test]
fn altered_transcripts_tags_direction_labels_and_contexts() {
    for suite in [
        CipherSuite::Aes128GcmSha256,
        CipherSuite::Aes256GcmSha384,
        CipherSuite::Chacha20Poly1305Sha256,
    ] {
        let n = suite.hash().output_len();
        let hash = vec![0x31; n];
        let hs = HandshakeSecrets::derive(&AwsLcProvider, suite, &[7; 32], &hash).unwrap();
        let mut tag = vec![0; n];
        hs.server
            .sign_finished(&AwsLcProvider, &hash, &mut tag)
            .unwrap();
        for i in 0..n {
            let mut bad = tag.clone();
            bad[i] ^= 1;
            assert!(
                hs.server
                    .verify_finished(&AwsLcProvider, &hash, &bad)
                    .is_err()
            );
        }
        let mut altered_hash = hash.clone();
        altered_hash[0] ^= 1;
        assert!(
            hs.server
                .verify_finished(&AwsLcProvider, &altered_hash, &tag)
                .is_err()
        );
        assert!(
            hs.client
                .verify_finished(&AwsLcProvider, &hash, &tag)
                .is_err()
        );
        assert_eq!(
            hs.server
                .verify_finished(&AwsLcProvider, &hash, &tag[..n - 1]),
            Err(KeyScheduleError::InvalidHashLength)
        );
        let mut short = vec![0xA5; n - 1];
        assert_eq!(
            hs.server.sign_finished(&AwsLcProvider, &hash, &mut short),
            Err(KeyScheduleError::InvalidHashLength)
        );
        assert!(short.iter().all(|&b| b == 0));
        let mut a = vec![0; n];
        let mut b = vec![0; n];
        expand_label(&AwsLcProvider, suite.hash(), &hash, b"key", b"x", &mut a).unwrap();
        expand_label(&AwsLcProvider, suite.hash(), &hash, b"iv", b"x", &mut b).unwrap();
        assert_ne!(a, b);
        expand_label(&AwsLcProvider, suite.hash(), &hash, b"key", b"y", &mut b).unwrap();
        assert_ne!(a, b);
        let before = hs.server.key_material(&AwsLcProvider).unwrap();
        let altered =
            HandshakeSecrets::derive(&AwsLcProvider, suite, &[7; 32], &altered_hash).unwrap();
        assert_ne!(
            before.key_bytes(),
            altered
                .server
                .key_material(&AwsLcProvider)
                .unwrap()
                .key_bytes()
        );
        let app = hs
            .into_application(&AwsLcProvider, &hash)
            .unwrap()
            .application;
        let send = app.client.into_sending();
        let receive = app.server.into_receiving();
        let old_key = send.key_material(&AwsLcProvider).unwrap();
        let send = send.update(&AwsLcProvider).unwrap();
        let receive = receive.update(&AwsLcProvider).unwrap();
        assert_eq!(send.epoch(), 1);
        assert_eq!(receive.epoch(), 1);
        assert_ne!(
            old_key.key_bytes(),
            send.key_material(&AwsLcProvider).unwrap().key_bytes()
        );
    }
}

#[derive(Clone, Copy)]
enum Failure {
    Hash,
    Extract,
    Expand,
    Sign,
    Unsupported,
}
struct Failing(Failure);
impl CryptoProvider for Failing {
    type Key = AwsLcKey;
    fn supports(&self, suite: CipherSuite) -> bool {
        !matches!(self.0, Failure::Unsupported) && AwsLcProvider.supports(suite)
    }
    fn aead_key(&self, suite: CipherSuite, key: &[u8]) -> Result<Self::Key, CryptoError> {
        AwsLcProvider.aead_key(suite, key)
    }
    fn fill_random(&self, output: &mut [u8]) -> Result<(), CryptoError> {
        AwsLcProvider.fill_random(output)
    }
    fn hash(&self, alg: HashAlgorithm, input: &[u8], output: &mut [u8]) -> Result<(), CryptoError> {
        if matches!(self.0, Failure::Hash) {
            output.fill(0x42);
            Err(CryptoError::BackendFailure)
        } else {
            AwsLcProvider.hash(alg, input, output)
        }
    }
    fn hkdf_extract(
        &self,
        alg: HashAlgorithm,
        salt: &[u8],
        ikm: &[u8],
        output: &mut [u8],
    ) -> Result<(), CryptoError> {
        if matches!(self.0, Failure::Extract) {
            output.fill(0x42);
            Err(CryptoError::BackendFailure)
        } else {
            AwsLcProvider.hkdf_extract(alg, salt, ikm, output)
        }
    }
    fn hkdf_expand(
        &self,
        alg: HashAlgorithm,
        prk: &[u8],
        info: &[u8],
        output: &mut [u8],
    ) -> Result<(), CryptoError> {
        if matches!(self.0, Failure::Expand) {
            output.fill(0x42);
            Err(CryptoError::BackendFailure)
        } else {
            AwsLcProvider.hkdf_expand(alg, prk, info, output)
        }
    }
}
impl HandshakeCryptoProvider for Failing {
    type Hasher = AwsLcHashContext;
    fn hash_context(&self, alg: HashAlgorithm) -> Result<Self::Hasher, CryptoError> {
        AwsLcProvider.hash_context(alg)
    }
    fn hmac_sign(
        &self,
        alg: HashAlgorithm,
        key: &[u8],
        input: &[u8],
        output: &mut [u8],
    ) -> Result<(), CryptoError> {
        if matches!(self.0, Failure::Sign) {
            output.fill(0x42);
            Err(CryptoError::BackendFailure)
        } else {
            AwsLcProvider.hmac_sign(alg, key, input, output)
        }
    }
    fn hmac_verify(
        &self,
        alg: HashAlgorithm,
        key: &[u8],
        input: &[u8],
        tag: &[u8],
    ) -> Result<(), CryptoError> {
        AwsLcProvider.hmac_verify(alg, key, input, tag)
    }
}

#[test]
fn invalid_input_and_faulting_provider_never_return_secret_success() {
    let suite = CipherSuite::Aes128GcmSha256;
    for (shared, hash, error) in [
        (
            &b""[..],
            &[0; 32][..],
            KeyScheduleError::InvalidSharedSecret,
        ),
        (
            &[0; 257][..],
            &[0; 32][..],
            KeyScheduleError::InvalidSharedSecret,
        ),
        (
            &[1; 32][..],
            &[0; 48][..],
            KeyScheduleError::InvalidHashLength,
        ),
    ] {
        assert!(
            matches!(HandshakeSecrets::derive(&AwsLcProvider,suite,shared,hash),Err(actual) if actual==error)
        );
    }
    for failure in [
        Failure::Hash,
        Failure::Extract,
        Failure::Expand,
        Failure::Unsupported,
    ] {
        assert!(HandshakeSecrets::derive(&Failing(failure), suite, &[1; 32], &[0; 32]).is_err());
    }
    let hs = HandshakeSecrets::derive(&AwsLcProvider, suite, &[1; 32], &[0; 32]).unwrap();
    let mut output = [0xA5; 32];
    for failure in [Failure::Expand, Failure::Sign] {
        output.fill(0xA5);
        assert!(
            hs.server
                .sign_finished(&Failing(failure), &[0; 32], &mut output)
                .is_err()
        );
        assert_eq!(output, [0; 32]);
    }
    output.fill(0xA5);
    assert!(
        expand_label(
            &Failing(Failure::Expand),
            HashAlgorithm::Sha256,
            &[1; 32],
            b"key",
            b"",
            &mut output
        )
        .is_err()
    );
    assert_eq!(output, [0; 32]);
    output.fill(0xA5);
    assert_eq!(
        expand_label(
            &AwsLcProvider,
            HashAlgorithm::Sha256,
            &[1; 48],
            b"key",
            b"",
            &mut output
        ),
        Err(KeyScheduleError::InvalidHashLength)
    );
    assert_eq!(output, [0; 32]);
    assert!(
        hs.into_application(&Failing(Failure::Extract), &[0; 32])
            .is_err()
    );
    let hs = HandshakeSecrets::derive(&AwsLcProvider, suite, &[1; 32], &[0; 32]).unwrap();
    let app = hs
        .into_application(&AwsLcProvider, &[0; 32])
        .unwrap()
        .application;
    assert!(
        app.client
            .into_sending()
            .update(&Failing(Failure::Expand))
            .is_err()
    );
}
