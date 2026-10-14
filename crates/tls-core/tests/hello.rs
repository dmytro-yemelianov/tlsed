use tls_core::hello::{
    ClientHelloParams, CodecError, MAX_OFFERED_CODES, encode_client_hello, parse_certificate,
    parse_certificate_verify, parse_encrypted_extensions, parse_server_hello,
};
use tls_core::transcript::HELLO_RETRY_REQUEST_RANDOM;

fn hex(input: &str) -> Vec<u8> {
    input
        .split_whitespace()
        .map(|b| u8::from_str_radix(b, 16).unwrap())
        .collect()
}
fn extension(kind: u16, data: &[u8]) -> Vec<u8> {
    let mut out = kind.to_be_bytes().to_vec();
    out.extend_from_slice(&(data.len() as u16).to_be_bytes());
    out.extend_from_slice(data);
    out
}
fn share() -> Vec<u8> {
    let mut out = vec![0, 29, 0, 32];
    out.extend_from_slice(&[7; 32]);
    out
}
fn server_hello(retry: bool, extensions: &[Vec<u8>]) -> Vec<u8> {
    let mut out = vec![3, 3];
    out.extend_from_slice(if retry {
        &HELLO_RETRY_REQUEST_RANDOM
    } else {
        &[0x37; 32]
    });
    out.extend_from_slice(&[3, 1, 2, 3, 0x13, 1, 0]);
    let mut ext = vec![];
    for value in extensions {
        ext.extend_from_slice(value);
    }
    out.extend_from_slice(&(ext.len() as u16).to_be_bytes());
    out.extend_from_slice(&ext);
    out
}
fn ee(extensions: &[Vec<u8>]) -> Vec<u8> {
    let mut out = vec![];
    for value in extensions {
        out.extend_from_slice(value);
    }
    let mut body = (out.len() as u16).to_be_bytes().to_vec();
    body.extend_from_slice(&out);
    body
}
fn params<'a>(random: &'a [u8; 32], key: &'a [u8]) -> ClientHelloParams<'a> {
    ClientHelloParams {
        random,
        session_id: &[],
        server_name: Some(b"example.com"),
        alpn: b"h2",
        suites: &[0x1301, 0x1303],
        groups: &[29, 23],
        signatures: &[0x0804, 0x0403, 0x0807],
        key_share_group: 29,
        key_share: key,
        cookie: None,
    }
}

#[test]
fn published_server_hello_hrr_and_server_flight_auth_views() {
    let server = hex(include_str!("fixtures/rfc8448_server_hello.hex"));
    let parsed = parse_server_hello(&server[4..]).unwrap();
    assert!(!parsed.is_retry);
    assert_eq!(parsed.suite, 0x1301);
    assert!(parsed.session_id.is_empty());
    assert_eq!(parsed.key_share.unwrap().group, 29);
    assert_eq!(parsed.key_share.unwrap().key.len(), 32);
    let hrr = hex(include_str!("fixtures/rfc8448_hrr.hex"));
    let parsed = parse_server_hello(&hrr[4..]).unwrap();
    assert!(parsed.is_retry);
    assert_eq!(parsed.selected_group, Some(23));
    assert!(parsed.key_share.is_none());
    let flight = hex(include_str!(
        "fixtures/rfc8448_server_handshake_payload.hex"
    ));
    // Historical CH offered record_size_limit; ours does not. Preserve fail-closed
    // behavior for the full EE, then test its supported groups/SNI subset.
    assert_eq!(
        parse_encrypted_extensions(&flight[4..40]),
        Err(CodecError::UnsupportedExtension)
    );
    let mut subset = vec![0, 28];
    subset.extend_from_slice(&flight[6..30]);
    subset.extend_from_slice(&flight[36..40]);
    let encrypted = parse_encrypted_extensions(&subset).unwrap();
    assert!(encrypted.server_name_ack);
    assert!(encrypted.alpn.is_none());
    assert!(encrypted.supported_groups.is_some());
    let mut chain = [&[][..]; 4];
    assert_eq!(parse_certificate(&flight[44..485], &mut chain), Ok(1));
    assert_eq!(chain[0].len(), 432);
    assert!(chain[1..].iter().all(|v| v.is_empty()));
    let verify = parse_certificate_verify(&flight[489..621]).unwrap();
    assert_eq!(verify.scheme, 0x0804);
    assert_eq!(verify.signature.len(), 128);
    assert!(chain[0].as_ptr() >= flight.as_ptr());
}

#[test]
fn server_hello_limits_version_selection_duplicates_and_placement() {
    let versions = extension(43, &[3, 4]);
    let key = extension(51, &share());
    let body = server_hello(false, &[versions.clone(), key.clone()]);
    for cut in 0..body.len() {
        assert!(parse_server_hello(&body[..cut]).is_err());
    }
    let parsed = parse_server_hello(&body).unwrap();
    assert_eq!(parsed.session_id, &[1, 2, 3]);
    assert!(parsed.cookie.is_none());
    // RFC9846 requires ignoring legacy_version when supported_versions exists.
    for legacy in [0, 0x0301, 0x0303, 0xffff] {
        let mut changed = body.clone();
        changed[..2].copy_from_slice(&u16::try_from(legacy).unwrap().to_be_bytes());
        assert!(parse_server_hello(&changed).is_ok());
    }
    for extensions in [
        vec![versions.clone(), versions.clone(), key.clone()],
        vec![versions.clone(), key.clone(), key.clone()],
    ] {
        assert_eq!(
            parse_server_hello(&server_hello(false, &extensions)),
            Err(CodecError::DuplicateExtension)
        );
    }
    for kind in [0, 10, 13, 16, 41, 42, 44, 0xffff] {
        assert_eq!(
            parse_server_hello(&server_hello(
                false,
                &[versions.clone(), key.clone(), extension(kind, &[])]
            )),
            Err(CodecError::UnsupportedExtension)
        );
    }
    assert_eq!(
        parse_server_hello(&server_hello(false, std::slice::from_ref(&versions))),
        Err(CodecError::MissingExtension)
    );
    assert_eq!(
        parse_server_hello(&server_hello(false, std::slice::from_ref(&key))),
        Err(CodecError::MissingExtension)
    );
    assert!(
        parse_server_hello(&server_hello(false, &[extension(43, &[3, 3]), key.clone()])).is_err()
    );
    assert!(
        parse_server_hello(&server_hello(
            false,
            &[extension(43, &[3, 4, 0]), key.clone()]
        ))
        .is_err()
    );
    assert!(
        parse_server_hello(&server_hello(
            false,
            &[versions.clone(), extension(51, &[0, 29, 0, 0])]
        ))
        .is_err()
    );
    let mut wrong = body.clone();
    wrong[40] = 1;
    assert!(parse_server_hello(&wrong).is_err()); // compression
    let mut extra = body;
    extra.push(0);
    assert_eq!(parse_server_hello(&extra), Err(CodecError::InvalidLength));
}

#[test]
fn cookie_only_retry_and_retry_key_share_format() {
    let versions = extension(43, &[3, 4]);
    let cookie = extension(44, &[0, 3, 1, 2, 3]);
    let body = server_hello(true, &[versions.clone(), cookie.clone()]);
    let parsed = parse_server_hello(&body).unwrap();
    assert!(parsed.is_retry);
    assert_eq!(parsed.cookie, Some(&[1, 2, 3][..]));
    assert!(parsed.selected_group.is_none());
    assert!(
        parse_server_hello(&server_hello(
            true,
            &[versions.clone(), extension(51, &[0, 23])]
        ))
        .is_ok()
    );
    assert!(
        parse_server_hello(&server_hello(
            true,
            &[versions.clone(), extension(51, &share())]
        ))
        .is_err()
    );
    assert!(parse_server_hello(&server_hello(true, std::slice::from_ref(&versions))).is_err());
    assert!(
        parse_server_hello(&server_hello(
            true,
            &[versions.clone(), extension(44, &[0, 0])]
        ))
        .is_err()
    );
    assert_eq!(
        parse_server_hello(&server_hello(true, &[versions, cookie.clone(), cookie])),
        Err(CodecError::DuplicateExtension)
    );
}

#[test]
fn encrypted_extensions_single_alpn_empty_ack_group_vector_and_fail_closed() {
    let alpn = extension(16, &[0, 3, 2, b'h', b'2']);
    let ack = extension(0, &[]);
    let groups = extension(10, &[0, 4, 0, 29, 0, 23]);
    let body = ee(&[ack.clone(), alpn.clone(), groups.clone()]);
    let parsed = parse_encrypted_extensions(&body).unwrap();
    assert_eq!(parsed.alpn, Some(&b"h2"[..]));
    assert!(parsed.server_name_ack);
    assert_eq!(parsed.supported_groups, Some(&[0, 29, 0, 23][..]));
    for cut in 0..body.len() {
        assert!(parse_encrypted_extensions(&body[..cut]).is_err());
    }
    for value in [ack, alpn, groups] {
        assert_eq!(
            parse_encrypted_extensions(&ee(&[value.clone(), value])),
            Err(CodecError::DuplicateExtension)
        );
    }
    for kind in [13, 41, 42, 43, 44, 45, 49, 51, 0xffff] {
        assert_eq!(
            parse_encrypted_extensions(&ee(&[extension(kind, &[])])),
            Err(CodecError::UnsupportedExtension)
        );
    }
    for (kind, value) in [
        (0, &[1][..]),
        (16, &[0, 1, 0][..]),
        (16, &[0, 4, 1, b'a', 1, b'b'][..]),
        (10, &[0, 0][..]),
        (10, &[0, 1, 0][..]),
    ] {
        assert!(parse_encrypted_extensions(&ee(&[extension(kind, value)])).is_err());
    }
    assert_eq!(parse_encrypted_extensions(&[0, 0]).unwrap().alpn, None);
}

fn certificates(entries: &[(&[u8], &[u8])], context: &[u8]) -> Vec<u8> {
    let mut list = vec![];
    for (der, extensions) in entries {
        let n = der.len();
        list.extend_from_slice(&[
            ((n >> 16) & 255) as u8,
            ((n >> 8) & 255) as u8,
            (n & 255) as u8,
        ]);
        list.extend_from_slice(der);
        list.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        list.extend_from_slice(extensions);
    }
    let n = list.len();
    let mut out = vec![context.len() as u8];
    out.extend_from_slice(context);
    out.extend_from_slice(&[
        ((n >> 16) & 255) as u8,
        ((n >> 8) & 255) as u8,
        (n & 255) as u8,
    ]);
    out.extend_from_slice(&list);
    out
}
#[test]
fn certificate_borrowing_two_pass_atomic_slots_and_auth_lengths() {
    let body = certificates(&[(&[0x30, 1, 0][..], &[]), (&[0x30, 1, 1][..], &[])], &[]);
    let mut slots = [&b"old"[..]; 3];
    assert_eq!(parse_certificate(&body, &mut slots), Ok(2));
    assert_eq!(slots[0], &[0x30, 1, 0]);
    assert_eq!(slots[1], &[0x30, 1, 1]);
    assert!(slots[2].is_empty());
    for cut in 0..body.len() {
        slots.fill(b"old");
        assert!(parse_certificate(&body[..cut], &mut slots).is_err());
        assert!(slots.iter().all(|value| value.is_empty()));
    }
    let mut short = [&b"old"[..]; 1];
    assert_eq!(
        parse_certificate(&body, &mut short),
        Err(CodecError::BufferTooSmall)
    );
    assert!(short[0].is_empty());
    for bad in [
        certificates(&[], &[]),
        certificates(&[(&[], &[])], &[]),
        certificates(&[(&[1], &[])], &[1]),
        certificates(&[(&[1], &[0, 5, 0, 0])], &[]),
        vec![0, 255, 255, 255],
        vec![0, 0, 0, 3, 255, 255, 255],
    ] {
        let mut bad_slots = [&b"old"[..]; 3];
        assert!(parse_certificate(&bad, &mut bad_slots).is_err());
        assert!(bad_slots.iter().all(|value| value.is_empty()));
    }
    let verify = [8, 4, 0, 3, 1, 2, 3];
    let parsed = parse_certificate_verify(&verify).unwrap();
    assert_eq!(parsed.scheme, 0x0804);
    assert_eq!(parsed.signature, &[1, 2, 3]);
    for cut in 0..verify.len() {
        assert!(parse_certificate_verify(&verify[..cut]).is_err());
    }
    assert!(parse_certificate_verify(&[8, 4, 0, 0]).is_err());
    assert!(parse_certificate_verify(&[8, 4, 0, 1, 1, 2]).is_err());
}

#[test]
fn client_encoding_lengths_and_exact_extension_layout() {
    let random = [0xA5; 32];
    let key = [7; 32];
    let mut configured = params(&random, &key);
    configured.session_id = &[9; 32];
    configured.cookie = Some(&[1, 2, 3]);
    let mut output = [0xEE; 2048];
    let length = encode_client_hello(&configured, &mut output).unwrap();
    assert_eq!(output[0], 1);
    let body_len =
        (usize::from(output[1]) << 16) | (usize::from(output[2]) << 8) | usize::from(output[3]);
    assert_eq!(body_len + 4, length);
    assert_eq!(&output[4..6], &[3, 3]);
    assert_eq!(&output[6..38], &random);
    assert_eq!(output[38], 32);
    assert_eq!(&output[39..71], &[9; 32]);
    let mut cursor = 71;
    let suites_len = usize::from(u16::from_be_bytes([output[cursor], output[cursor + 1]]));
    cursor += 2;
    assert_eq!(suites_len, 4);
    assert_eq!(&output[cursor..cursor + 4], &[0x13, 1, 0x13, 3]);
    cursor += 4;
    assert_eq!(&output[cursor..cursor + 2], &[1, 0]);
    cursor += 2;
    let extensions_len = usize::from(u16::from_be_bytes([output[cursor], output[cursor + 1]]));
    cursor += 2;
    assert_eq!(cursor + extensions_len, length);
    let expected = [
        (43, vec![2, 3, 4]),
        (10, vec![0, 4, 0, 29, 0, 23]),
        (13, vec![0, 6, 8, 4, 4, 3, 8, 7]),
        (51, {
            let mut b = vec![0, 36, 0, 29, 0, 32];
            b.extend_from_slice(&key);
            b
        }),
        (0, {
            let mut b = vec![0, 14, 0, 0, 11];
            b.extend_from_slice(b"example.com");
            b
        }),
        (16, vec![0, 3, 2, b'h', b'2']),
        (44, vec![0, 3, 1, 2, 3]),
    ];
    for (kind, bytes) in expected {
        assert_eq!(
            u16::from_be_bytes([output[cursor], output[cursor + 1]]),
            kind
        );
        let n = usize::from(u16::from_be_bytes([output[cursor + 2], output[cursor + 3]]));
        cursor += 4;
        assert_eq!(n, bytes.len());
        assert_eq!(&output[cursor..cursor + n], bytes);
        cursor += n;
    }
    assert_eq!(cursor, length);
    assert!(output[length..].iter().all(|&b| b == 0xEE));
    for size in 0..length {
        output.fill(0xEE);
        assert_eq!(
            encode_client_hello(&configured, &mut output[..size]),
            Err(CodecError::BufferTooSmall)
        );
        assert!(output.iter().all(|&b| b == 0xEE));
    }
}

#[test]
fn client_invalid_configuration_dns_and_protocol_bounds_are_atomic() {
    let random = [0xA5; 32];
    let key = [7; 32];
    let mut output = [0xEE; 2048];
    for name in [
        &b""[..],
        b"127.0.0.1",
        b"[::1]",
        b"::1",
        b"*.example.com",
        b"a..b",
        b"a.",
        b"-a",
        b"a-",
        b"foo_bar",
        b"\xFF.example",
        &[b'a'; 254],
    ] {
        let mut p = params(&random, &key);
        p.server_name = Some(name);
        assert_eq!(
            encode_client_hello(&p, &mut output),
            Err(CodecError::InvalidName)
        );
        assert!(output.iter().all(|&b| b == 0xEE));
    }
    for mode in 0..8 {
        let mut p = params(&random, &key);
        match mode {
            0 => p.session_id = &[0; 33],
            1 => p.alpn = &[0; 256],
            2 => p.suites = &[],
            3 => p.groups = &[29, 29],
            4 => p.signatures = &[0x0403; MAX_OFFERED_CODES + 1],
            5 => p.key_share = &[],
            6 => p.key_share_group = 0xffff,
            _ => p.cookie = Some(&[]),
        };
        assert_eq!(
            encode_client_hello(&p, &mut output),
            Err(CodecError::InvalidParameter)
        );
        assert!(output.iter().all(|&b| b == 0xEE));
    }
    for name in [
        b"localhost".as_slice(),
        b"xn--example.test",
        b"a.example",
        b"123.example",
    ] {
        let mut p = params(&random, &key);
        p.server_name = Some(name);
        assert!(encode_client_hello(&p, &mut output).is_ok());
        output.fill(0xEE);
    }
    let mut p = params(&random, &key);
    p.server_name = None;
    p.alpn = &[];
    assert!(encode_client_hello(&p, &mut output).is_ok());
    let large_share = vec![1; 65529];
    let mut p = params(&random, &large_share);
    assert_eq!(
        encode_client_hello(&p, &mut output),
        Err(CodecError::InvalidLength)
    );
    p.key_share = &[7; 32];
    let huge_cookie = vec![1; 65533];
    p.cookie = Some(&huge_cookie);
    assert_eq!(
        encode_client_hello(&p, &mut output),
        Err(CodecError::InvalidLength)
    );
}
