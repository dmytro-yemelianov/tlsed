//! Pinned maintained AWS-LC adapter, outside the formally modeled TLS subset.
//! Nonce uniqueness, traffic-key freshness and algorithm usage limits belong to
//! the integrating record engine. See the crate README for trust boundaries.
pub mod agreement;
pub use agreement::AwsLcEphemeral;

use aws_lc_rs::{aead, digest, hkdf, hmac, rand};
use tls_crypto::{
    AeadKey, CipherSuite, CryptoError, CryptoProvider, HandshakeCryptoProvider, HashAlgorithm,
    HashContext, NONCE_LEN, TAG_LEN,
};
use zeroize::Zeroize;

/// Stateless provider. Construction does not weaken authentication or RNG use.
pub struct AwsLcProvider;

/// Connection-owned native AEAD context. Deliberately neither Debug nor Clone.
/// Native context cleanup/erasure is delegated to the maintained provider.
///
/// ```compile_fail
/// use tls_crypto::{CipherSuite, CryptoProvider};
/// use tls_crypto_awslc::AwsLcProvider;
/// let key = AwsLcProvider.aead_key(CipherSuite::Aes128GcmSha256, &[0; 16]).unwrap();
/// let duplicate = key.clone();
/// ```
/// ```compile_fail
/// use tls_crypto::{CipherSuite, CryptoProvider};
/// use tls_crypto_awslc::AwsLcProvider;
/// let key = AwsLcProvider.aead_key(CipherSuite::Aes128GcmSha256, &[0; 16]).unwrap();
/// println!("{key:?}");
/// ```
pub struct AwsLcKey {
    suite: CipherSuite,
    key: aead::LessSafeKey,
}

/// Erase caller bytes with aligned u128 stores, as `Reassembler::drop` does.
fn wipe(bytes: &mut [u8]) {
    let (head, words, tail) = bytemuck::pod_align_to_mut::<u8, u128>(bytes);
    head.zeroize();
    words.zeroize();
    tail.zeroize();
}

impl AeadKey for AwsLcKey {
    fn suite(&self) -> CipherSuite {
        self.suite
    }

    fn seal_in_place(
        &self,
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        buffer: &mut [u8],
        plaintext_len: usize,
    ) -> Result<usize, CryptoError> {
        let result = (|| {
            let total = plaintext_len
                .checked_add(TAG_LEN)
                .ok_or(CryptoError::InvalidLength)?;
            if total > buffer.len() {
                return Err(CryptoError::InvalidLength);
            }
            let tag = self
                .key
                .seal_in_place_separate_tag(
                    aead::Nonce::assume_unique_for_key(*nonce),
                    aead::Aad::from(aad),
                    &mut buffer[..plaintext_len],
                )
                .map_err(|_| CryptoError::BackendFailure)?;
            buffer[plaintext_len..total].copy_from_slice(tag.as_ref());
            Ok(total)
        })();
        if result.is_err() {
            wipe(buffer);
        }
        result
    }

    fn open_in_place(
        &self,
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        buffer: &mut [u8],
    ) -> Result<usize, CryptoError> {
        let result = if buffer.len() < TAG_LEN {
            Err(CryptoError::InvalidLength)
        } else {
            self.key
                .open_in_place(
                    aead::Nonce::assume_unique_for_key(*nonce),
                    aead::Aad::from(aad),
                    buffer,
                )
                .map(|plaintext| plaintext.len())
                .map_err(|_| CryptoError::AuthenticationFailed)
        };
        // The provider may modify the buffer before reporting an invalid tag.
        // Wipe even the tag and every supplied byte on every returned error.
        if result.is_err() {
            wipe(buffer);
        }
        result
    }
}

fn digest_algorithm(algorithm: HashAlgorithm) -> &'static digest::Algorithm {
    match algorithm {
        HashAlgorithm::Sha256 => &digest::SHA256,
        HashAlgorithm::Sha384 => &digest::SHA384,
    }
}
fn hmac_algorithm(algorithm: HashAlgorithm) -> hmac::Algorithm {
    match algorithm {
        HashAlgorithm::Sha256 => hmac::HMAC_SHA256,
        HashAlgorithm::Sha384 => hmac::HMAC_SHA384,
    }
}
fn hkdf_algorithm(algorithm: HashAlgorithm) -> hkdf::Algorithm {
    match algorithm {
        HashAlgorithm::Sha256 => hkdf::HKDF_SHA256,
        HashAlgorithm::Sha384 => hkdf::HKDF_SHA384,
    }
}
struct OutputLength(usize);
impl hkdf::KeyType for OutputLength {
    fn len(&self) -> usize {
        self.0
    }
}

impl CryptoProvider for AwsLcProvider {
    type Key = AwsLcKey;
    fn supports(&self, suite: CipherSuite) -> bool {
        matches!(
            suite,
            CipherSuite::Aes128GcmSha256
                | CipherSuite::Aes256GcmSha384
                | CipherSuite::Chacha20Poly1305Sha256
        )
    }
    fn aead_key(&self, suite: CipherSuite, key: &[u8]) -> Result<Self::Key, CryptoError> {
        if key.len() != suite.key_len() {
            return Err(CryptoError::InvalidKey);
        }
        let algorithm = match suite {
            CipherSuite::Aes128GcmSha256 => &aead::AES_128_GCM,
            CipherSuite::Aes256GcmSha384 => &aead::AES_256_GCM,
            CipherSuite::Chacha20Poly1305Sha256 => &aead::CHACHA20_POLY1305,
        };
        let key = aead::UnboundKey::new(algorithm, key).map_err(|_| CryptoError::BackendFailure)?;
        Ok(AwsLcKey {
            suite,
            key: aead::LessSafeKey::new(key),
        })
    }
    fn fill_random(&self, output: &mut [u8]) -> Result<(), CryptoError> {
        if rand::fill(output).is_err() {
            output.zeroize();
            return Err(CryptoError::EntropyUnavailable);
        }
        Ok(())
    }
    fn hash(
        &self,
        algorithm: HashAlgorithm,
        input: &[u8],
        output: &mut [u8],
    ) -> Result<(), CryptoError> {
        if output.len() != algorithm.output_len() {
            output.zeroize();
            return Err(CryptoError::InvalidLength);
        }
        output.copy_from_slice(digest::digest(digest_algorithm(algorithm), input).as_ref());
        Ok(())
    }
    fn hkdf_extract(
        &self,
        algorithm: HashAlgorithm,
        salt: &[u8],
        input_key_material: &[u8],
        output: &mut [u8],
    ) -> Result<(), CryptoError> {
        let result = (|| {
            if output.len() != algorithm.output_len() {
                return Err(CryptoError::InvalidLength);
            }
            // RFC 5869 section 2.2: Extract = HMAC(salt, IKM). AWS-LC's
            // opaque Salt::extract cannot export its PRK through a public API.
            let default_salt = [0; 48];
            let salt = if salt.is_empty() {
                &default_salt[..algorithm.output_len()]
            } else {
                salt
            };
            let key = hmac::Key::new(hmac_algorithm(algorithm), salt);
            hmac::sign_to_buffer(&key, input_key_material, output)
                .map_err(|_| CryptoError::BackendFailure)?;
            Ok(())
        })();
        if result.is_err() {
            output.zeroize();
        }
        result
    }
    fn hkdf_expand(
        &self,
        algorithm: HashAlgorithm,
        pseudorandom_key: &[u8],
        info: &[u8],
        output: &mut [u8],
    ) -> Result<(), CryptoError> {
        let result = (|| {
            // Restrict to exact Extract outputs for this TLS provider boundary.
            if pseudorandom_key.len() != algorithm.output_len() {
                return Err(CryptoError::InvalidKey);
            }
            if output.len() > 255 * algorithm.output_len() {
                return Err(CryptoError::InvalidLength);
            }
            if output.is_empty() {
                return Ok(());
            }
            // Guards above keep the constructor's fixed PRK storage in bounds.
            let prk = hkdf::Prk::new_less_safe(hkdf_algorithm(algorithm), pseudorandom_key);
            let info = [info];
            prk.expand(&info, OutputLength(output.len()))
                .map_err(|_| CryptoError::BackendFailure)?
                .fill(output)
                .map_err(|_| CryptoError::BackendFailure)
        })();
        if result.is_err() {
            output.zeroize();
        }
        result
    }
}

/// Bounded native streaming hash state; no retained input/transcript bytes.
/// Snapshot clones the maintained digest state, not the transcript. Native
/// initialization/copy/update/finalization panic behavior remains trusted.
pub struct AwsLcHashContext {
    algorithm: HashAlgorithm,
    context: digest::Context,
    bytes: u64,
}

impl HashContext for AwsLcHashContext {
    fn algorithm(&self) -> HashAlgorithm {
        self.algorithm
    }
    fn update(&mut self, input: &[u8]) -> Result<(), CryptoError> {
        let size = u64::try_from(input.len()).map_err(|_| CryptoError::InvalidLength)?;
        let total = self
            .bytes
            .checked_add(size)
            .ok_or(CryptoError::InvalidLength)?;
        // Conservative 64-bit bit-length cap for this TLS transcript boundary,
        // including SHA384. It also excludes native byte-counter overflow.
        if total > u64::MAX / 8 {
            return Err(CryptoError::InvalidLength);
        }
        self.context.update(input);
        self.bytes = total;
        Ok(())
    }
    fn snapshot(&self, output: &mut [u8]) -> Result<(), CryptoError> {
        if output.len() != self.algorithm.output_len() {
            output.zeroize();
            return Err(CryptoError::InvalidLength);
        }
        output.copy_from_slice(self.context.clone().finish().as_ref());
        Ok(())
    }
    fn reset(&mut self) -> Result<(), CryptoError> {
        self.context = digest::Context::new(digest_algorithm(self.algorithm));
        self.bytes = 0;
        Ok(())
    }
}

impl HandshakeCryptoProvider for AwsLcProvider {
    type Hasher = AwsLcHashContext;
    fn hash_context(&self, algorithm: HashAlgorithm) -> Result<Self::Hasher, CryptoError> {
        Ok(AwsLcHashContext {
            algorithm,
            context: digest::Context::new(digest_algorithm(algorithm)),
            bytes: 0,
        })
    }
    fn hmac_sign(
        &self,
        algorithm: HashAlgorithm,
        key: &[u8],
        input: &[u8],
        output: &mut [u8],
    ) -> Result<(), CryptoError> {
        let result = (|| {
            if output.len() != algorithm.output_len() {
                return Err(CryptoError::InvalidLength);
            }
            let key = hmac::Key::new(hmac_algorithm(algorithm), key);
            hmac::sign_to_buffer(&key, input, output).map_err(|_| CryptoError::BackendFailure)?;
            Ok(())
        })();
        if result.is_err() {
            output.zeroize();
        }
        result
    }
    fn hmac_verify(
        &self,
        algorithm: HashAlgorithm,
        key: &[u8],
        input: &[u8],
        tag: &[u8],
    ) -> Result<(), CryptoError> {
        if tag.len() != algorithm.output_len() {
            return Err(CryptoError::InvalidLength);
        }
        let key = hmac::Key::new(hmac_algorithm(algorithm), key);
        hmac::verify(&key, input, tag).map_err(|_| CryptoError::AuthenticationFailed)
    }
}

#[cfg(test)]
mod error_path_erasure {
    use super::*;

    #[test]
    fn failed_seal_and_open_wipe_the_whole_buffer() {
        let key = AwsLcProvider
            .aead_key(CipherSuite::Aes128GcmSha256, &[7; 16])
            .unwrap();
        let nonce = [0u8; NONCE_LEN];
        let aad = b"header";
        for total in [1usize, 15, 16, 17, 1_041, 16_401] {
            // Plaintext longer than the buffer: seal fails and wipes everything.
            let mut small = vec![0xA5u8; total];
            assert!(
                key.seal_in_place(&nonce, aad, &mut small, total + 1)
                    .is_err()
            );
            assert!(small.iter().all(|&b| b == 0), "seal total={total}");
            if total < TAG_LEN {
                // Too short to hold a tag: open fails and wipes everything.
                let mut short = vec![0x5Au8; total];
                assert!(key.open_in_place(&nonce, aad, &mut short).is_err());
                assert!(short.iter().all(|&b| b == 0), "short open total={total}");
            } else {
                // Valid record with a flipped tag: open fails and wipes everything.
                let mut record = vec![0x5Au8; total];
                key.seal_in_place(&nonce, aad, &mut record, total - TAG_LEN)
                    .unwrap();
                let last = record.len() - 1;
                record[last] ^= 1;
                assert!(key.open_in_place(&nonce, aad, &mut record).is_err());
                assert!(record.iter().all(|&b| b == 0), "tag open total={total}");
            }
        }
    }
}
