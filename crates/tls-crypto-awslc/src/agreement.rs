//! Maintained fresh ECDHE, with TLS share formatting and consuming ownership.
use crate::AwsLcProvider;
use aws_lc_rs::{agreement, rand::SystemRandom};
use tls_crypto::{CryptoError, EphemeralKeyExchange, KeyExchangeProvider, NamedGroup};
use zeroize::Zeroize;

fn algorithm(group: NamedGroup) -> &'static agreement::Algorithm {
    match group {
        NamedGroup::X25519 => &agreement::X25519,
        NamedGroup::Secp256r1 => &agreement::ECDH_P256,
    }
}
fn valid_share_shape(group: NamedGroup, share: &[u8]) -> bool {
    share.len() == group.public_key_len()
        && (group != NamedGroup::Secp256r1 || share.first() == Some(&0x04))
}

/// Fresh native private owner, neither Clone nor Debug. Consuming completion
/// prevents repeated agreement even on a caller length/peer-format failure.
///
/// ```compile_fail
/// use tls_crypto::{EphemeralKeyExchange,KeyExchangeProvider,NamedGroup};
/// use tls_crypto_awslc::AwsLcProvider;
/// let a=AwsLcProvider.start_key_exchange(NamedGroup::X25519).unwrap();
/// let b=AwsLcProvider.start_key_exchange(NamedGroup::X25519).unwrap();
/// let peer=b.public_key().to_vec();
/// a.complete(&peer,&mut [0;32]).unwrap();
/// a.complete(&peer,&mut [0;32]).unwrap();
/// ```
/// ```compile_fail
/// use tls_crypto::{KeyExchangeProvider,NamedGroup};
/// use tls_crypto_awslc::AwsLcProvider;
/// let key=AwsLcProvider.start_key_exchange(NamedGroup::X25519).unwrap();
/// let copy=key.clone();
/// ```
/// ```compile_fail
/// use tls_crypto::{KeyExchangeProvider,NamedGroup};
/// use tls_crypto_awslc::AwsLcProvider;
/// let key=AwsLcProvider.start_key_exchange(NamedGroup::X25519).unwrap();
/// println!("{key:?}");
/// ```
pub struct AwsLcEphemeral {
    group: NamedGroup,
    private: agreement::EphemeralPrivateKey,
    public: agreement::PublicKey,
}
impl EphemeralKeyExchange for AwsLcEphemeral {
    fn group(&self) -> NamedGroup {
        self.group
    }
    fn public_key(&self) -> &[u8] {
        self.public.as_ref()
    }
    fn complete(self, peer_share: &[u8], output: &mut [u8]) -> Result<(), CryptoError> {
        let result = (|| {
            if output.len() != self.group.shared_secret_len() {
                return Err(CryptoError::InvalidLength);
            }
            if !valid_share_shape(self.group, peer_share) {
                return Err(CryptoError::InvalidKey);
            }
            let peer = agreement::UnparsedPublicKey::new(algorithm(self.group), peer_share);
            agreement::agree_ephemeral(self.private, peer, CryptoError::InvalidKey, |secret| {
                if secret.len() != output.len() {
                    return Err(CryptoError::BackendFailure);
                }
                output.copy_from_slice(secret);
                Ok(())
            })
        })();
        if result.is_err() {
            output.zeroize();
        }
        result
    }
}
impl KeyExchangeProvider for AwsLcProvider {
    type Ephemeral = AwsLcEphemeral;
    fn start_key_exchange(&self, group: NamedGroup) -> Result<Self::Ephemeral, CryptoError> {
        let private =
            agreement::EphemeralPrivateKey::generate(algorithm(group), &SystemRandom::new())
                .map_err(|_| CryptoError::BackendFailure)?;
        let public = private
            .compute_public_key()
            .map_err(|_| CryptoError::BackendFailure)?;
        if !valid_share_shape(group, public.as_ref()) {
            return Err(CryptoError::BackendFailure);
        }
        Ok(AwsLcEphemeral {
            group,
            private,
            public,
        })
    }
}
