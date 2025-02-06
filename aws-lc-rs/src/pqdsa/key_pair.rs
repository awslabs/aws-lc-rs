// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

// TODO: Remove
#![allow(missing_docs)]

use crate::aws_lc::{EVP_PKEY_CTX_pqdsa_set_params, EVP_PKEY, EVP_PKEY_PQDSA};
use crate::buffer::Buffer;
use crate::constant_time::verify_slices_are_equal;
use crate::encoding::{AsBigEndian, AsDer, AsRawBytes, Pkcs8V1Der, PqdsaPrivateKeyBin};
use crate::error::Unspecified;
use crate::evp_pkey::No_EVP_PKEY_CTX_consumer;
use crate::pkcs8;
use crate::pkcs8::{Document, Version};
use crate::pqdsa::signature::{PqdsaSigningAlgorithm, PublicKey};
use crate::pqdsa::validate_pqdsa_evp_key;
use crate::ptr::LcPtr;
use crate::signature::KeyPair;
use core::fmt::{Debug, Formatter};
use std::ffi::c_int;

/// A PQDSA (Post-Quantum Digital Signature Algorithm) key pair, used for signing.
///
/// # Example
/// TODO:
#[allow(clippy::module_name_repetitions)]
pub struct PqdsaKeyPair {
    algorithm: &'static PqdsaSigningAlgorithm,
    evp_pkey: LcPtr<EVP_PKEY>,
    pubkey: PublicKey,
}

#[allow(clippy::missing_fields_in_debug)]
impl Debug for PqdsaKeyPair {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PqdsaKeyPair")
            .field("algorithm", &self.algorithm)
            .finish()
    }
}

impl KeyPair for PqdsaKeyPair {
    type PublicKey = PublicKey;

    fn public_key(&self) -> &Self::PublicKey {
        &self.pubkey
    }
}

pub struct PqdsaPrivateKey<'a>(&'a PqdsaKeyPair);

impl AsDer<Pkcs8V1Der<'static>> for PqdsaPrivateKey<'_> {
    /// Serializes the key to PKCS#8 v1 DER.
    ///
    /// # Errors
    /// Returns `Unspecified` if serialization fails.
    fn as_der(&self) -> Result<Pkcs8V1Der<'static>, Unspecified> {
        Ok(Pkcs8V1Der::new(
            self.0
                .evp_pkey
                .marshal_rfc5208_private_key(pkcs8::Version::V1)?,
        ))
    }
}

impl AsRawBytes<PqdsaPrivateKeyBin<'static>> for PqdsaPrivateKey<'_> {
    fn as_raw_bytes(&self) -> Result<PqdsaPrivateKeyBin<'static>, Unspecified> {
        Ok(PqdsaPrivateKeyBin::new(
            self.0.evp_pkey.marshal_raw_private_key()?,
        ))
    }
}

impl PqdsaKeyPair {
    /// Generates a new PQDSA key pair for the specified algorithm.
    ///
    /// # Errors
    /// Returns `Unspecified` is the key generation fails.
    pub fn generate(algorithm: &'static PqdsaSigningAlgorithm) -> Result<Self, Unspecified> {
        let evp_pkey = evp_key_pqdsa_generate(algorithm.0.id.nid())?;
        let pubkey = PublicKey::from_private_evp_pkey(&evp_pkey)?;
        Ok(Self {
            algorithm,
            evp_pkey,
            pubkey,
        })
    }

    /// Parses a PKCS#8 v1 key from the specified bytes.
    ///
    /// # Errors
    /// Returns `Unspecified` if the key is invalid.
    pub fn from_pkcs8(
        algorithm: &'static PqdsaSigningAlgorithm,
        pkcs8: &[u8],
    ) -> Result<Self, Unspecified> {
        let evp_pkey = LcPtr::<EVP_PKEY>::parse_rfc5208_private_key(pkcs8, EVP_PKEY_PQDSA)?;
        validate_pqdsa_evp_key(&evp_pkey, algorithm.0.id)?;
        let pubkey = PublicKey::from_private_evp_pkey(&evp_pkey)?;
        Ok(Self {
            algorithm,
            evp_pkey,
            pubkey,
        })
    }

    /// Constructs a key pair from a raw private key.
    ///
    /// # Errors
    /// Returns `Unspecified` if the key is invalid or the corresponding public key is invalid.
    pub fn from_raw_private_key(
        algorithm: &'static PqdsaSigningAlgorithm,
        raw_private_key: &[u8],
    ) -> Result<Self, Unspecified> {
        let evp_pkey = LcPtr::<EVP_PKEY>::parse_raw_private_key(raw_private_key, EVP_PKEY_PQDSA)?;
        validate_pqdsa_evp_key(&evp_pkey, algorithm.0.id)?;
        let pubkey = PublicKey::from_private_evp_pkey(&evp_pkey)?;
        Ok(Self {
            algorithm,
            evp_pkey,
            pubkey,
        })
    }

    /// Parses a PKCS#8 v1 key from the specified bytes.
    ///
    /// # Errors
    /// Returns `Unspecified` if the key is invalid.
    pub fn from_raw_private_key_and_public_key(
        algorithm: &'static PqdsaSigningAlgorithm,
        raw_private_key: &[u8],
        raw_public_key: &[u8],
    ) -> Result<Self, Unspecified> {
        let priv_evp_pkey =
            LcPtr::<EVP_PKEY>::parse_raw_private_key(raw_private_key, EVP_PKEY_PQDSA)?;
        validate_pqdsa_evp_key(&priv_evp_pkey, algorithm.0.id)?;
        let pubkey = PublicKey::from_private_evp_pkey(&priv_evp_pkey)?;

        // Verify the public/private key correspond
        let pub_evp_pkey = LcPtr::<EVP_PKEY>::parse_raw_public_key(raw_public_key, EVP_PKEY_PQDSA)?;
        let pubkey_octets = priv_evp_pkey.marshal_raw_public_key()?;
        verify_slices_are_equal(pubkey_octets.as_slice(), &pubkey.octets)?;

        Ok(Self {
            algorithm,
            evp_pkey: priv_evp_pkey,
            pubkey,
        })
    }

    /// Serializes the key to PKCS#8 v1 DER.
    ///
    /// # Errors
    /// Returns `Unspecified` if serialization fails.
    pub fn to_pkcs8(&self) -> Result<Document, Unspecified> {
        Ok(Document::new(
            self.evp_pkey.marshal_rfc5208_private_key(Version::V1)?,
        ))
    }

    /// Uses thie key to sign the specified message.
    ///
    /// # Errors
    /// Returns `Unspecified` if an error occurs.
    pub fn sign(&self, msg: &[u8]) -> Result<crate::signature::Signature, Unspecified> {
        let sig_bytes = self.evp_pkey.sign(msg, None, No_EVP_PKEY_CTX_consumer)?;
        // TODO: Should we use crate::signature::Signature?
        Ok(crate::signature::Signature::new(|buf| {
            buf[0..sig_bytes.len()].copy_from_slice(&sig_bytes);
            sig_bytes.len()
        }))
    }

    /// Returns the signing algorithm associated with this key pair.
    #[must_use]
    pub fn algorithm(&self) -> &'static PqdsaSigningAlgorithm {
        self.algorithm
    }

    /// Returns the private key associated with this key pair.
    #[must_use]
    pub fn private_key(&self) -> PqdsaPrivateKey {
        PqdsaPrivateKey(self)
    }
}

unsafe impl Send for PqdsaKeyPair {}

unsafe impl Sync for PqdsaKeyPair {}

pub(crate) fn evp_key_pqdsa_generate(nid: c_int) -> Result<LcPtr<EVP_PKEY>, Unspecified> {
    let params_fn = |ctx| {
        if 1 == unsafe { EVP_PKEY_CTX_pqdsa_set_params(ctx, nid) } {
            Ok(())
        } else {
            Err(())
        }
    };
    LcPtr::<EVP_PKEY>::generate(EVP_PKEY_PQDSA, Some(params_fn))
}

#[cfg(all(test, feature = "unstable"))]
mod tests {
    use super::*;
    use crate::pqdsa::signature::PqdsaVerificationAlgorithm;
    use crate::pqdsa::AlgorithmID;
    use crate::pqdsa::AlgorithmID::MLDSA_44;
    use crate::signature::{UnparsedPublicKey, VerificationAlgorithm};
    use crate::unstable::signature::{
        PqdsaPublicKey, MLDSA_44_SIGNING, MLDSA_65_SIGNING, MLDSA_87_SIGNING,
    };

    const TEST_ALGORITHMS: &[&PqdsaSigningAlgorithm] =
        &[&MLDSA_44_SIGNING, &MLDSA_65_SIGNING, &MLDSA_87_SIGNING];

    #[test]
    fn test_public_key_serialization() {
        for &alg in TEST_ALGORITHMS {
            // Generate a new key pair
            let keypair = PqdsaKeyPair::generate(alg).unwrap();
            let message = b"Test message";
            let different_message = b"Different message";
            let signature = keypair.sign(message).unwrap();
            let invalid_signature = vec![0u8; alg.0.id.signature_size_bytes()];

            let original_public_key = keypair.public_key();

            let x509_der = original_public_key.as_der().unwrap();
            let x509_public_key = UnparsedPublicKey::new(alg.0, x509_der.as_ref());
            assert!(x509_public_key.verify(message, signature.as_ref()).is_ok());
            assert!(x509_public_key
                .verify(different_message, signature.as_ref())
                .is_err());
            assert!(x509_public_key.verify(message, &invalid_signature).is_err());

            let raw = original_public_key.as_ref();
            let raw_public_key = UnparsedPublicKey::new(alg.0, raw);
            assert!(raw_public_key.verify(message, signature.as_ref()).is_ok());
            assert!(raw_public_key
                .verify(different_message, signature.as_ref())
                .is_err());
            assert!(raw_public_key
                .verify(different_message, &invalid_signature)
                .is_err());

            #[cfg(feature = "ring-sig-verify")]
            #[allow(deprecated)]
            {
                use untrusted::Input;
                assert!(alg
                    .0
                    .verify(
                        raw.into(),
                        message.as_ref().into(),
                        signature.as_ref().into()
                    )
                    .is_ok());
            }
        }
    }

    #[test]
    fn test_private_key_serialization() {
        for &alg in TEST_ALGORITHMS {
            // Generate a new key pair
            let keypair = PqdsaKeyPair::generate(alg).unwrap();
            let message = b"Test message";
            let different_message = b"Different message";
            let original_signature = keypair.sign(message).unwrap();

            let original_public_key = keypair.public_key();

            let pkcs8_1 = keypair.to_pkcs8().unwrap();
            let pkcs8_2 = keypair.private_key().as_der().unwrap();
            let raw = keypair.private_key().as_raw_bytes().unwrap();

            assert_eq!(pkcs8_1.as_ref(), pkcs8_2.as_ref());

            let pkcs8_keypair = PqdsaKeyPair::from_pkcs8(alg, pkcs8_1.as_ref()).unwrap();
            let raw_keypair = PqdsaKeyPair::from_raw_private_key(alg, raw.as_ref()).unwrap();
            let raw_pair_keypair = PqdsaKeyPair::from_raw_private_key_and_public_key(
                alg,
                raw.as_ref(),
                original_public_key.as_ref(),
            )
            .unwrap();
            assert_eq!(pkcs8_keypair.evp_pkey, raw_keypair.evp_pkey);
            assert_eq!(pkcs8_keypair.evp_pkey, raw_pair_keypair.evp_pkey);
        }
    }

    // Additional test for the algorithm getter
    #[test]
    fn test_algorithm_getter() {
        for &alg in TEST_ALGORITHMS {
            let keypair = PqdsaKeyPair::generate(alg).unwrap();
            assert_eq!(keypair.algorithm(), alg);
        }
    }

    // Additional test for the algorithm getter
    #[test]
    fn test_debug() {
        for &alg in TEST_ALGORITHMS {
            let keypair = PqdsaKeyPair::generate(alg).unwrap();
            assert!(
                format!("{keypair:?}").starts_with("PqdsaKeyPair { algorithm: PqdsaSigningAlgorithm(PqdsaVerificationAlgorithm { id:"),
                "{keypair:?}"
            );
            let pubkey = keypair.public_key();
            assert!(
                format!("{pubkey:?}").starts_with("PqdsaPublicKey("),
                "{pubkey:?}"
            );
        }
    }
}
