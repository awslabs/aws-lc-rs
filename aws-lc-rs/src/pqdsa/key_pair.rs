// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

// TODO: Remove
#![allow(missing_docs)]

use crate::aws_lc::{EVP_PKEY_CTX_pqdsa_set_params, EVP_PKEY, EVP_PKEY_PQDSA};
use crate::buffer::Buffer;
use crate::constant_time::verify_slices_are_equal;
use crate::encoding::{AsDer, Pkcs8V1Der};
use crate::error::Unspecified;
use crate::evp_pkey::No_EVP_PKEY_CTX_consumer;
use crate::pkcs8;
use crate::pqdsa::signature::{PqdsaSigningAlgorithm, PublicKey};
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

impl PqdsaKeyPair {
    /// Generates a new PQDSA key pair for the specified algorithm.
    ///
    /// # Error
    /// Returns `Unspecified` is the key generation fails.
    ///

    pub fn generate(algorithm: &'static PqdsaSigningAlgorithm) -> Result<Self, Unspecified> {
        let evp_pkey = evp_key_pqdsa_generate(algorithm.0.id.nid()).unwrap();
        let pubkey = PublicKey::from_private_evp_pkey(&evp_pkey).unwrap();
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
        let evp_pkey = LcPtr::<EVP_PKEY>::parse_rfc5208_private_key(pkcs8, algorithm.0.id.nid())?;
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
        let evp_pkey =
            LcPtr::<EVP_PKEY>::parse_raw_private_key(raw_private_key, algorithm.0.id.nid())?;
        let pubkey = PublicKey::from_private_evp_pkey(&evp_pkey).unwrap();
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
            LcPtr::<EVP_PKEY>::parse_raw_private_key(raw_private_key, algorithm.0.id.nid())?;
        let pubkey = PublicKey::from_private_evp_pkey(&priv_evp_pkey).unwrap();

        // Verify the public/private key correspond
        let pub_evp_pkey =
            LcPtr::<EVP_PKEY>::parse_raw_public_key(raw_public_key, algorithm.0.id.nid())?;
        let pubkey_octets = priv_evp_pkey.marshal_raw_public_key()?;
        verify_slices_are_equal(pubkey_octets.as_slice(), &pubkey.octets)?;

        Ok(Self {
            algorithm,
            evp_pkey: priv_evp_pkey,
            pubkey,
        })
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
}

unsafe impl Send for PqdsaKeyPair {}

unsafe impl Sync for PqdsaKeyPair {}

impl AsDer<Pkcs8V1Der<'static>> for PqdsaKeyPair {
    /// Serializes the key to PKCS#8 v1 DER.
    ///
    /// # Errors
    /// Returns `Unspecified` if serialization fails.
    fn as_der(&self) -> Result<Pkcs8V1Der<'static>, Unspecified> {
        Ok(Pkcs8V1Der::new(
            self.evp_pkey
                .marshal_rfc5208_private_key(pkcs8::Version::V1)?,
        ))
    }
}
pub(crate) fn evp_key_pqdsa_generate(nid: c_int) -> Result<LcPtr<EVP_PKEY>, Unspecified> {
    let params_fn = |ctx| {
        if 1 == unsafe { EVP_PKEY_CTX_pqdsa_set_params(ctx, nid) } {
            return Ok(());
        } else {
            return Err(());
        }
    };
    LcPtr::<EVP_PKEY>::generate(EVP_PKEY_PQDSA, Some(params_fn))
}
