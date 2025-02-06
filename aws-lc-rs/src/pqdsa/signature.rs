// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

// TODO: Remove
#![allow(missing_docs)]

use crate::aws_lc::EVP_PKEY;
use crate::buffer::Buffer;
use crate::encoding::{AsDer, Pkcs8V1Der, PublicKeyX509Der};
use crate::error::Unspecified;
use crate::evp_pkey::No_EVP_PKEY_CTX_consumer;
use crate::pqdsa::key_pair::PqdsaKeyPair;
use crate::pqdsa::{parse_pqdsa_public_key, AlgorithmID};
use crate::ptr::LcPtr;
use crate::sealed;
use crate::signature::VerificationAlgorithm;
use aws_lc_sys::EVP_PKEY_PQDSA;
use core::fmt;
use core::fmt::{Debug, Formatter};
#[cfg(feature = "ring-sig-verify")]
use untrusted::Input;

/// An PQDSA verification algorithm.
#[derive(Debug, Eq, PartialEq)]
pub struct PqdsaVerificationAlgorithm {
    pub(crate) id: &'static AlgorithmID,
}

impl sealed::Sealed for PqdsaVerificationAlgorithm {}

/// An PQDSA signing algorithm.
#[derive(Debug, Eq, PartialEq)]
pub struct PqdsaSigningAlgorithm(pub(crate) &'static PqdsaVerificationAlgorithm);

/// A PQDSA public key.
#[derive(Clone)]
pub struct PublicKey {
    evp_pkey: LcPtr<EVP_PKEY>,
    pub(crate) octets: Box<[u8]>,
}
unsafe impl Send for PublicKey {}

unsafe impl Sync for PublicKey {}

impl PublicKey {
    pub(crate) fn from_private_evp_pkey(evp_pkey: &LcPtr<EVP_PKEY>) -> Result<Self, Unspecified> {
        let octets = evp_pkey.marshal_raw_public_key()?;
        Ok(Self {
            evp_pkey: evp_pkey.clone(),
            octets: octets.into_boxed_slice(),
        })
    }
}

impl VerificationAlgorithm for PqdsaVerificationAlgorithm {
    /// Verifies the the signature of `msg` using the public key `public_key`.
    ///
    /// # Errors
    /// `error::Unspecified` if the signature is invalid.
    #[cfg(feature = "ring-sig-verify")]
    fn verify(
        &self,
        public_key: Input<'_>,
        msg: Input<'_>,
        signature: Input<'_>,
    ) -> Result<(), Unspecified> {
        self.verify_sig(
            public_key.as_slice_less_safe(),
            msg.as_slice_less_safe(),
            signature.as_slice_less_safe(),
        )
    }

    /// Verifies the signature for `msg` using the `public_key`.
    ///
    /// # Errors
    /// `error::Unspecified` if the signature is invalid.
    fn verify_sig(
        &self,
        public_key: &[u8],
        msg: &[u8],
        signature: &[u8],
    ) -> Result<(), Unspecified> {
        // TODO: Do we need to also allow "raw" public keys?
        let evp_pkey = parse_pqdsa_public_key(public_key, self.id)?;
        evp_pkey.verify(msg, None, No_EVP_PKEY_CTX_consumer, signature)
    }
}

impl AsRef<[u8]> for PublicKey {
    /// Serializes the public key as a raw byte string.
    fn as_ref(&self) -> &[u8] {
        self.octets.as_ref()
    }
}

impl AsDer<PublicKeyX509Der<'static>> for PublicKey {
    /// Provides the public key as a DER-encoded (X.509) `SubjectPublicKeyInfo` structure.
    /// # Errors
    /// Returns an error if the public key fails to marshal to X.509.
    fn as_der(&self) -> Result<PublicKeyX509Der<'static>, crate::error::Unspecified> {
        let der = self.evp_pkey.marshal_rfc5280_public_key()?;
        Ok(PublicKeyX509Der::from(Buffer::new(der)))
    }
}

impl Debug for PublicKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), fmt::Error> {
        f.write_str(&format!(
            "PqdsaPublicKey(\"{}\")",
            crate::hex::encode(self.octets.as_ref())
        ))
    }
}
