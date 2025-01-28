// Copyright 2015-2017 Brian Smith.
// SPDX-License-Identifier: ISC
// Modifications copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

//! Key Agreement: ECDH, including X25519.
//!
//! # Example
//!
//! Note that this example uses X25519, but ECDH using NIST P-256/P-384 is done
//! exactly the same way, just substituting
//! `agreement::ECDH_P256`/`agreement::ECDH_P384` for `agreement::X25519`.
//!
//! ```
//! use aws_lc_rs::{agreement, rand};
//!
//! let rng = rand::SystemRandom::new();
//!
//! let my_private_key = agreement::EphemeralPrivateKey::generate(&agreement::X25519, &rng)?;
//!
//! // Make `my_public_key` a byte slice containing my public key. In a real
//! // application, this would be sent to the peer in an encoded protocol
//! // message.
//! let my_public_key = my_private_key.compute_public_key()?;
//!
//! let peer_public_key = {
//!     // In a real application, the peer public key would be parsed out of a
//!     // protocol message. Here we just generate one.
//!     let peer_public_key = {
//!         let peer_private_key =
//!             agreement::EphemeralPrivateKey::generate(&agreement::X25519, &rng)?;
//!         peer_private_key.compute_public_key()?
//!     };
//!
//!     agreement::UnparsedPublicKey::new(&agreement::X25519, peer_public_key)
//! };
//!
//! agreement::agree_ephemeral(
//!     my_private_key,
//!     &peer_public_key,
//!     aws_lc_rs::error::Unspecified,
//!     |_key_material| {
//!         // In a real application, we'd apply a KDF to the key material and the
//!         // public keys (as recommended in RFC 7748) and then derive session
//!         // keys from the result. We omit all that here.
//!         Ok(())
//!     },
//! )?;
//!
//! # Ok::<(), aws_lc_rs::error::Unspecified>(())
//! ```
mod ephemeral;

use crate::ec::encoding::sec1::{
    marshal_sec1_private_key, marshal_sec1_public_point, marshal_sec1_public_point_into_buffer,
    parse_sec1_private_bn,
};
use crate::ec::{encoding, evp_key_generate};
use crate::error::{KeyRejected, Unspecified};
use crate::hex;
use crate::ptr::ConstPointer;
pub use ephemeral::{agree_ephemeral, EphemeralPrivateKey};

use crate::aws_lc::{
    EVP_PKEY_CTX_new_id, EVP_PKEY_derive, EVP_PKEY_derive_init, EVP_PKEY_derive_set_peer,
    EVP_PKEY_get0_EC_KEY, EVP_PKEY_keygen, EVP_PKEY_keygen_init, NID_X9_62_prime256v1,
    NID_secp384r1, NID_secp521r1, EVP_PKEY, EVP_PKEY_X25519, NID_X25519,
};

use crate::buffer::Buffer;
use crate::ec;
use crate::ec::encoding::rfc5915::parse_rfc5915_private_key;
use crate::encoding::{
    AsBigEndian, AsDer, Curve25519SeedBin, EcPrivateKeyBin, EcPrivateKeyRfc5915Der,
    EcPublicKeyCompressedBin, EcPublicKeyUncompressedBin, PublicKeyX509Der,
};
use crate::fips::indicator_check;
use crate::ptr::LcPtr;
use core::fmt;
use core::fmt::{Debug, Formatter};
use core::ptr::null_mut;

#[allow(non_camel_case_types)]
#[derive(PartialEq, Eq)]
enum AlgorithmID {
    ECDH_P256,
    ECDH_P384,
    ECDH_P521,
    X25519,
}

impl AlgorithmID {
    #[inline]
    const fn nid(&self) -> i32 {
        match self {
            AlgorithmID::ECDH_P256 => NID_X9_62_prime256v1,
            AlgorithmID::ECDH_P384 => NID_secp384r1,
            AlgorithmID::ECDH_P521 => NID_secp521r1,
            AlgorithmID::X25519 => NID_X25519,
        }
    }

    // Uncompressed public key length in bytes
    #[inline]
    const fn pub_key_len(&self) -> usize {
        match self {
            AlgorithmID::ECDH_P256 => ec::uncompressed_public_key_size_bytes(256),
            AlgorithmID::ECDH_P384 => ec::uncompressed_public_key_size_bytes(384),
            AlgorithmID::ECDH_P521 => ec::uncompressed_public_key_size_bytes(521),
            AlgorithmID::X25519 => 32,
        }
    }

    #[inline]
    const fn private_key_len(&self) -> usize {
        match self {
            AlgorithmID::ECDH_P256 | AlgorithmID::X25519 => 32,
            AlgorithmID::ECDH_P384 => 48,
            AlgorithmID::ECDH_P521 => 66,
        }
    }
}

impl Debug for AlgorithmID {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), fmt::Error> {
        let output = match self {
            AlgorithmID::ECDH_P256 => "curve: P256",
            AlgorithmID::ECDH_P384 => "curve: P384",
            AlgorithmID::ECDH_P521 => "curve: P521",
            AlgorithmID::X25519 => "curve: Curve25519",
        };
        f.write_str(output)
    }
}

/// A key agreement algorithm.
#[derive(PartialEq, Eq)]
pub struct Algorithm {
    id: AlgorithmID,
}

impl Debug for Algorithm {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), fmt::Error> {
        f.write_str(&format!("Algorithm {{ {:?} }}", self.id))
    }
}

/// ECDH using the NSA Suite B P-256 (secp256r1) curve.
pub const ECDH_P256: Algorithm = Algorithm {
    id: AlgorithmID::ECDH_P256,
};

/// ECDH using the NSA Suite B P-384 (secp384r1) curve.
pub const ECDH_P384: Algorithm = Algorithm {
    id: AlgorithmID::ECDH_P384,
};

/// ECDH using the NSA Suite B P-521 (secp521r1) curve.
pub const ECDH_P521: Algorithm = Algorithm {
    id: AlgorithmID::ECDH_P521,
};

/// X25519 (ECDH using Curve25519) as described in [RFC 7748].
///
/// Everything is as described in RFC 7748. Key agreement will fail if the
/// result of the X25519 operation is zero; see the notes on the
/// "all-zero value" in [RFC 7748 section 6.1].
///
/// [RFC 7748]: https://tools.ietf.org/html/rfc7748
/// [RFC 7748 section 6.1]: https://tools.ietf.org/html/rfc7748#section-6.1
pub const X25519: Algorithm = Algorithm {
    id: AlgorithmID::X25519,
};

#[allow(non_camel_case_types)]
enum KeyInner {
    ECDH_P256(LcPtr<EVP_PKEY>),
    ECDH_P384(LcPtr<EVP_PKEY>),
    ECDH_P521(LcPtr<EVP_PKEY>),
    X25519(LcPtr<EVP_PKEY>),
}

impl Clone for KeyInner {
    fn clone(&self) -> KeyInner {
        match self {
            KeyInner::ECDH_P256(evp_pkey) => KeyInner::ECDH_P256(evp_pkey.clone()),
            KeyInner::ECDH_P384(evp_pkey) => KeyInner::ECDH_P384(evp_pkey.clone()),
            KeyInner::ECDH_P521(evp_pkey) => KeyInner::ECDH_P521(evp_pkey.clone()),
            KeyInner::X25519(evp_pkey) => KeyInner::X25519(evp_pkey.clone()),
        }
    }
}

/// A private key for use (only) with `agree`. The
/// signature of `agree` allows `PrivateKey` to be
/// used for more than one key agreement.
pub struct PrivateKey {
    inner_key: KeyInner,
}

impl KeyInner {
    #[inline]
    fn algorithm(&self) -> &'static Algorithm {
        match self {
            KeyInner::ECDH_P256(..) => &ECDH_P256,
            KeyInner::ECDH_P384(..) => &ECDH_P384,
            KeyInner::ECDH_P521(..) => &ECDH_P521,
            KeyInner::X25519(..) => &X25519,
        }
    }

    fn get_evp_pkey(&self) -> &LcPtr<EVP_PKEY> {
        match self {
            KeyInner::ECDH_P256(evp_pkey)
            | KeyInner::ECDH_P384(evp_pkey)
            | KeyInner::ECDH_P521(evp_pkey)
            | KeyInner::X25519(evp_pkey) => evp_pkey,
        }
    }
}

unsafe impl Send for PrivateKey {}

// https://github.com/awslabs/aws-lc/blob/main/include/openssl/ec_key.h#L88
// An |EC_KEY| object represents a public or private EC key. A given object may
// be used concurrently on multiple threads by non-mutating functions, provided
// no other thread is concurrently calling a mutating function. Unless otherwise
// documented, functions which take a |const| pointer are non-mutating and
// functions which take a non-|const| pointer are mutating.
unsafe impl Sync for PrivateKey {}

impl Debug for PrivateKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), fmt::Error> {
        f.write_str(&format!(
            "PrivateKey {{ algorithm: {:?} }}",
            self.inner_key.algorithm()
        ))
    }
}

impl PrivateKey {
    fn new(alg: &'static Algorithm, evp_pkey: LcPtr<EVP_PKEY>) -> Self {
        match alg.id {
            AlgorithmID::X25519 => Self {
                inner_key: KeyInner::X25519(evp_pkey),
            },
            AlgorithmID::ECDH_P256 => Self {
                inner_key: KeyInner::ECDH_P256(evp_pkey),
            },
            AlgorithmID::ECDH_P384 => Self {
                inner_key: KeyInner::ECDH_P384(evp_pkey),
            },
            AlgorithmID::ECDH_P521 => Self {
                inner_key: KeyInner::ECDH_P521(evp_pkey),
            },
        }
    }

    #[inline]
    /// Generate a new private key for the given algorithm.
    // # FIPS
    // Use this function with one of the following algorithms:
    // * `ECDH_P256`
    // * `ECDH_P384`
    // * `ECDH_P521`
    //
    /// # Errors
    /// `error::Unspecified` when operation fails due to internal error.
    pub fn generate(alg: &'static Algorithm) -> Result<Self, Unspecified> {
        let evp_pkey = match alg.id {
            AlgorithmID::X25519 => generate_x25519()?,
            _ => evp_key_generate(alg.id.nid())?,
        };
        Ok(Self::new(alg, evp_pkey))
    }

    /// Deserializes a DER-encoded private key structure to produce a `agreement::PrivateKey`.
    ///
    /// This function is typically used to deserialize RFC 5915 encoded private keys, but it will
    /// attempt to automatically detect other key formats. This function supports unencrypted
    /// PKCS#8 `PrivateKeyInfo` structures as well as key type specific formats.
    ///
    /// X25519 keys are not supported. See `PrivateKey::as_der`.
    ///
    /// # Errors
    /// `error::KeyRejected` if parsing failed or key otherwise unacceptable.
    ///
    /// # Panics
    pub fn from_private_key_der(
        alg: &'static Algorithm,
        key_bytes: &[u8],
    ) -> Result<Self, KeyRejected> {
        if AlgorithmID::X25519 == alg.id {
            return Err(KeyRejected::invalid_encoding());
        }
        let evp_pkey = parse_rfc5915_private_key(key_bytes, alg.id.nid())?;
        Ok(Self::new(alg, evp_pkey))
    }

    /// Constructs an ECDH key from private key bytes
    ///
    /// The private key must encoded as a big-endian fixed-length integer. For
    /// example, a P-256 private key must be 32 bytes prefixed with leading
    /// zeros as needed.
    ///
    /// # Errors
    /// `error::KeyRejected` if parsing failed or key otherwise unacceptable.
    pub fn from_private_key(
        alg: &'static Algorithm,
        key_bytes: &[u8],
    ) -> Result<Self, KeyRejected> {
        if key_bytes.len() != alg.id.private_key_len() {
            return Err(KeyRejected::wrong_algorithm());
        }
        let evp_pkey = if AlgorithmID::X25519 == alg.id {
            LcPtr::<EVP_PKEY>::parse_raw_private_key(key_bytes, EVP_PKEY_X25519)?
        } else {
            parse_sec1_private_bn(key_bytes, alg.id.nid())?
        };
        Ok(Self::new(alg, evp_pkey))
    }

    #[cfg(test)]
    #[allow(clippy::missing_errors_doc, missing_docs)]
    pub fn generate_for_test(
        alg: &'static Algorithm,
        rng: &dyn crate::rand::SecureRandom,
    ) -> Result<Self, Unspecified> {
        match alg.id {
            AlgorithmID::X25519 => {
                let mut priv_key = [0u8; AlgorithmID::X25519.private_key_len()];
                rng.fill(&mut priv_key)?;
                Self::from_x25519_private_key(&priv_key)
            }
            AlgorithmID::ECDH_P256 => {
                let mut priv_key = [0u8; AlgorithmID::ECDH_P256.private_key_len()];
                rng.fill(&mut priv_key)?;
                Self::from_p256_private_key(&priv_key)
            }
            AlgorithmID::ECDH_P384 => {
                let mut priv_key = [0u8; AlgorithmID::ECDH_P384.private_key_len()];
                rng.fill(&mut priv_key)?;
                Self::from_p384_private_key(&priv_key)
            }
            AlgorithmID::ECDH_P521 => {
                let mut priv_key = [0u8; AlgorithmID::ECDH_P521.private_key_len()];
                rng.fill(&mut priv_key)?;
                Self::from_p521_private_key(&priv_key)
            }
        }
    }

    #[cfg(test)]
    fn from_x25519_private_key(
        priv_key: &[u8; AlgorithmID::X25519.private_key_len()],
    ) -> Result<Self, Unspecified> {
        let pkey = LcPtr::<EVP_PKEY>::parse_raw_private_key(priv_key, EVP_PKEY_X25519)?;

        Ok(PrivateKey {
            inner_key: KeyInner::X25519(pkey),
        })
    }

    #[cfg(test)]
    fn from_p256_private_key(priv_key: &[u8]) -> Result<Self, Unspecified> {
        let pkey = parse_sec1_private_bn(priv_key, ECDH_P256.id.nid())?;
        Ok(PrivateKey {
            inner_key: KeyInner::ECDH_P256(pkey),
        })
    }

    #[cfg(test)]
    fn from_p384_private_key(priv_key: &[u8]) -> Result<Self, Unspecified> {
        let pkey = parse_sec1_private_bn(priv_key, ECDH_P384.id.nid())?;
        Ok(PrivateKey {
            inner_key: KeyInner::ECDH_P384(pkey),
        })
    }

    #[cfg(test)]
    fn from_p521_private_key(priv_key: &[u8]) -> Result<Self, Unspecified> {
        let pkey = parse_sec1_private_bn(priv_key, ECDH_P521.id.nid())?;
        Ok(PrivateKey {
            inner_key: KeyInner::ECDH_P521(pkey),
        })
    }

    /// Computes the public key from the private key.
    ///
    /// # Errors
    /// `error::Unspecified` when operation fails due to internal error.
    pub fn compute_public_key(&self) -> Result<PublicKey, Unspecified> {
        match &self.inner_key {
            KeyInner::ECDH_P256(evp_pkey)
            | KeyInner::ECDH_P384(evp_pkey)
            | KeyInner::ECDH_P521(evp_pkey) => {
                let mut public_key = [0u8; MAX_PUBLIC_KEY_LEN];
                let len = marshal_sec1_public_point_into_buffer(&mut public_key, evp_pkey, false)?;
                Ok(PublicKey {
                    inner_key: self.inner_key.clone(),
                    public_key,
                    len,
                })
            }
            KeyInner::X25519(priv_key) => {
                let mut buffer = [0u8; MAX_PUBLIC_KEY_LEN];
                let out_len = priv_key.marshal_raw_public_to_buffer(&mut buffer)?;
                Ok(PublicKey {
                    inner_key: self.inner_key.clone(),
                    public_key: buffer,
                    len: out_len,
                })
            }
        }
    }

    /// The algorithm for the private key.
    #[inline]
    #[must_use]
    pub fn algorithm(&self) -> &'static Algorithm {
        self.inner_key.algorithm()
    }
}

impl AsDer<EcPrivateKeyRfc5915Der<'static>> for PrivateKey {
    /// Serializes the key as a DER-encoded `ECPrivateKey` (RFC 5915) structure.
    ///
    /// X25519 is not supported.
    ///
    /// # Errors
    /// `error::Unspecified`  if serialization failed.
    fn as_der(&self) -> Result<EcPrivateKeyRfc5915Der<'static>, Unspecified> {
        if AlgorithmID::X25519 == self.inner_key.algorithm().id {
            return Err(Unspecified);
        }

        let mut outp = null_mut::<u8>();
        let ec_key = {
            ConstPointer::new(unsafe {
                EVP_PKEY_get0_EC_KEY(*self.inner_key.get_evp_pkey().as_const())
            })?
        };
        let length = usize::try_from(unsafe { aws_lc::i2d_ECPrivateKey(*ec_key, &mut outp) })
            .map_err(|_| Unspecified)?;
        let mut outp = LcPtr::new(outp)?;
        Ok(EcPrivateKeyRfc5915Der::take_from_slice(unsafe {
            core::slice::from_raw_parts_mut(*outp.as_mut(), length)
        }))
    }
}

impl AsBigEndian<EcPrivateKeyBin<'static>> for PrivateKey {
    /// Exposes the private key encoded as a big-endian fixed-length integer.
    ///
    /// X25519 is not supported.
    ///
    /// # Errors
    /// `error::Unspecified` if serialization failed.
    fn as_be_bytes(&self) -> Result<EcPrivateKeyBin<'static>, Unspecified> {
        if AlgorithmID::X25519 == self.inner_key.algorithm().id {
            return Err(Unspecified);
        }
        let buffer = marshal_sec1_private_key(self.inner_key.get_evp_pkey())?;
        Ok(EcPrivateKeyBin::new(buffer))
    }
}

impl AsBigEndian<Curve25519SeedBin<'static>> for PrivateKey {
    /// Exposes the seed encoded as a big-endian fixed-length integer.
    ///
    /// Only X25519 is supported.
    ///
    /// # Errors
    /// `error::Unspecified` if serialization failed.
    fn as_be_bytes(&self) -> Result<Curve25519SeedBin<'static>, Unspecified> {
        if AlgorithmID::X25519 != self.inner_key.algorithm().id {
            return Err(Unspecified);
        }
        let evp_pkey = self.inner_key.get_evp_pkey();
        Ok(Curve25519SeedBin::new(evp_pkey.marshal_raw_private_key()?))
    }
}

pub(crate) fn generate_x25519() -> Result<LcPtr<EVP_PKEY>, Unspecified> {
    let mut pkey_ctx = LcPtr::new(unsafe { EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, null_mut()) })?;

    if 1 != unsafe { EVP_PKEY_keygen_init(*pkey_ctx.as_mut()) } {
        return Err(Unspecified);
    }

    let mut pkey: *mut EVP_PKEY = null_mut();

    if 1 != indicator_check!(unsafe { EVP_PKEY_keygen(*pkey_ctx.as_mut(), &mut pkey) }) {
        return Err(Unspecified);
    }

    let pkey = LcPtr::new(pkey)?;

    Ok(pkey)
}

const MAX_PUBLIC_KEY_LEN: usize = ec::PUBLIC_KEY_MAX_LEN;

/// A public key for key agreement.
pub struct PublicKey {
    inner_key: KeyInner,
    public_key: [u8; MAX_PUBLIC_KEY_LEN],
    len: usize,
}

impl PublicKey {
    /// The algorithm for the public key.
    #[must_use]
    pub fn algorithm(&self) -> &'static Algorithm {
        self.inner_key.algorithm()
    }
}

unsafe impl Send for PublicKey {}
unsafe impl Sync for PublicKey {}

impl Debug for PublicKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(&format!(
            "PublicKey {{ algorithm: {:?}, bytes: \"{}\" }}",
            self.inner_key.algorithm(),
            hex::encode(&self.public_key[0..self.len])
        ))
    }
}

impl AsRef<[u8]> for PublicKey {
    /// Serializes the public key in an uncompressed form (X9.62) using the
    /// Octet-String-to-Elliptic-Curve-Point algorithm in
    /// [SEC 1: Elliptic Curve Cryptography, Version 2.0].
    fn as_ref(&self) -> &[u8] {
        &self.public_key[0..self.len]
    }
}

impl Clone for PublicKey {
    fn clone(&self) -> Self {
        PublicKey {
            inner_key: self.inner_key.clone(),
            public_key: self.public_key,
            len: self.len,
        }
    }
}

impl AsDer<PublicKeyX509Der<'static>> for PublicKey {
    /// Provides the public key as a DER-encoded (X.509) `SubjectPublicKeyInfo` structure.
    /// # Errors
    /// Returns an error if the public key fails to marshal to X.509.
    fn as_der(&self) -> Result<PublicKeyX509Der<'static>, crate::error::Unspecified> {
        match &self.inner_key {
            KeyInner::ECDH_P256(evp_pkey)
            | KeyInner::ECDH_P384(evp_pkey)
            | KeyInner::ECDH_P521(evp_pkey)
            | KeyInner::X25519(evp_pkey) => {
                let der = evp_pkey.marshal_rfc5280_public_key()?;
                Ok(PublicKeyX509Der::from(Buffer::new(der)))
            }
        }
    }
}

impl AsBigEndian<EcPublicKeyCompressedBin<'static>> for PublicKey {
    /// Provides the public key elliptic curve point to a compressed point format.
    /// # Errors
    /// Returns an error if the underlying implementation is unable to marshal the public key to this format.
    fn as_be_bytes(&self) -> Result<EcPublicKeyCompressedBin<'static>, crate::error::Unspecified> {
        let evp_pkey = match &self.inner_key {
            KeyInner::ECDH_P256(evp_pkey)
            | KeyInner::ECDH_P384(evp_pkey)
            | KeyInner::ECDH_P521(evp_pkey) => evp_pkey,
            KeyInner::X25519(_) => return Err(Unspecified),
        };
        let pub_point = marshal_sec1_public_point(evp_pkey, true)?;
        Ok(EcPublicKeyCompressedBin::new(pub_point))
    }
}

impl AsBigEndian<EcPublicKeyUncompressedBin<'static>> for PublicKey {
    /// Provides the public key elliptic curve point to a compressed point format.
    ///
    /// Equivalent to [`PublicKey::as_ref`] for ECDH key types, except that it provides you a copy instead of a reference.
    ///
    /// # Errors
    /// Returns an error if the underlying implementation is unable to marshal the public key to this format.
    fn as_be_bytes(
        &self,
    ) -> Result<EcPublicKeyUncompressedBin<'static>, crate::error::Unspecified> {
        if self.algorithm().id == AlgorithmID::X25519 {
            return Err(Unspecified);
        }

        let mut buffer = vec![0u8; self.len];
        buffer.copy_from_slice(&self.public_key[0..self.len]);

        Ok(EcPublicKeyUncompressedBin::new(buffer))
    }
}

/// An unparsed, possibly malformed, public key for key agreement.
#[derive(Clone)]
pub struct UnparsedPublicKey<B: AsRef<[u8]>> {
    alg: &'static Algorithm,
    bytes: B,
}

impl<B: Copy + AsRef<[u8]>> Copy for UnparsedPublicKey<B> {}

impl<B: Debug + AsRef<[u8]>> Debug for UnparsedPublicKey<B> {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), fmt::Error> {
        f.write_str(&format!(
            "UnparsedPublicKey {{ algorithm: {:?}, bytes: {:?} }}",
            self.alg,
            hex::encode(self.bytes.as_ref())
        ))
    }
}

impl<B: AsRef<[u8]>> UnparsedPublicKey<B> {
    /// Constructs a new `UnparsedPublicKey`.
    pub fn new(algorithm: &'static Algorithm, bytes: B) -> Self {
        UnparsedPublicKey {
            alg: algorithm,
            bytes,
        }
    }

    /// The agreement algorithm associated with this public key
    pub fn algorithm(&self) -> &'static Algorithm {
        self.alg
    }

    /// The bytes provided for this public key
    pub fn bytes(&self) -> &B {
        &self.bytes
    }
}

/// Performs a key agreement with a private key and the given public key.
///
/// `my_private_key` is the private key to use. Only a reference to the key
/// is required, allowing the key to continue to be used.
///
/// `peer_public_key` is the peer's public key. `agree` will return
/// `Err(error_value)` if it does not match `my_private_key's` algorithm/curve.
/// `agree` verifies that it is encoded in the standard form for the
/// algorithm and that the key is *valid*; see the algorithm's documentation for
/// details on how keys are to be encoded and what constitutes a valid key for
/// that algorithm.
///
/// `error_value` is the value to return if an error occurs before `kdf` is
/// called, e.g. when decoding of the peer's public key fails or when the public
/// key is otherwise invalid.
///
/// After the key agreement is done, `agree` calls `kdf` with the raw
/// key material from the key agreement operation and then returns what `kdf`
/// returns.
// # FIPS
// Use this function with one of the following key algorithms:
// * `ECDH_P256`
// * `ECDH_P384`
// * `ECDH_P521`
//
/// # Errors
/// `error_value` on internal failure.
#[inline]
#[allow(clippy::missing_panics_doc)]
pub fn agree<B: AsRef<[u8]>, F, R, E>(
    my_private_key: &PrivateKey,
    peer_public_key: &UnparsedPublicKey<B>,
    error_value: E,
    kdf: F,
) -> Result<R, E>
where
    F: FnOnce(&[u8]) -> Result<R, E>,
{
    let expected_alg = my_private_key.algorithm();
    let expected_nid = expected_alg.id.nid();

    if peer_public_key.alg != expected_alg {
        return Err(error_value);
    }

    let peer_pub_bytes = peer_public_key.bytes.as_ref();

    let mut buffer = [0u8; MAX_AGREEMENT_SECRET_LEN];

    let secret: &[u8] = match &my_private_key.inner_key {
        KeyInner::X25519(priv_key) => {
            x25519_diffie_hellman(&mut buffer, priv_key, peer_pub_bytes).or(Err(error_value))?
        }
        KeyInner::ECDH_P256(priv_key)
        | KeyInner::ECDH_P384(priv_key)
        | KeyInner::ECDH_P521(priv_key) => {
            ec_key_ecdh(&mut buffer, priv_key, peer_pub_bytes, expected_nid).or(Err(error_value))?
        }
    };
    kdf(secret)
}

// Current max secret length is P-521's.
const MAX_AGREEMENT_SECRET_LEN: usize = AlgorithmID::ECDH_P521.private_key_len();

#[inline]
#[allow(clippy::needless_pass_by_value)]
fn ec_key_ecdh<'a>(
    buffer: &'a mut [u8; MAX_AGREEMENT_SECRET_LEN],
    priv_key: &LcPtr<EVP_PKEY>,
    peer_pub_key_bytes: &[u8],
    nid: i32,
) -> Result<&'a [u8], Unspecified> {
    let mut pub_key = encoding::parse_ec_public_key(peer_pub_key_bytes, nid)?;

    let mut pkey_ctx = priv_key.create_EVP_PKEY_CTX()?;

    if 1 != unsafe { EVP_PKEY_derive_init(*pkey_ctx.as_mut()) } {
        return Err(Unspecified);
    };

    if 1 != unsafe { EVP_PKEY_derive_set_peer(*pkey_ctx.as_mut(), *pub_key.as_mut()) } {
        return Err(Unspecified);
    }

    let mut out_key_len = buffer.len();

    if 1 != indicator_check!(unsafe {
        EVP_PKEY_derive(*pkey_ctx.as_mut(), buffer.as_mut_ptr(), &mut out_key_len)
    }) {
        return Err(Unspecified);
    }

    if 0 == out_key_len {
        return Err(Unspecified);
    }

    Ok(&buffer[0..out_key_len])
}

#[inline]
fn x25519_diffie_hellman<'a>(
    buffer: &'a mut [u8; MAX_AGREEMENT_SECRET_LEN],
    priv_key: &LcPtr<EVP_PKEY>,
    peer_pub_key: &[u8],
) -> Result<&'a [u8], ()> {
    let mut pkey_ctx = priv_key.create_EVP_PKEY_CTX()?;

    if 1 != unsafe { EVP_PKEY_derive_init(*pkey_ctx.as_mut()) } {
        return Err(());
    };

    let mut pub_key = try_parse_x25519_public_key_bytes(peer_pub_key)?;

    if 1 != unsafe { EVP_PKEY_derive_set_peer(*pkey_ctx.as_mut(), *pub_key.as_mut()) } {
        return Err(());
    }

    let mut out_key_len = buffer.len();

    if 1 != indicator_check!(unsafe {
        EVP_PKEY_derive(*pkey_ctx.as_mut(), buffer.as_mut_ptr(), &mut out_key_len)
    }) {
        return Err(());
    }

    debug_assert!(out_key_len == AlgorithmID::X25519.pub_key_len());

    Ok(&buffer[0..AlgorithmID::X25519.pub_key_len()])
}

pub(crate) fn try_parse_x25519_public_key_bytes(
    key_bytes: &[u8],
) -> Result<LcPtr<EVP_PKEY>, Unspecified> {
    LcPtr::<EVP_PKEY>::parse_rfc5280_public_key(key_bytes, EVP_PKEY_X25519)
        .or(try_parse_x25519_public_key_raw_bytes(key_bytes))
}

fn try_parse_x25519_public_key_raw_bytes(key_bytes: &[u8]) -> Result<LcPtr<EVP_PKEY>, Unspecified> {
    let expected_pub_key_len = X25519.id.pub_key_len();
    if key_bytes.len() != expected_pub_key_len {
        return Err(Unspecified);
    }

    Ok(LcPtr::<EVP_PKEY>::parse_raw_public_key(
        key_bytes,
        EVP_PKEY_X25519,
    )?)
}

#[cfg(test)]
mod tests {
    use crate::agreement::{
        agree, Algorithm, PrivateKey, PublicKey, UnparsedPublicKey, ECDH_P256, ECDH_P384,
        ECDH_P521, X25519,
    };
    use crate::encoding::{
        AsBigEndian, AsDer, Curve25519SeedBin, EcPrivateKeyBin, EcPrivateKeyRfc5915Der,
        EcPublicKeyCompressedBin, EcPublicKeyUncompressedBin, PublicKeyX509Der,
    };
    use crate::{rand, test};

    #[test]
    fn test_agreement_x25519() {
        let alg = &X25519;
        let peer_public = UnparsedPublicKey::new(
            alg,
            test::from_dirty_hex(
                "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c",
            ),
        );

        let my_private = test::from_dirty_hex(
            "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4",
        );

        let my_private = {
            let rng = test::rand::FixedSliceRandom { bytes: &my_private };
            PrivateKey::generate_for_test(alg, &rng).unwrap()
        };

        let my_public = test::from_dirty_hex(
            "1c9fd88f45606d932a80c71824ae151d15d73e77de38e8e000852e614fae7019",
        );
        let output = test::from_dirty_hex(
            "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552",
        );

        assert_eq!(my_private.algorithm(), alg);

        let be_private_key_buffer: Curve25519SeedBin = my_private.as_be_bytes().unwrap();
        let be_private_key =
            PrivateKey::from_private_key(&X25519, be_private_key_buffer.as_ref()).unwrap();
        {
            let result = agree(&be_private_key, &peer_public, (), |key_material| {
                assert_eq!(key_material, &output[..]);
                Ok(())
            });
            assert_eq!(result, Ok(()));
        }

        let computed_public = my_private.compute_public_key().unwrap();
        assert_eq!(computed_public.as_ref(), &my_public[..]);

        assert_eq!(computed_public.algorithm(), alg);
        {
            let result = agree(&my_private, &peer_public, (), |key_material| {
                assert_eq!(key_material, &output[..]);
                Ok(())
            });
            assert_eq!(result, Ok(()));
        }
        {
            let result = agree(&my_private, &peer_public, (), |key_material| {
                assert_eq!(key_material, &output[..]);
                Ok(())
            });
            assert_eq!(result, Ok(()));
        }
    }

    #[test]
    fn test_agreement_invalid_keys() {
        fn test_with_key(alg: &'static Algorithm, my_private_key: &PrivateKey, test_key: &[u8]) {
            assert!(PrivateKey::from_private_key(alg, test_key).is_err());
            assert!(PrivateKey::from_private_key_der(alg, test_key).is_err());
            assert!(agree(
                my_private_key,
                &UnparsedPublicKey::new(alg, test_key),
                (),
                |_| Ok(())
            )
            .is_err());
        }

        let alg_variants: [&'static Algorithm; 4] = [&X25519, &ECDH_P256, &ECDH_P384, &ECDH_P521];

        for alg in alg_variants {
            let my_private_key = PrivateKey::generate(alg).unwrap();

            let empty_key = [];
            test_with_key(alg, &my_private_key, &empty_key);

            let wrong_size_key: [u8; 31] = [
                0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22,
                23, 24, 25, 26, 27, 28, 29, 30,
            ];
            test_with_key(alg, &my_private_key, &wrong_size_key);
        }
    }

    #[test]
    fn test_agreement_ecdh_p256() {
        let alg = &ECDH_P256;
        let peer_public = UnparsedPublicKey::new(
            alg,
            test::from_dirty_hex(
                "04D12DFB5289C8D4F81208B70270398C342296970A0BCCB74C736FC7554494BF6356FBF3CA366CC23E8157854C13C58D6AAC23F046ADA30F8353E74F33039872AB",
            ),
        );
        assert_eq!(peer_public.algorithm(), alg);
        assert_eq!(peer_public.bytes(), &peer_public.bytes);

        let my_private = test::from_dirty_hex(
            "C88F01F510D9AC3F70A292DAA2316DE544E9AAB8AFE84049C62A9C57862D1433",
        );

        let my_private = {
            let rng = test::rand::FixedSliceRandom { bytes: &my_private };
            PrivateKey::generate_for_test(alg, &rng).unwrap()
        };

        let my_public = test::from_dirty_hex(
            "04DAD0B65394221CF9B051E1FECA5787D098DFE637FC90B9EF945D0C37725811805271A0461CDB8252D61F1C456FA3E59AB1F45B33ACCF5F58389E0577B8990BB3",
        );
        let output = test::from_dirty_hex(
            "D6840F6B42F6EDAFD13116E0E12565202FEF8E9ECE7DCE03812464D04B9442DE",
        );

        assert_eq!(my_private.algorithm(), alg);

        let be_private_key_buffer: EcPrivateKeyBin = my_private.as_be_bytes().unwrap();
        let be_private_key =
            PrivateKey::from_private_key(&ECDH_P256, be_private_key_buffer.as_ref()).unwrap();
        {
            let result = agree(&be_private_key, &peer_public, (), |key_material| {
                assert_eq!(key_material, &output[..]);
                Ok(())
            });
            assert_eq!(result, Ok(()));
        }

        let der_private_key_buffer: EcPrivateKeyRfc5915Der = my_private.as_der().unwrap();
        let der_private_key =
            PrivateKey::from_private_key_der(&ECDH_P256, der_private_key_buffer.as_ref()).unwrap();
        {
            let result = agree(&der_private_key, &peer_public, (), |key_material| {
                assert_eq!(key_material, &output[..]);
                Ok(())
            });
            assert_eq!(result, Ok(()));
        }

        let computed_public = my_private.compute_public_key().unwrap();
        assert_eq!(computed_public.as_ref(), &my_public[..]);

        assert_eq!(computed_public.algorithm(), alg);

        {
            let result = agree(&my_private, &peer_public, (), |key_material| {
                assert_eq!(key_material, &output[..]);
                Ok(())
            });
            assert_eq!(result, Ok(()));
        }

        {
            let result = agree(&my_private, &peer_public, (), |key_material| {
                assert_eq!(key_material, &output[..]);
                Ok(())
            });
            assert_eq!(result, Ok(()));
        }
    }

    #[test]
    fn test_agreement_ecdh_p384() {
        let alg = &ECDH_P384;
        let peer_public = UnparsedPublicKey::new(
            alg,
            test::from_dirty_hex(
                "04E558DBEF53EECDE3D3FCCFC1AEA08A89A987475D12FD950D83CFA41732BC509D0D1AC43A0336DEF96FDA41D0774A3571DCFBEC7AACF3196472169E838430367F66EEBE3C6E70C416DD5F0C68759DD1FFF83FA40142209DFF5EAAD96DB9E6386C",
            ),
        );

        let my_private = test::from_dirty_hex(
            "099F3C7034D4A2C699884D73A375A67F7624EF7C6B3C0F160647B67414DCE655E35B538041E649EE3FAEF896783AB194",
        );

        let my_private = {
            let rng = test::rand::FixedSliceRandom { bytes: &my_private };
            PrivateKey::generate_for_test(alg, &rng).unwrap()
        };

        let my_public = test::from_dirty_hex(
            "04667842D7D180AC2CDE6F74F37551F55755C7645C20EF73E31634FE72B4C55EE6DE3AC808ACB4BDB4C88732AEE95F41AA9482ED1FC0EEB9CAFC4984625CCFC23F65032149E0E144ADA024181535A0F38EEB9FCFF3C2C947DAE69B4C634573A81C",
        );
        let output = test::from_dirty_hex(
            "11187331C279962D93D604243FD592CB9D0A926F422E47187521287E7156C5C4D603135569B9E9D09CF5D4A270F59746",
        );

        assert_eq!(my_private.algorithm(), alg);

        let be_private_key_buffer: EcPrivateKeyBin = my_private.as_be_bytes().unwrap();
        let be_private_key =
            PrivateKey::from_private_key(&ECDH_P384, be_private_key_buffer.as_ref()).unwrap();
        {
            let result = agree(&be_private_key, &peer_public, (), |key_material| {
                assert_eq!(key_material, &output[..]);
                Ok(())
            });
            assert_eq!(result, Ok(()));
        }

        let der_private_key_buffer: EcPrivateKeyRfc5915Der = my_private.as_der().unwrap();
        let der_private_key =
            PrivateKey::from_private_key_der(&ECDH_P384, der_private_key_buffer.as_ref()).unwrap();
        {
            let result = agree(&der_private_key, &peer_public, (), |key_material| {
                assert_eq!(key_material, &output[..]);
                Ok(())
            });
            assert_eq!(result, Ok(()));
        }

        let computed_public = my_private.compute_public_key().unwrap();
        assert_eq!(computed_public.as_ref(), &my_public[..]);

        assert_eq!(computed_public.algorithm(), alg);

        {
            let result = agree(&my_private, &peer_public, (), |key_material| {
                assert_eq!(key_material, &output[..]);
                Ok(())
            });
            assert_eq!(result, Ok(()));
        }
    }

    #[test]
    fn test_agreement_ecdh_p521() {
        let alg = &ECDH_P521;
        let peer_public = UnparsedPublicKey::new(
            alg,
            test::from_dirty_hex(
                "0401a32099b02c0bd85371f60b0dd20890e6c7af048c8179890fda308b359dbbc2b7a832bb8c6526c4af99a7ea3f0b3cb96ae1eb7684132795c478ad6f962e4a6f446d017627357b39e9d7632a1370b3e93c1afb5c851b910eb4ead0c9d387df67cde85003e0e427552f1cd09059aad0262e235cce5fba8cedc4fdc1463da76dcd4b6d1a46",
            ),
        );

        let my_private = test::from_dirty_hex(
            "00df14b1f1432a7b0fb053965fd8643afee26b2451ecb6a8a53a655d5fbe16e4c64ce8647225eb11e7fdcb23627471dffc5c2523bd2ae89957cba3a57a23933e5a78",
        );

        let my_private = {
            let rng = test::rand::FixedSliceRandom { bytes: &my_private };
            PrivateKey::generate_for_test(alg, &rng).unwrap()
        };

        let my_public = test::from_dirty_hex(
            "04004e8583bbbb2ecd93f0714c332dff5ab3bc6396e62f3c560229664329baa5138c3bb1c36428abd4e23d17fcb7a2cfcc224b2e734c8941f6f121722d7b6b9415457601cf0874f204b0363f020864672fadbf87c8811eb147758b254b74b14fae742159f0f671a018212bbf25b8519e126d4cad778cfff50d288fd39ceb0cac635b175ec0",
        );
        let output = test::from_dirty_hex(
            "01aaf24e5d47e4080c18c55ea35581cd8da30f1a079565045d2008d51b12d0abb4411cda7a0785b15d149ed301a3697062f42da237aa7f07e0af3fd00eb1800d9c41",
        );

        assert_eq!(my_private.algorithm(), alg);

        let be_private_key_buffer: EcPrivateKeyBin = my_private.as_be_bytes().unwrap();
        let be_private_key =
            PrivateKey::from_private_key(&ECDH_P521, be_private_key_buffer.as_ref()).unwrap();
        {
            let result = agree(&be_private_key, &peer_public, (), |key_material| {
                assert_eq!(key_material, &output[..]);
                Ok(())
            });
            assert_eq!(result, Ok(()));
        }

        let der_private_key_buffer: EcPrivateKeyRfc5915Der = my_private.as_der().unwrap();
        let der_private_key =
            PrivateKey::from_private_key_der(&ECDH_P521, der_private_key_buffer.as_ref()).unwrap();
        {
            let result = agree(&der_private_key, &peer_public, (), |key_material| {
                assert_eq!(key_material, &output[..]);
                Ok(())
            });
            assert_eq!(result, Ok(()));
        }

        let computed_public = my_private.compute_public_key().unwrap();
        assert_eq!(computed_public.as_ref(), &my_public[..]);

        assert_eq!(computed_public.algorithm(), alg);
        {
            let result = agree(&my_private, &peer_public, (), |key_material| {
                assert_eq!(key_material, &output[..]);
                Ok(())
            });
            assert_eq!(result, Ok(()));
        }
        {
            let result = agree(&my_private, &peer_public, (), |key_material| {
                assert_eq!(key_material, &output[..]);
                Ok(())
            });
            assert_eq!(result, Ok(()));
        }
    }

    #[test]
    fn agreement_traits() {
        use crate::test;
        use regex::{self, Regex};

        let rng = rand::SystemRandom::new();
        let private_key = PrivateKey::generate_for_test(&ECDH_P256, &rng).unwrap();

        test::compile_time_assert_send::<PrivateKey>();
        test::compile_time_assert_sync::<PrivateKey>();

        assert_eq!(
            format!("{:?}", &private_key),
            "PrivateKey { algorithm: Algorithm { curve: P256 } }"
        );

        let ephemeral_private_key = PrivateKey::generate_for_test(&ECDH_P256, &rng).unwrap();

        test::compile_time_assert_send::<PrivateKey>();
        test::compile_time_assert_sync::<PrivateKey>();

        assert_eq!(
            format!("{:?}", &ephemeral_private_key),
            "PrivateKey { algorithm: Algorithm { curve: P256 } }"
        );

        let public_key = private_key.compute_public_key().unwrap();
        let pubkey_re = Regex::new(
            "PublicKey \\{ algorithm: Algorithm \\{ curve: P256 \\}, bytes: \"[0-9a-f]+\" \\}",
        )
        .unwrap();
        let pubkey_debug = format!("{:?}", &public_key);

        assert!(
            pubkey_re.is_match(&pubkey_debug),
            "pubkey_debug: {pubkey_debug}"
        );

        #[allow(clippy::redundant_clone)]
        let pubkey_clone = public_key.clone();
        assert_eq!(public_key.as_ref(), pubkey_clone.as_ref());
        assert_eq!(pubkey_debug, format!("{:?}", &pubkey_clone));

        test::compile_time_assert_clone::<PublicKey>();
        test::compile_time_assert_send::<PublicKey>();
        test::compile_time_assert_sync::<PublicKey>();

        // Verify `PublicKey` implements `Debug`.
        //
        // TODO: Test the actual output.
        let _: &dyn core::fmt::Debug = &public_key;

        test::compile_time_assert_clone::<UnparsedPublicKey<&[u8]>>();
        test::compile_time_assert_copy::<UnparsedPublicKey<&[u8]>>();
        test::compile_time_assert_sync::<UnparsedPublicKey<&[u8]>>();

        test::compile_time_assert_clone::<UnparsedPublicKey<Vec<u8>>>();
        test::compile_time_assert_sync::<UnparsedPublicKey<Vec<u8>>>();

        let bytes = [0x01, 0x02, 0x03];

        let unparsed_public_key = UnparsedPublicKey::new(&X25519, &bytes);
        let unparsed_pubkey_clone = unparsed_public_key;
        assert_eq!(
            format!("{unparsed_public_key:?}"),
            r#"UnparsedPublicKey { algorithm: Algorithm { curve: Curve25519 }, bytes: "010203" }"#
        );
        assert_eq!(
            format!("{unparsed_pubkey_clone:?}"),
            r#"UnparsedPublicKey { algorithm: Algorithm { curve: Curve25519 }, bytes: "010203" }"#
        );

        let unparsed_public_key = UnparsedPublicKey::new(&X25519, Vec::from(bytes));
        #[allow(clippy::redundant_clone)]
        let unparsed_pubkey_clone = unparsed_public_key.clone();
        assert_eq!(
            format!("{unparsed_public_key:?}"),
            r#"UnparsedPublicKey { algorithm: Algorithm { curve: Curve25519 }, bytes: "010203" }"#
        );
        assert_eq!(
            format!("{unparsed_pubkey_clone:?}"),
            r#"UnparsedPublicKey { algorithm: Algorithm { curve: Curve25519 }, bytes: "010203" }"#
        );
    }

    #[test]
    fn test_agreement_random() {
        let test_algorithms = [&ECDH_P256, &ECDH_P384, &ECDH_P521, &X25519];

        for alg in test_algorithms {
            test_agreement_random_helper(alg);
        }
    }

    fn test_agreement_random_helper(alg: &'static Algorithm) {
        let peer_private = PrivateKey::generate(alg).unwrap();
        let my_private = PrivateKey::generate(alg).unwrap();

        let peer_public_keys =
            public_key_formats_helper(&peer_private.compute_public_key().unwrap());

        let my_public_keys = public_key_formats_helper(&my_private.compute_public_key().unwrap());

        let mut results: Vec<Vec<u8>> = Vec::new();

        for peer_public in peer_public_keys {
            let peer_public = UnparsedPublicKey::new(alg, peer_public);
            let result = agree(&my_private, &peer_public, (), |key_material| {
                results.push(key_material.to_vec());
                Ok(())
            });
            assert_eq!(result, Ok(()));
        }

        for my_public in my_public_keys {
            let my_public = UnparsedPublicKey::new(alg, my_public);
            let result = agree(&peer_private, &my_public, (), |key_material| {
                results.push(key_material.to_vec());
                Ok(())
            });
            assert_eq!(result, Ok(()));
        }

        let key_types_tested = match alg.id {
            crate::agreement::AlgorithmID::ECDH_P256
            | crate::agreement::AlgorithmID::ECDH_P384
            | crate::agreement::AlgorithmID::ECDH_P521 => 4,
            crate::agreement::AlgorithmID::X25519 => 2,
        };

        assert_eq!(results.len(), key_types_tested * 2); // Multiplied by two because we tested the other direction

        assert_eq!(results[0..key_types_tested], results[key_types_tested..]);
    }

    fn public_key_formats_helper(public_key: &PublicKey) -> Vec<Vec<u8>> {
        let verify_ec_raw_traits = matches!(
            public_key.algorithm().id,
            crate::agreement::AlgorithmID::ECDH_P256
                | crate::agreement::AlgorithmID::ECDH_P384
                | crate::agreement::AlgorithmID::ECDH_P521
        );

        let mut public_keys = Vec::<Vec<u8>>::new();
        public_keys.push(public_key.as_ref().into());

        if verify_ec_raw_traits {
            let raw = AsBigEndian::<EcPublicKeyCompressedBin>::as_be_bytes(public_key).unwrap();
            public_keys.push(raw.as_ref().into());
            let raw = AsBigEndian::<EcPublicKeyUncompressedBin>::as_be_bytes(public_key).unwrap();
            public_keys.push(raw.as_ref().into());
        }

        let peer_x509 = AsDer::<PublicKeyX509Der>::as_der(public_key).unwrap();
        public_keys.push(peer_x509.as_ref().into());

        public_keys
    }

    #[test]
    fn private_key_drop() {
        let private_key = PrivateKey::generate(&ECDH_P256).unwrap();
        let public_key = private_key.compute_public_key().unwrap();
        // PublicKey maintains a reference counted pointer to private keys EVP_PKEY so we test that with drop
        drop(private_key);
        let _ = AsBigEndian::<EcPublicKeyCompressedBin>::as_be_bytes(&public_key).unwrap();
        let _ = AsBigEndian::<EcPublicKeyUncompressedBin>::as_be_bytes(&public_key).unwrap();
        let _ = AsDer::<PublicKeyX509Der>::as_der(&public_key).unwrap();
    }
}
