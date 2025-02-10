// Copyright 2015-2016 Brian Smith.
// SPDX-License-Identifier: ISC
// Modifications copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC
use super::signature::{RsaEncoding, RsaPadding};
use super::{encoding, RsaParameters};
#[cfg(feature = "fips")]
use crate::aws_lc::RSA;
use crate::aws_lc::{
    EVP_PKEY_CTX_set_rsa_keygen_bits, EVP_PKEY_assign_RSA, EVP_PKEY_new, RSA_new, RSA_set0_key,
    RSA_size, EVP_PKEY, EVP_PKEY_RSA, EVP_PKEY_RSA_PSS,
};
#[cfg(feature = "ring-io")]
use crate::aws_lc::{RSA_get0_e, RSA_get0_n};
use crate::encoding::{AsDer, Pkcs8V1Der};
use crate::error::{KeyRejected, Unspecified};
#[cfg(feature = "ring-io")]
use crate::io;
use crate::ptr::{DetachableLcPtr, LcPtr};
use crate::rsa::PublicEncryptingKey;
use crate::sealed::Sealed;
use crate::{hex, rand};
#[cfg(feature = "fips")]
use aws_lc::RSA_check_fips;
use core::fmt::{self, Debug, Formatter};
use core::ptr::null_mut;

// TODO: Uncomment when MSRV >= 1.64
// use core::ffi::c_int;
use std::os::raw::c_int;

use crate::pkcs8::Version;
use crate::rsa::signature::configure_rsa_pkcs1_pss_padding;
#[cfg(feature = "ring-io")]
use untrusted::Input;
use zeroize::Zeroize;

/// RSA key-size.
#[allow(clippy::module_name_repetitions)]
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeySize {
    /// 2048-bit key
    Rsa2048,

    /// 3072-bit key
    Rsa3072,

    /// 4096-bit key
    Rsa4096,

    /// 8192-bit key
    Rsa8192,
}

#[allow(clippy::len_without_is_empty)]
impl KeySize {
    /// Returns the size of the key in bytes.
    #[inline]
    #[must_use]
    pub fn len(self) -> usize {
        match self {
            Self::Rsa2048 => 256,
            Self::Rsa3072 => 384,
            Self::Rsa4096 => 512,
            Self::Rsa8192 => 1024,
        }
    }

    /// Returns the key size in bits.
    #[inline]
    pub(super) fn bits(self) -> i32 {
        match self {
            Self::Rsa2048 => 2048,
            Self::Rsa3072 => 3072,
            Self::Rsa4096 => 4096,
            Self::Rsa8192 => 8192,
        }
    }
}

/// An RSA key pair, used for signing.
#[allow(clippy::module_name_repetitions)]
pub struct KeyPair {
    // https://github.com/aws/aws-lc/blob/ebaa07a207fee02bd68fe8d65f6b624afbf29394/include/openssl/evp.h#L295
    // An |EVP_PKEY| object represents a public or private RSA key. A given object may be
    // used concurrently on multiple threads by non-mutating functions, provided no
    // other thread is concurrently calling a mutating function. Unless otherwise
    // documented, functions which take a |const| pointer are non-mutating and
    // functions which take a non-|const| pointer are mutating.
    pub(super) evp_pkey: LcPtr<EVP_PKEY>,
    pub(super) serialized_public_key: PublicKey,
}

impl Sealed for KeyPair {}
unsafe impl Send for KeyPair {}
unsafe impl Sync for KeyPair {}

impl KeyPair {
    fn new(evp_pkey: LcPtr<EVP_PKEY>) -> Result<Self, KeyRejected> {
        KeyPair::validate_private_key(&evp_pkey)?;
        let serialized_public_key = PublicKey::new(&evp_pkey)?;
        Ok(KeyPair {
            evp_pkey,
            serialized_public_key,
        })
    }

    /// Generate a RSA `KeyPair` of the specified key-strength.
    ///
    /// Supports the following key sizes:
    /// * `KeySize::Rsa2048`
    /// * `KeySize::Rsa3072`
    /// * `KeySize::Rsa4096`
    /// * `KeySize::Rsa8192`
    ///
    /// # Errors
    /// * `Unspecified`: Any key generation failure.
    pub fn generate(size: KeySize) -> Result<Self, Unspecified> {
        let private_key = generate_rsa_key(size.bits())?;
        Ok(Self::new(private_key)?)
    }

    /// Generate a RSA `KeyPair` of the specified key-strength.
    ///
    /// ## Deprecated
    /// This is equivalent to `KeyPair::generate`.
    ///
    /// # Errors
    /// * `Unspecified`: Any key generation failure.
    #[cfg(feature = "fips")]
    #[deprecated]
    pub fn generate_fips(size: KeySize) -> Result<Self, Unspecified> {
        Self::generate(size)
    }

    /// Parses an unencrypted PKCS#8 DER encoded RSA private key.
    ///
    /// Keys can be generated using [`KeyPair::generate`].
    ///
    /// # *ring*-compatibility
    ///
    /// *aws-lc-rs* does not impose the same limitations that *ring* does for
    /// RSA keys. Thus signatures may be generated by keys that are not accepted
    /// by *ring*. In particular:
    /// * RSA private keys ranging between 2048-bit keys and 8192-bit keys are supported.
    /// * The public exponent does not have a required minimum size.
    ///
    /// # Errors
    /// `error::KeyRejected` if bytes do not encode an RSA private key or if the key is otherwise
    /// not acceptable.
    pub fn from_pkcs8(pkcs8: &[u8]) -> Result<Self, KeyRejected> {
        let key = LcPtr::<EVP_PKEY>::parse_rfc5208_private_key(pkcs8, EVP_PKEY_RSA)?;
        Self::new(key)
    }

    /// Parses a DER-encoded `RSAPrivateKey` structure (RFC 8017).
    ///
    /// # Errors
    /// `error:KeyRejected` on error.
    pub fn from_der(input: &[u8]) -> Result<Self, KeyRejected> {
        let key = encoding::rfc8017::decode_private_key_der(input)?;
        Self::new(key)
    }

    /// Returns a boolean indicator if this RSA key is an approved FIPS 140-3 key.
    #[cfg(feature = "fips")]
    #[must_use]
    pub fn is_valid_fips_key(&self) -> bool {
        is_valid_fips_key(&self.evp_pkey)
    }

    fn validate_private_key(key: &LcPtr<EVP_PKEY>) -> Result<(), KeyRejected> {
        if !is_rsa_key(key) {
            return Err(KeyRejected::unspecified());
        }
        match key.key_size_bits() {
            2048..=8192 => Ok(()),
            _ => Err(KeyRejected::unspecified()),
        }
    }

    /// Sign `msg`. `msg` is digested using the digest algorithm from
    /// `padding_alg` and the digest is then padded using the padding algorithm
    /// from `padding_alg`. The signature it written into `signature`;
    /// `signature`'s length must be exactly the length returned by
    /// `public_modulus_len()`.
    ///
    /// Many other crypto libraries have signing functions that takes a
    /// precomputed digest as input, instead of the message to digest. This
    /// function does *not* take a precomputed digest; instead, `sign`
    /// calculates the digest itself.
    ///
    /// # *ring* Compatibility
    /// Our implementation ignores the `SecureRandom` parameter.
    // # FIPS
    // The following conditions must be met:
    // * RSA Key Sizes: 2048, 3072, 4096
    // * Digest Algorithms: SHA256, SHA384, SHA512
    //
    /// # Errors
    /// `error::Unspecified` on error.
    /// With "fips" feature enabled, errors if digest length is greater than `u32::MAX`.
    pub fn sign(
        &self,
        padding_alg: &'static dyn RsaEncoding,
        _rng: &dyn rand::SecureRandom,
        msg: &[u8],
        signature: &mut [u8],
    ) -> Result<(), Unspecified> {
        let encoding = padding_alg.encoding();
        let padding_fn = if let RsaPadding::RSA_PKCS1_PSS_PADDING = encoding.padding() {
            Some(configure_rsa_pkcs1_pss_padding)
        } else {
            None
        };

        let sig_bytes = self
            .evp_pkey
            .sign(msg, Some(encoding.digest_algorithm()), padding_fn)?;

        signature.copy_from_slice(&sig_bytes);
        Ok(())
    }

    /// Returns the length in bytes of the key pair's public modulus.
    ///
    /// A signature has the same length as the public modulus.
    #[must_use]
    pub fn public_modulus_len(&self) -> usize {
        // This was already validated to be an RSA key so this can't fail
        match self.evp_pkey.get_rsa() {
            Ok(rsa) => {
                // https://github.com/awslabs/aws-lc/blob/main/include/openssl/rsa.h#L99
                unsafe { RSA_size(*rsa) as usize }
            }
            Err(_) => unreachable!(),
        }
    }
}

impl Debug for KeyPair {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), fmt::Error> {
        f.write_str(&format!(
            "RsaKeyPair {{ public_key: {:?} }}",
            self.serialized_public_key
        ))
    }
}

impl crate::signature::KeyPair for KeyPair {
    type PublicKey = PublicKey;

    fn public_key(&self) -> &Self::PublicKey {
        &self.serialized_public_key
    }
}

impl AsDer<Pkcs8V1Der<'static>> for KeyPair {
    fn as_der(&self) -> Result<Pkcs8V1Der<'static>, Unspecified> {
        Ok(Pkcs8V1Der::new(
            self.evp_pkey.marshal_rfc5208_private_key(Version::V1)?,
        ))
    }
}

/// A serialized RSA public key.
#[derive(Clone)]
#[allow(clippy::module_name_repetitions)]
pub struct PublicKey {
    key: Box<[u8]>,
    #[cfg(feature = "ring-io")]
    modulus: Box<[u8]>,
    #[cfg(feature = "ring-io")]
    exponent: Box<[u8]>,
}

impl Drop for PublicKey {
    fn drop(&mut self) {
        self.key.zeroize();
        #[cfg(feature = "ring-io")]
        self.modulus.zeroize();
        #[cfg(feature = "ring-io")]
        self.exponent.zeroize();
    }
}

impl PublicKey {
    pub(super) fn new(evp_pkey: &LcPtr<EVP_PKEY>) -> Result<Self, Unspecified> {
        let key = encoding::rfc8017::encode_public_key_der(evp_pkey)?;
        #[cfg(feature = "ring-io")]
        {
            let pubkey = evp_pkey.get_rsa()?;
            let modulus =
                pubkey.project_const_lifetime(unsafe { |pubkey| RSA_get0_n(**pubkey) })?;
            let modulus = modulus.to_be_bytes().into_boxed_slice();
            let exponent =
                pubkey.project_const_lifetime(unsafe { |pubkey| RSA_get0_e(**pubkey) })?;
            let exponent = exponent.to_be_bytes().into_boxed_slice();
            Ok(PublicKey {
                key,
                modulus,
                exponent,
            })
        }

        #[cfg(not(feature = "ring-io"))]
        Ok(PublicKey { key })
    }
}

impl Debug for PublicKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), fmt::Error> {
        f.write_str(&format!(
            "RsaPublicKey(\"{}\")",
            hex::encode(self.key.as_ref())
        ))
    }
}

impl AsRef<[u8]> for PublicKey {
    /// DER encode a RSA public key to (RFC 8017) `RSAPublicKey` structure.
    fn as_ref(&self) -> &[u8] {
        self.key.as_ref()
    }
}

#[cfg(feature = "ring-io")]
impl PublicKey {
    /// The public modulus (n).
    #[must_use]
    pub fn modulus(&self) -> io::Positive<'_> {
        io::Positive::new_non_empty_without_leading_zeros(Input::from(self.modulus.as_ref()))
    }

    /// The public exponent (e).
    #[must_use]
    pub fn exponent(&self) -> io::Positive<'_> {
        io::Positive::new_non_empty_without_leading_zeros(Input::from(self.exponent.as_ref()))
    }
}

/// Low-level API for RSA public keys.
///
/// When the public key is in DER-encoded PKCS#1 ASN.1 format, it is
/// recommended to use `aws_lc_rs::signature::verify()` with
/// `aws_lc_rs::signature::RSA_PKCS1_*`, because `aws_lc_rs::signature::verify()`
/// will handle the parsing in that case. Otherwise, this function can be used
/// to pass in the raw bytes for the public key components as
/// `untrusted::Input` arguments.
#[allow(clippy::module_name_repetitions)]
#[derive(Clone)]
pub struct PublicKeyComponents<B>
where
    B: AsRef<[u8]> + Debug,
{
    /// The public modulus, encoded in big-endian bytes without leading zeros.
    pub n: B,
    /// The public exponent, encoded in big-endian bytes without leading zeros.
    pub e: B,
}

impl<B: AsRef<[u8]> + Debug> Debug for PublicKeyComponents<B> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("RsaPublicKeyComponents")
            .field("n", &self.n)
            .field("e", &self.e)
            .finish()
    }
}

impl<B: Copy + AsRef<[u8]> + Debug> Copy for PublicKeyComponents<B> {}

impl<B> PublicKeyComponents<B>
where
    B: AsRef<[u8]> + Debug,
{
    #[inline]
    fn build_rsa(&self) -> Result<LcPtr<EVP_PKEY>, ()> {
        let n_bytes = self.n.as_ref();
        if n_bytes.is_empty() || n_bytes[0] == 0u8 {
            return Err(());
        }
        let n_bn = DetachableLcPtr::try_from(n_bytes)?;

        let e_bytes = self.e.as_ref();
        if e_bytes.is_empty() || e_bytes[0] == 0u8 {
            return Err(());
        }
        let e_bn = DetachableLcPtr::try_from(e_bytes)?;

        let rsa = DetachableLcPtr::new(unsafe { RSA_new() })?;
        if 1 != unsafe { RSA_set0_key(*rsa, *n_bn, *e_bn, null_mut()) } {
            return Err(());
        }
        n_bn.detach();
        e_bn.detach();

        let mut pkey = LcPtr::new(unsafe { EVP_PKEY_new() })?;
        if 1 != unsafe { EVP_PKEY_assign_RSA(*pkey.as_mut(), *rsa) } {
            return Err(());
        }
        rsa.detach();

        Ok(pkey)
    }

    /// Verifies that `signature` is a valid signature of `message` using `self`
    /// as the public key. `params` determine what algorithm parameters
    /// (padding, digest algorithm, key length range, etc.) are used in the
    /// verification.
    ///
    /// # Errors
    /// `error::Unspecified` if `message` was not verified.
    pub fn verify(
        &self,
        params: &RsaParameters,
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), Unspecified> {
        let rsa = self.build_rsa()?;
        super::signature::verify_rsa_signature(
            params.digest_algorithm(),
            params.padding(),
            &rsa,
            message,
            signature,
            params.bit_size_range(),
        )
    }
}

impl<B> TryInto<PublicEncryptingKey> for PublicKeyComponents<B>
where
    B: AsRef<[u8]> + Debug,
{
    type Error = Unspecified;

    /// Try to build a `PublicEncryptingKey` from the public key components.
    ///
    /// # Errors
    /// `error::Unspecified` if the key failed to verify.
    fn try_into(self) -> Result<PublicEncryptingKey, Self::Error> {
        let rsa = self.build_rsa()?;
        PublicEncryptingKey::new(rsa)
    }
}

pub(super) fn generate_rsa_key(size: c_int) -> Result<LcPtr<EVP_PKEY>, Unspecified> {
    let params_fn = |ctx| {
        if 1 == unsafe { EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, size) } {
            Ok(())
        } else {
            Err(())
        }
    };

    LcPtr::<EVP_PKEY>::generate(EVP_PKEY_RSA, Some(params_fn))
}

#[cfg(feature = "fips")]
#[must_use]
pub(super) fn is_valid_fips_key(key: &LcPtr<EVP_PKEY>) -> bool {
    // This should always be an RSA key and must-never panic.
    let rsa_key = key.get_rsa().expect("RSA EVP_PKEY");

    1 == unsafe { RSA_check_fips(*rsa_key as *mut RSA) }
}

pub(super) fn is_rsa_key(key: &LcPtr<EVP_PKEY>) -> bool {
    let id = key.id();
    id == EVP_PKEY_RSA || id == EVP_PKEY_RSA_PSS
}
