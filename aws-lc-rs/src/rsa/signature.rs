// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

use std::fmt::{self, Debug, Formatter};
use std::mem::MaybeUninit;
use std::ops::RangeInclusive;
use std::ptr::{null, null_mut};

use crate::aws_lc::{
    EVP_DigestSign, EVP_DigestVerify, EVP_DigestVerifyInit, EVP_PKEY_CTX_set_rsa_padding,
    EVP_PKEY_CTX_set_rsa_pss_saltlen, EVP_PKEY_get0_RSA, RSA_bits, RSA_get0_n, EVP_PKEY,
    EVP_PKEY_CTX, RSA_PKCS1_PSS_PADDING, RSA_PSS_SALTLEN_DIGEST,
};

use crate::digest::digest_ctx::DigestContext;
use crate::digest::{self};
use crate::error::Unspecified;
use crate::fips::indicator_check;
use crate::ptr::{ConstPointer, DetachableLcPtr, LcPtr};
use crate::sealed::Sealed;
use crate::signature::VerificationAlgorithm;

#[cfg(feature = "ring-sig-verify")]
use untrusted::Input;

use super::encoding;

#[allow(non_camel_case_types)]
#[allow(clippy::module_name_repetitions)]
#[derive(Debug)]
pub enum RsaPadding {
    RSA_PKCS1_PADDING,
    RSA_PKCS1_PSS_PADDING,
}

/// Parameters for RSA verification.
pub struct RsaParameters(
    &'static digest::Algorithm,
    &'static RsaPadding,
    RangeInclusive<u32>,
    &'static RsaVerificationAlgorithmId,
);

impl RsaParameters {
    #[inline]
    pub(crate) fn digest_algorithm(&self) -> &'static digest::Algorithm {
        self.0
    }

    #[inline]
    pub(crate) fn padding(&self) -> &'static RsaPadding {
        self.1
    }

    #[inline]
    pub(crate) fn bit_size_range(&self) -> &RangeInclusive<u32> {
        &self.2
    }
}

impl VerificationAlgorithm for RsaParameters {
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

    fn verify_sig(
        &self,
        public_key: &[u8],
        msg: &[u8],
        signature: &[u8],
    ) -> Result<(), Unspecified> {
        let evp_pkey = encoding::rfc8017::decode_public_key_der(public_key)?;
        verify_rsa_signature(
            self.digest_algorithm(),
            self.padding(),
            &evp_pkey,
            msg,
            signature,
            self.bit_size_range(),
        )
    }
}

impl Sealed for RsaParameters {}

impl Debug for RsaParameters {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(&format!("{{ {:?} }}", self.3))
    }
}

impl RsaParameters {
    pub(crate) const fn new(
        digest_alg: &'static digest::Algorithm,
        padding: &'static RsaPadding,
        range: RangeInclusive<u32>,
        verification_alg: &'static RsaVerificationAlgorithmId,
    ) -> Self {
        Self(digest_alg, padding, range, verification_alg)
    }

    /// Parses a DER-encoded `RSAPublicKey` structure (RFC 8017) to determine its size in bits.
    ///
    /// # Errors
    /// `error::Unspecified` on parse error.
    pub fn public_modulus_len(public_key: &[u8]) -> Result<u32, Unspecified> {
        let rsa = encoding::rfc8017::decode_public_key_der(public_key)?;
        Ok(unsafe { RSA_bits(*rsa.get_rsa()?) })
    }

    #[must_use]
    /// Minimum modulus length in bits.
    pub fn min_modulus_len(&self) -> u32 {
        *self.2.start()
    }

    #[must_use]
    /// Maximum modulus length in bits.
    pub fn max_modulus_len(&self) -> u32 {
        *self.2.end()
    }
}

#[derive(Debug)]
#[allow(non_camel_case_types)]
pub(crate) enum RsaVerificationAlgorithmId {
    RSA_PKCS1_1024_8192_SHA1_FOR_LEGACY_USE_ONLY,
    RSA_PKCS1_1024_8192_SHA256_FOR_LEGACY_USE_ONLY,
    RSA_PKCS1_1024_8192_SHA512_FOR_LEGACY_USE_ONLY,
    RSA_PKCS1_2048_8192_SHA1_FOR_LEGACY_USE_ONLY,
    RSA_PKCS1_2048_8192_SHA256,
    RSA_PKCS1_2048_8192_SHA384,
    RSA_PKCS1_2048_8192_SHA512,
    RSA_PKCS1_3072_8192_SHA384,
    RSA_PSS_2048_8192_SHA256,
    RSA_PSS_2048_8192_SHA384,
    RSA_PSS_2048_8192_SHA512,
}

#[derive(Debug)]
#[allow(non_camel_case_types)]
pub(crate) enum RsaSigningAlgorithmId {
    RSA_PSS_SHA256,
    RSA_PSS_SHA384,
    RSA_PSS_SHA512,
    RSA_PKCS1_SHA256,
    RSA_PKCS1_SHA384,
    RSA_PKCS1_SHA512,
}

#[allow(clippy::module_name_repetitions)]
pub struct RsaSignatureEncoding(
    &'static digest::Algorithm,
    &'static RsaPadding,
    &'static RsaSigningAlgorithmId,
);

impl RsaSignatureEncoding {
    pub(crate) const fn new(
        digest_alg: &'static digest::Algorithm,
        padding: &'static RsaPadding,
        sig_alg: &'static RsaSigningAlgorithmId,
    ) -> Self {
        Self(digest_alg, padding, sig_alg)
    }

    #[inline]
    pub(super) fn digest_algorithm(&self) -> &'static digest::Algorithm {
        self.0
    }

    #[inline]
    pub(super) fn padding(&self) -> &'static RsaPadding {
        self.1
    }
}

impl Sealed for RsaSignatureEncoding {}

/// An RSA signature encoding as described in [RFC 3447 Section 8].
///
/// [RFC 3447 Section 8]: https://tools.ietf.org/html/rfc3447#section-8
#[allow(clippy::module_name_repetitions)]
pub trait RsaEncoding: 'static + Sync + Sealed + Debug {
    /// The signature encoding.
    fn encoding(&'static self) -> &'static RsaSignatureEncoding;
}

impl RsaEncoding for RsaSignatureEncoding {
    fn encoding(&'static self) -> &'static RsaSignatureEncoding {
        self
    }
}

impl Debug for RsaSignatureEncoding {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), fmt::Error> {
        f.write_str(&format!("{{ {:?} }}", self.2))
    }
}

#[inline]
pub(super) fn compute_rsa_signature<'a>(
    ctx: &mut DigestContext,
    message: &[u8],
    signature: &'a mut [u8],
) -> Result<&'a mut [u8], Unspecified> {
    let mut out_sig_len = signature.len();

    if 1 != indicator_check!(unsafe {
        EVP_DigestSign(
            ctx.as_mut_ptr(),
            signature.as_mut_ptr(),
            &mut out_sig_len,
            message.as_ptr(),
            message.len(),
        )
    }) {
        return Err(Unspecified);
    }

    Ok(&mut signature[0..out_sig_len])
}

#[inline]
pub(crate) fn configure_rsa_pkcs1_pss_padding(pctx: *mut EVP_PKEY_CTX) -> Result<(), ()> {
    if 1 != unsafe { EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING) } {
        return Err(());
    };
    if 1 != unsafe { EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, RSA_PSS_SALTLEN_DIGEST) } {
        return Err(());
    };
    Ok(())
}

#[inline]
pub(crate) fn verify_rsa_signature(
    algorithm: &'static digest::Algorithm,
    padding: &'static RsaPadding,
    public_key: &LcPtr<EVP_PKEY>,
    msg: &[u8],
    signature: &[u8],
    allowed_bit_size: &RangeInclusive<u32>,
) -> Result<(), Unspecified> {
    let rsa = ConstPointer::new(unsafe { EVP_PKEY_get0_RSA(*public_key.as_const()) })?;
    let n = ConstPointer::new(unsafe { RSA_get0_n(*rsa) })?;
    let n_bits = n.num_bits();
    if !allowed_bit_size.contains(&n_bits) {
        return Err(Unspecified);
    }

    let mut md_ctx = DigestContext::new_uninit();
    let digest = digest::match_digest_type(&algorithm.id);

    let mut pctx = null_mut::<EVP_PKEY_CTX>();

    if 1 != unsafe {
        // EVP_DigestVerifyInit does not mutate |pkey| for thread-safety purposes and may be
        // used concurrently with other non-mutating functions on |pkey|.
        // https://github.com/aws/aws-lc/blob/9b4b5a15a97618b5b826d742419ccd54c819fa42/include/openssl/evp.h#L353-L369
        EVP_DigestVerifyInit(
            md_ctx.as_mut_ptr(),
            &mut pctx,
            *digest,
            null_mut(),
            *public_key.as_mut_unsafe(),
        )
    } {
        return Err(Unspecified);
    }

    if let RsaPadding::RSA_PKCS1_PSS_PADDING = padding {
        // AWS-LC owns pctx, check for null and then immediately detach so we don't drop it.
        let pctx = DetachableLcPtr::new(pctx)?.detach();
        configure_rsa_pkcs1_pss_padding(pctx)?;
    }

    if 1 != indicator_check!(unsafe {
        EVP_DigestVerify(
            md_ctx.as_mut_ptr(),
            signature.as_ptr(),
            signature.len(),
            msg.as_ptr(),
            msg.len(),
        )
    }) {
        return Err(Unspecified);
    }

    Ok(())
}

#[inline]
pub(super) fn get_signature_length(ctx: &mut DigestContext) -> Result<usize, Unspecified> {
    let mut out_sig_len = MaybeUninit::<usize>::uninit();

    // determine signature size
    if 1 != unsafe {
        EVP_DigestSign(
            ctx.as_mut_ptr(),
            null_mut(),
            out_sig_len.as_mut_ptr(),
            null(),
            0,
        )
    } {
        return Err(Unspecified);
    }

    Ok(unsafe { out_sig_len.assume_init() })
}
