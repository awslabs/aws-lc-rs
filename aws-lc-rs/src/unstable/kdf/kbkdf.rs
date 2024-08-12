// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

#![allow(clippy::module_name_repetitions)]

#[cfg(not(feature = "fips"))]
use aws_lc::KBKDF_ctr_hmac;

use aws_lc::EVP_MD;
#[cfg(feature = "fips")]
use stubs::KBKDF_ctr_hmac;

#[cfg(feature = "fips")]
mod stubs {
    #[allow(non_snake_case)]
    pub(super) unsafe fn KBKDF_ctr_hmac(
        _out_key: *mut u8,
        _out_len: usize,
        _digest: *const aws_lc::EVP_MD,
        _secret: *const u8,
        _secret_len: usize,
        _info: *const u8,
        _info_len: usize,
    ) -> std::os::raw::c_int {
        0
    }
}

use crate::{
    digest::{match_digest_type, AlgorithmID},
    error::Unspecified,
    ptr::ConstPointer,
};

/// KBKDF in Counter Mode with HMAC-SHA224
#[allow(dead_code)]
const KBKDF_CTR_HMAC_SHA224: KbkdfCtrHmacAlgorithm = KbkdfCtrHmacAlgorithm {
    id: KbkdfCtrHmacAlgorithmId::Sha224,
};

/// KBKDF in Counter Mode with HMAC-SHA256
#[allow(dead_code)]
const KBKDF_CTR_HMAC_SHA256: KbkdfCtrHmacAlgorithm = KbkdfCtrHmacAlgorithm {
    id: KbkdfCtrHmacAlgorithmId::Sha256,
};

/// KBKDF in Counter Mode with HMAC-SHA384
#[allow(dead_code)]
const KBKDF_CTR_HMAC_SHA384: KbkdfCtrHmacAlgorithm = KbkdfCtrHmacAlgorithm {
    id: KbkdfCtrHmacAlgorithmId::Sha384,
};

/// KBKDF in Counter Mode with HMAC-SHA512
#[allow(dead_code)]
const KBKDF_CTR_HMAC_SHA512: KbkdfCtrHmacAlgorithm = KbkdfCtrHmacAlgorithm {
    id: KbkdfCtrHmacAlgorithmId::Sha512,
};

/// Retrieve an unstable [`KbkdfCtrHmacAlgorithm`] using the [`KbkdfAlgorithmId`] specified by `id`.
/// May return [`None`] if the algorithm is not usable with the configured crate feature set (i.e. `fips`).
#[must_use]
pub const fn get_kbkdf_ctr_hmac_algorithm(
    id: KbkdfCtrHmacAlgorithmId,
) -> Option<&'static KbkdfCtrHmacAlgorithm> {
    #[cfg(feature = "fips")]
    {
        let _ = id;
        None
    }
    #[cfg(not(feature = "fips"))]
    {
        Some(match id {
            KbkdfCtrHmacAlgorithmId::Sha224 => &KBKDF_CTR_HMAC_SHA224,
            KbkdfCtrHmacAlgorithmId::Sha256 => &KBKDF_CTR_HMAC_SHA256,
            KbkdfCtrHmacAlgorithmId::Sha384 => &KBKDF_CTR_HMAC_SHA384,
            KbkdfCtrHmacAlgorithmId::Sha512 => &KBKDF_CTR_HMAC_SHA512,
        })
    }
}

/// KBKDF in Counter Mode with HMAC Algorithm
pub struct KbkdfCtrHmacAlgorithm {
    id: KbkdfCtrHmacAlgorithmId,
}

impl KbkdfCtrHmacAlgorithm {
    /// Returns the KBKDF Counter HMAC Algorithm Identifier
    #[must_use]
    pub fn id(&self) -> KbkdfCtrHmacAlgorithmId {
        self.id
    }

    #[must_use]
    fn get_evp_md(&self) -> ConstPointer<EVP_MD> {
        match_digest_type(match self.id {
            KbkdfCtrHmacAlgorithmId::Sha224 => &AlgorithmID::SHA224,
            KbkdfCtrHmacAlgorithmId::Sha256 => &AlgorithmID::SHA256,
            KbkdfCtrHmacAlgorithmId::Sha384 => &AlgorithmID::SHA384,
            KbkdfCtrHmacAlgorithmId::Sha512 => &AlgorithmID::SHA512,
        })
    }
}

impl PartialEq for KbkdfCtrHmacAlgorithm {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

impl Eq for KbkdfCtrHmacAlgorithm {}

impl core::fmt::Debug for KbkdfCtrHmacAlgorithm {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        core::fmt::Debug::fmt(&self.id, f)
    }
}

/// Key-based Derivation Function Algorithm Identifier
#[non_exhaustive]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum KbkdfCtrHmacAlgorithmId {
    /// KBKDF in Counter Mode with HMAC-SHA224
    Sha224,

    /// KBKDF in Counter Mode with HMAC-SHA256
    Sha256,

    /// KBKDF in Counter Mode with HMAC-SHA384
    Sha384,

    /// KBKDF in Counter Mode with HMAC-SHA512
    Sha512,
}

/// # Key-based Key Derivation Function (KBKDF) in Counter Mode with HMAC PRF
///
/// ## Implementation Notes
///
/// This implementation adheres to the algorithm specified in Section 4.1 of the
/// NIST Special Publication 800-108 Revision 1 Update 1 published on August
/// 2022. The parameters relevant to the specification are as follows:
/// * `output.len() * 8` is analogous to `L` in the specification.
/// * `r` the length of the binary representation of the counter `i`
///   referred to by the specification. `r` is 32 bits in this implementation.
/// * `K_IN` is analogous to `secret`.
/// * The iteration counter `i` is place before the fixed info.
/// * `PRF` refers to HMAC in this implementation.
///
/// Specification available at <https://doi.org/10.6028/NIST.SP.800-108r1-upd1>
///
/// # Errors
/// `Unspecified` is returned if an error has occurred. This can occur due to the following reasons:
/// * `secret.len() == 0 || output.len() == 0`
/// * `output.len() > usize::MAX - DIGEST_LENGTH`
/// * The requested `output.len()` exceeds the `u32::MAX` counter `i`.
pub fn kbkdf_ctr_hmac(
    algorithm: &'static KbkdfCtrHmacAlgorithm,
    secret: &[u8],
    info: &[u8],
    output: &mut [u8],
) -> Result<(), Unspecified> {
    let evp_md = algorithm.get_evp_md();
    let out_len = output.len();
    if 1 != unsafe {
        KBKDF_ctr_hmac(
            output.as_mut_ptr(),
            out_len,
            *evp_md,
            secret.as_ptr(),
            secret.len(),
            info.as_ptr(),
            info.len(),
        )
    } {
        return Err(Unspecified);
    }
    Ok(())
}
