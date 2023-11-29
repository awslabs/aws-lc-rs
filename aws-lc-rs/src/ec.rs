// Copyright 2015-2016 Brian Smith.
// SPDX-License-Identifier: ISC
// Modifications copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

use crate::buffer::Buffer;
use crate::digest::digest_ctx::DigestContext;
use crate::error::{KeyRejected, Unspecified};
use core::fmt;

use crate::ptr::{ConstPointer, DetachableLcPtr, LcPtr, Pointer};

use crate::fips::indicator_check;
use crate::signature::{Signature, VerificationAlgorithm};
use crate::{digest, sealed, test};
#[cfg(feature = "fips")]
use aws_lc::EC_KEY_check_fips;
#[cfg(not(feature = "fips"))]
use aws_lc::EC_KEY_check_key;
use aws_lc::{
    point_conversion_form_t, BN_bn2bin_padded, BN_num_bytes, ECDSA_SIG_from_bytes,
    ECDSA_SIG_get0_r, ECDSA_SIG_get0_s, ECDSA_SIG_new, ECDSA_SIG_set0, ECDSA_SIG_to_bytes,
    EC_GROUP_get_curve_name, EC_GROUP_new_by_curve_name, EC_KEY_get0_group,
    EC_KEY_get0_private_key, EC_KEY_get0_public_key, EC_KEY_new, EC_KEY_set_group,
    EC_KEY_set_private_key, EC_KEY_set_public_key, EC_POINT_new, EC_POINT_oct2point,
    EC_POINT_point2oct, EVP_DigestVerify, EVP_DigestVerifyInit, EVP_PKEY_CTX_new_id,
    EVP_PKEY_CTX_set_ec_paramgen_curve_nid, EVP_PKEY_assign_EC_KEY, EVP_PKEY_get0_EC_KEY,
    EVP_PKEY_keygen, EVP_PKEY_keygen_init, EVP_PKEY_new, NID_X9_62_prime256v1, NID_secp256k1,
    NID_secp384r1, NID_secp521r1, BIGNUM, ECDSA_SIG, EC_GROUP, EC_POINT, EVP_PKEY, EVP_PKEY_EC,
};

#[cfg(test)]
use aws_lc::EC_POINT_mul;

use std::fmt::{Debug, Formatter};
use std::mem::MaybeUninit;
use std::ops::Deref;
use std::os::raw::{c_int, c_uint};
#[cfg(test)]
use std::ptr::null;
use std::ptr::null_mut;

#[cfg(feature = "ring-sig-verify")]
use untrusted::Input;

pub(crate) mod key_pair;

const ELEM_MAX_BITS: usize = 521;
pub(crate) const ELEM_MAX_BYTES: usize = (ELEM_MAX_BITS + 7) / 8;

pub(crate) const SCALAR_MAX_BYTES: usize = ELEM_MAX_BYTES;

/// The maximum length, in bytes, of an encoded public key.
pub(crate) const PUBLIC_KEY_MAX_LEN: usize = 1 + (2 * ELEM_MAX_BYTES);

/// The maximum length of a PKCS#8 documents generated by *aws-lc-rs* for ECC keys.
///
/// This is NOT the maximum length of a PKCS#8 document that can be consumed by
/// `pkcs8::unwrap_key()`.
///
/// `40` is the length of the P-384 template. It is actually one byte shorter
/// than the P-256 template, but the private key and the public key are much
/// longer.
/// `42` is the length of the P-521 template.
pub const PKCS8_DOCUMENT_MAX_LEN: usize = 42 + SCALAR_MAX_BYTES + PUBLIC_KEY_MAX_LEN;

/// An ECDSA verification algorithm.
#[derive(Debug, Eq, PartialEq)]
pub struct EcdsaVerificationAlgorithm {
    pub(super) id: &'static AlgorithmID,
    pub(super) digest: &'static digest::Algorithm,
    pub(super) bits: c_uint,
    pub(super) sig_format: EcdsaSignatureFormat,
}

/// An ECDSA signing algorithm.
#[derive(Debug, Eq, PartialEq)]
pub struct EcdsaSigningAlgorithm(pub(crate) &'static EcdsaVerificationAlgorithm);

impl Deref for EcdsaSigningAlgorithm {
    type Target = EcdsaVerificationAlgorithm;
    #[inline]
    fn deref(&self) -> &Self::Target {
        self.0
    }
}

impl sealed::Sealed for EcdsaVerificationAlgorithm {}
impl sealed::Sealed for EcdsaSigningAlgorithm {}

#[derive(Debug, Eq, PartialEq)]
pub(crate) enum EcdsaSignatureFormat {
    ASN1,
    Fixed,
}

#[derive(Debug, Eq, PartialEq)]
#[allow(non_camel_case_types)]
pub(crate) enum AlgorithmID {
    ECDSA_P256,
    ECDSA_P384,
    ECDSA_P521,
    ECDSA_P256K1,
}

impl AlgorithmID {
    #[inline]
    pub(crate) fn nid(&'static self) -> i32 {
        match self {
            AlgorithmID::ECDSA_P256 => NID_X9_62_prime256v1,
            AlgorithmID::ECDSA_P384 => NID_secp384r1,
            AlgorithmID::ECDSA_P521 => NID_secp521r1,
            AlgorithmID::ECDSA_P256K1 => NID_secp256k1,
        }
    }
}

/// Elliptic curve public key.
#[derive(Clone)]
pub struct PublicKey {
    algorithm: &'static EcdsaSigningAlgorithm,
    octets: Box<[u8]>,
}

#[allow(clippy::module_name_repetitions)]
pub struct EcPublicKeyX509DerType {
    _priv: (),
}
/// An elliptic curve public key as a DER-encoded (X509) `SubjectPublicKeyInfo` structure
#[allow(clippy::module_name_repetitions)]
pub type EcPublicKeyX509Der<'a> = Buffer<'a, EcPublicKeyX509DerType>;

impl PublicKey {
    /// Provides the public key as a DER-encoded (X.509) `SubjectPublicKeyInfo` structure.
    /// # Errors
    /// Returns an error if the underlying implementation is unable to marshal the point.
    pub fn as_der(&self) -> Result<EcPublicKeyX509Der<'_>, Unspecified> {
        let ec_group = unsafe { LcPtr::new(EC_GROUP_new_by_curve_name(self.algorithm.id.nid()))? };
        let ec_point = unsafe { ec_point_from_bytes(&ec_group, self.as_ref())? };
        let ec_key = unsafe { LcPtr::new(EC_KEY_new())? };
        if 1 != unsafe { EC_KEY_set_group(*ec_key, *ec_group) } {
            return Err(Unspecified);
        }
        if 1 != unsafe { EC_KEY_set_public_key(*ec_key, *ec_point) } {
            return Err(Unspecified);
        }
        let mut buffer = null_mut::<u8>();
        let len = unsafe { aws_lc::i2d_EC_PUBKEY(*ec_key, &mut buffer) };
        if len < 0 || buffer.is_null() {
            return Err(Unspecified);
        }
        let buffer = LcPtr::new(buffer)?;
        let mut der = unsafe { std::slice::from_raw_parts(*buffer, len.try_into()?) }.to_owned();

        Ok(Buffer::take_from_slice(&mut der))
    }
}

impl Debug for PublicKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), fmt::Error> {
        f.write_str(&format!(
            "EcdsaPublicKey(\"{}\")",
            test::to_hex(self.octets.as_ref())
        ))
    }
}

impl AsRef<[u8]> for PublicKey {
    #[inline]
    /// Serializes the public key in an uncompressed form (X9.62) using the
    /// Octet-String-to-Elliptic-Curve-Point algorithm in
    /// [SEC 1: Elliptic Curve Cryptography, Version 2.0].
    fn as_ref(&self) -> &[u8] {
        self.octets.as_ref()
    }
}

unsafe impl Send for PublicKey {}
unsafe impl Sync for PublicKey {}

impl VerificationAlgorithm for EcdsaVerificationAlgorithm {
    #[inline]
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
        match self.sig_format {
            EcdsaSignatureFormat::ASN1 => {
                verify_asn1_signature(self.id, self.digest, public_key, msg, signature)
            }
            EcdsaSignatureFormat::Fixed => {
                verify_fixed_signature(self.id, self.digest, public_key, msg, signature)
            }
        }
    }
}

fn verify_fixed_signature(
    alg: &'static AlgorithmID,
    digest: &'static digest::Algorithm,
    public_key: &[u8],
    msg: &[u8],
    signature: &[u8],
) -> Result<(), Unspecified> {
    let mut out_bytes = null_mut::<u8>();
    let mut out_bytes_len = MaybeUninit::<usize>::uninit();
    let sig = unsafe { ecdsa_sig_from_fixed(alg, signature)? };
    if 1 != unsafe {
        ECDSA_SIG_to_bytes(&mut out_bytes, out_bytes_len.as_mut_ptr(), *sig.as_const())
    } {
        return Err(Unspecified);
    }
    let out_bytes = LcPtr::new(out_bytes)?;
    let signature = unsafe { out_bytes.as_slice(out_bytes_len.assume_init()) };
    verify_asn1_signature(alg, digest, public_key, msg, signature)
}

fn verify_asn1_signature(
    alg: &'static AlgorithmID,
    digest: &'static digest::Algorithm,
    public_key: &[u8],
    msg: &[u8],
    signature: &[u8],
) -> Result<(), Unspecified> {
    let pkey = evp_pkey_from_public_key(alg, public_key)?;

    let mut md_ctx = DigestContext::new_uninit();

    let digest = digest::match_digest_type(&digest.id);

    if 1 != unsafe {
        EVP_DigestVerifyInit(md_ctx.as_mut_ptr(), null_mut(), *digest, null_mut(), *pkey)
    } {
        return Err(Unspecified);
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
fn evp_pkey_from_public_key(
    alg: &'static AlgorithmID,
    public_key: &[u8],
) -> Result<LcPtr<EVP_PKEY>, Unspecified> {
    let ec_group = unsafe { ec_group_from_nid(alg.nid())? };
    let ec_point = unsafe { ec_point_from_bytes(&ec_group, public_key)? };
    let pkey = unsafe { evp_pkey_from_public_point(&ec_group, &ec_point)? };

    Ok(pkey)
}

#[inline]
unsafe fn validate_evp_key(
    evp_pkey: &ConstPointer<EVP_PKEY>,
    expected_curve_nid: i32,
) -> Result<(), KeyRejected> {
    let ec_key = ConstPointer::new(EVP_PKEY_get0_EC_KEY(**evp_pkey))?;

    let ec_group = ConstPointer::new(EC_KEY_get0_group(*ec_key))?;
    let key_nid = EC_GROUP_get_curve_name(*ec_group);

    if key_nid != expected_curve_nid {
        return Err(KeyRejected::wrong_algorithm());
    }

    #[cfg(not(feature = "fips"))]
    if 1 != EC_KEY_check_key(*ec_key) {
        return Err(KeyRejected::inconsistent_components());
    }

    #[cfg(feature = "fips")]
    if 1 != indicator_check!(EC_KEY_check_fips(*ec_key)) {
        return Err(KeyRejected::inconsistent_components());
    }

    Ok(())
}

pub(crate) unsafe fn marshal_private_key_to_buffer(
    alg_id: &'static AlgorithmID,
    evp_pkey: &ConstPointer<EVP_PKEY>,
) -> Result<Vec<u8>, Unspecified> {
    let ec_key = ConstPointer::new(EVP_PKEY_get0_EC_KEY(**evp_pkey))?;
    let private_bn = ConstPointer::new(EC_KEY_get0_private_key(*ec_key))?;
    let private_size: usize = ecdsa_fixed_number_byte_size(alg_id);
    {
        let size: usize = BN_num_bytes(*private_bn).try_into()?;
        debug_assert!(size <= private_size);
    }

    let mut buffer = vec![0u8; SCALAR_MAX_BYTES];
    if 1 != BN_bn2bin_padded(buffer.as_mut_ptr(), private_size, *private_bn) {
        return Err(Unspecified);
    }
    buffer.truncate(private_size);

    Ok(buffer)
}

pub(crate) unsafe fn marshal_public_key_to_buffer(
    buffer: &mut [u8; PUBLIC_KEY_MAX_LEN],
    evp_pkey: &ConstPointer<EVP_PKEY>,
) -> Result<usize, Unspecified> {
    let ec_key = EVP_PKEY_get0_EC_KEY(**evp_pkey);
    if ec_key.is_null() {
        return Err(Unspecified);
    }

    let ec_group = ConstPointer::new(EC_KEY_get0_group(ec_key))?;

    let ec_point = ConstPointer::new(EC_KEY_get0_public_key(ec_key))?;

    let out_len = ec_point_to_bytes(&ec_group, &ec_point, buffer)?;
    Ok(out_len)
}

pub(crate) fn marshal_public_key(
    evp_pkey: &ConstPointer<EVP_PKEY>,
    algorithm: &'static EcdsaSigningAlgorithm,
) -> Result<PublicKey, Unspecified> {
    let mut pub_key_bytes = [0u8; PUBLIC_KEY_MAX_LEN];
    unsafe {
        let key_len = marshal_public_key_to_buffer(&mut pub_key_bytes, evp_pkey)?;

        Ok(PublicKey {
            algorithm,
            octets: pub_key_bytes[0..key_len].into(),
        })
    }
}

#[inline]
pub(crate) unsafe fn evp_pkey_from_public_point(
    ec_group: &LcPtr<EC_GROUP>,
    public_ec_point: &LcPtr<EC_POINT>,
) -> Result<LcPtr<EVP_PKEY>, Unspecified> {
    let nid = EC_GROUP_get_curve_name(ec_group.as_const_ptr());
    let ec_key = DetachableLcPtr::new(EC_KEY_new())?;
    if 1 != EC_KEY_set_group(*ec_key, **ec_group) {
        return Err(Unspecified);
    }
    if 1 != EC_KEY_set_public_key(*ec_key, **public_ec_point) {
        return Err(Unspecified);
    }

    let pkey = LcPtr::new(unsafe { EVP_PKEY_new() })?;

    if 1 != unsafe { EVP_PKEY_assign_EC_KEY(*pkey, *ec_key) } {
        return Err(Unspecified);
    }

    ec_key.detach();

    validate_evp_key(&pkey.as_const(), nid)?;

    Ok(pkey)
}

#[cfg(test)]
pub(crate) unsafe fn evp_pkey_from_private(
    ec_group: &ConstPointer<EC_GROUP>,
    private_big_num: &ConstPointer<BIGNUM>,
) -> Result<LcPtr<EVP_PKEY>, Unspecified> {
    let ec_key = DetachableLcPtr::new(EC_KEY_new())?;
    if 1 != EC_KEY_set_group(*ec_key, **ec_group) {
        return Err(Unspecified);
    }
    if 1 != EC_KEY_set_private_key(*ec_key, **private_big_num) {
        return Err(Unspecified);
    }
    let pub_key = LcPtr::new(EC_POINT_new(**ec_group))?;
    if 1 != EC_POINT_mul(
        **ec_group,
        *pub_key,
        **private_big_num,
        null(),
        null(),
        null_mut(),
    ) {
        return Err(Unspecified);
    }
    if 1 != EC_KEY_set_public_key(*ec_key, *pub_key) {
        return Err(Unspecified);
    }
    let expected_curve_nid = EC_GROUP_get_curve_name(**ec_group);

    let pkey = LcPtr::new(unsafe { EVP_PKEY_new() })?;

    if 1 != unsafe { EVP_PKEY_assign_EC_KEY(*pkey, *ec_key) } {
        return Err(Unspecified);
    }
    ec_key.detach();

    // Validate the EC_KEY before returning it.
    validate_evp_key(&pkey.as_const(), expected_curve_nid)?;

    Ok(pkey)
}

#[inline]
pub(crate) fn evp_key_generate(nid: c_int) -> Result<LcPtr<EVP_PKEY>, Unspecified> {
    let pkey_ctx = LcPtr::new(unsafe { EVP_PKEY_CTX_new_id(EVP_PKEY_EC, null_mut()) })?;

    if 1 != unsafe { EVP_PKEY_keygen_init(*pkey_ctx) } {
        return Err(Unspecified);
    }

    if 1 != unsafe { EVP_PKEY_CTX_set_ec_paramgen_curve_nid(*pkey_ctx, nid) } {
        return Err(Unspecified);
    }

    let mut pkey = null_mut::<EVP_PKEY>();

    if 1 != indicator_check!(unsafe { EVP_PKEY_keygen(*pkey_ctx, &mut pkey) }) {
        return Err(Unspecified);
    }

    let pkey = LcPtr::new(pkey)?;

    Ok(pkey)
}

#[inline]
unsafe fn evp_key_from_public_private(
    ec_group: &LcPtr<EC_GROUP>,
    public_ec_point: &LcPtr<EC_POINT>,
    private_bignum: &DetachableLcPtr<BIGNUM>,
) -> Result<LcPtr<EVP_PKEY>, KeyRejected> {
    let ec_key = DetachableLcPtr::new(EC_KEY_new())?;
    if 1 != EC_KEY_set_group(*ec_key, **ec_group) {
        return Err(KeyRejected::unexpected_error());
    }
    if 1 != EC_KEY_set_public_key(*ec_key, **public_ec_point) {
        return Err(KeyRejected::unexpected_error());
    }
    if 1 != EC_KEY_set_private_key(*ec_key, **private_bignum) {
        return Err(KeyRejected::unexpected_error());
    }

    let evp_pkey = LcPtr::new(EVP_PKEY_new())?;

    if 1 != EVP_PKEY_assign_EC_KEY(*evp_pkey, *ec_key) {
        return Err(KeyRejected::unexpected_error());
    }
    ec_key.detach();

    let nid = EC_GROUP_get_curve_name(ec_group.as_const_ptr());
    validate_evp_key(&evp_pkey.as_const(), nid)?;

    Ok(evp_pkey)
}

#[inline]
pub(crate) unsafe fn ec_group_from_nid(nid: i32) -> Result<LcPtr<EC_GROUP>, ()> {
    LcPtr::new(EC_GROUP_new_by_curve_name(nid))
}

#[inline]
pub(crate) unsafe fn ec_point_from_bytes(
    ec_group: &LcPtr<EC_GROUP>,
    bytes: &[u8],
) -> Result<LcPtr<EC_POINT>, Unspecified> {
    let ec_point = LcPtr::new(EC_POINT_new(**ec_group))?;

    if 1 != EC_POINT_oct2point(
        **ec_group,
        *ec_point,
        bytes.as_ptr(),
        bytes.len(),
        null_mut(),
    ) {
        return Err(Unspecified);
    }

    Ok(ec_point)
}

#[inline]
unsafe fn ec_point_to_bytes(
    ec_group: &ConstPointer<EC_GROUP>,
    ec_point: &ConstPointer<EC_POINT>,
    buf: &mut [u8; PUBLIC_KEY_MAX_LEN],
) -> Result<usize, Unspecified> {
    let pt_conv_form = point_conversion_form_t::POINT_CONVERSION_UNCOMPRESSED;

    let out_len = EC_POINT_point2oct(
        **ec_group,
        **ec_point,
        pt_conv_form,
        buf.as_mut_ptr(),
        PUBLIC_KEY_MAX_LEN,
        null_mut(),
    );
    if out_len == 0 {
        return Err(Unspecified);
    }

    Ok(out_len)
}

#[inline]
fn ecdsa_asn1_to_fixed(alg_id: &'static AlgorithmID, sig: &[u8]) -> Result<Signature, Unspecified> {
    let expected_number_size = ecdsa_fixed_number_byte_size(alg_id);

    let ecdsa_sig = LcPtr::new(unsafe { ECDSA_SIG_from_bytes(sig.as_ptr(), sig.len()) })?;

    let r_bn = ConstPointer::new(unsafe { ECDSA_SIG_get0_r(*ecdsa_sig) })?;
    let r_buffer = r_bn.to_be_bytes();

    let s_bn = ConstPointer::new(unsafe { ECDSA_SIG_get0_s(*ecdsa_sig) })?;
    let s_buffer = s_bn.to_be_bytes();

    Ok(Signature::new(|slice| {
        let (r_start, r_end) = (
            (expected_number_size - r_buffer.len()),
            expected_number_size,
        );
        let (s_start, s_end) = (
            (2 * expected_number_size - s_buffer.len()),
            2 * expected_number_size,
        );

        slice[r_start..r_end].copy_from_slice(r_buffer.as_slice());
        slice[s_start..s_end].copy_from_slice(s_buffer.as_slice());
        2 * expected_number_size
    }))
}

#[inline]
const fn ecdsa_fixed_number_byte_size(alg_id: &'static AlgorithmID) -> usize {
    match alg_id {
        AlgorithmID::ECDSA_P256 | AlgorithmID::ECDSA_P256K1 => 32,
        AlgorithmID::ECDSA_P384 => 48,
        AlgorithmID::ECDSA_P521 => 66,
    }
}

#[inline]
unsafe fn ecdsa_sig_from_fixed(
    alg_id: &'static AlgorithmID,
    signature: &[u8],
) -> Result<LcPtr<ECDSA_SIG>, ()> {
    let num_size_bytes = ecdsa_fixed_number_byte_size(alg_id);
    if signature.len() != 2 * num_size_bytes {
        return Err(());
    }
    let r_bn = DetachableLcPtr::try_from(&signature[..num_size_bytes])?;
    let s_bn = DetachableLcPtr::try_from(&signature[num_size_bytes..])?;

    let ecdsa_sig = LcPtr::new(ECDSA_SIG_new())?;

    if 1 != ECDSA_SIG_set0(*ecdsa_sig, *r_bn, *s_bn) {
        return Err(());
    }
    r_bn.detach();
    s_bn.detach();

    Ok(ecdsa_sig)
}

#[cfg(test)]
mod tests {
    use crate::ec::key_pair::EcdsaKeyPair;
    use crate::signature::{KeyPair, ECDSA_P256_SHA256_FIXED_SIGNING};
    use crate::test::from_dirty_hex;
    use crate::{signature, test};

    #[test]
    fn test_from_pkcs8() {
        let input = from_dirty_hex(
            r"308187020100301306072a8648ce3d020106082a8648ce3d030107046d306b0201010420090460075f15d
            2a256248000fb02d83ad77593dde4ae59fc5e96142dffb2bd07a14403420004cf0d13a3a7577231ea1b66cf4
            021cd54f21f4ac4f5f2fdd28e05bc7d2bd099d1374cd08d2ef654d6f04498db462f73e0282058dd661a4c9b0
            437af3f7af6e724",
        );

        let result = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &input);
        assert!(result.is_ok());
        let key_pair = result.unwrap();
        assert_eq!("EcdsaKeyPair { public_key: EcdsaPublicKey(\"04cf0d13a3a7577231ea1b66cf4021cd54f21f4ac4f5f2fdd28e05bc7d2bd099d1374cd08d2ef654d6f04498db462f73e0282058dd661a4c9b0437af3f7af6e724\") }", 
                   format!("{key_pair:?}"));
        assert_eq!(
            "EcdsaPrivateKey(ECDSA_P256)",
            format!("{:?}", key_pair.private_key())
        );
        let pub_key = key_pair.public_key();
        let der_pub_key = pub_key.as_der().unwrap();

        assert_eq!(
            from_dirty_hex(
                r"3059301306072a8648ce3d020106082a8648ce3d03010703420004cf0d13a3a7577231ea1b66cf402
                1cd54f21f4ac4f5f2fdd28e05bc7d2bd099d1374cd08d2ef654d6f04498db462f73e0282058dd661a4c9
                b0437af3f7af6e724",
            )
            .as_slice(),
            der_pub_key.as_ref()
        );
    }

    #[test]
    fn test_ecdsa_asn1_verify() {
        /*
                Curve = P-256
        Digest = SHA256
        Msg = ""
        Q = 0430345fd47ea21a11129be651b0884bfac698377611acc9f689458e13b9ed7d4b9d7599a68dcf125e7f31055ccb374cd04f6d6fd2b217438a63f6f667d50ef2f0
        Sig = 30440220341f6779b75e98bb42e01095dd48356cbf9002dc704ac8bd2a8240b88d3796c60220555843b1b4e264fe6ffe6e2b705a376c05c09404303ffe5d2711f3e3b3a010a1
        Result = P (0 )
                 */

        let alg = &signature::ECDSA_P256_SHA256_ASN1;
        let msg = "";
        let public_key = from_dirty_hex(
            r"0430345fd47ea21a11129be651b0884bfac698377611acc9f689458e1
        3b9ed7d4b9d7599a68dcf125e7f31055ccb374cd04f6d6fd2b217438a63f6f667d50ef2f0",
        );
        let sig = from_dirty_hex(
            r"30440220341f6779b75e98bb42e01095dd48356cbf9002dc704ac8bd2a8240b8
        8d3796c60220555843b1b4e264fe6ffe6e2b705a376c05c09404303ffe5d2711f3e3b3a010a1",
        );
        let unparsed_pub_key = signature::UnparsedPublicKey::new(alg, &public_key);

        let actual_result = unparsed_pub_key.verify(msg.as_bytes(), &sig);
        assert!(actual_result.is_ok(), "Key: {}", test::to_hex(public_key));
    }
}
