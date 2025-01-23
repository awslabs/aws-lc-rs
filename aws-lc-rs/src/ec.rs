// Copyright 2015-2016 Brian Smith.
// SPDX-License-Identifier: ISC
// Modifications copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

use crate::ec::signature::AlgorithmID;
use core::ptr::null_mut;
// TODO: Uncomment when MSRV >= 1.64
use std::os::raw::c_int;

use crate::error::{KeyRejected, Unspecified};
use crate::fips::indicator_check;
use crate::ptr::{ConstPointer, LcPtr};
use crate::signature::Signature;
#[cfg(feature = "fips")]
use crate::aws_lc::EC_KEY_check_fips;
#[cfg(not(feature = "fips"))]
use crate::aws_lc::EC_KEY_check_key;
use crate::aws_lc::{
    d2i_PrivateKey, point_conversion_form_t, BN_bn2bin_padded, BN_num_bytes, ECDSA_SIG_from_bytes,
    ECDSA_SIG_get0_r, ECDSA_SIG_get0_s, EC_GROUP_get_curve_name, EC_KEY_get0_group,
    EC_KEY_get0_private_key, EC_KEY_get0_public_key, EC_POINT_new,
    EC_POINT_oct2point, EC_POINT_point2oct, EC_group_p224, EC_group_p256, EC_group_p384,
    EC_group_p521, EC_group_secp256k1, EVP_PKEY_CTX_new_id, EVP_PKEY_CTX_set_ec_paramgen_curve_nid,
    EVP_PKEY_get0_EC_KEY, EVP_PKEY_keygen, EVP_PKEY_keygen_init, NID_X9_62_prime256v1,
    NID_secp224r1, NID_secp256k1, NID_secp384r1, NID_secp521r1, EC_GROUP, EC_KEY, EC_POINT,
    EVP_PKEY, EVP_PKEY_EC,
};

pub(crate) mod key_pair;
pub(crate) mod signature;

const ELEM_MAX_BITS: usize = 521;
pub(crate) const ELEM_MAX_BYTES: usize = (ELEM_MAX_BITS + 7) / 8;

pub(crate) const SCALAR_MAX_BYTES: usize = ELEM_MAX_BYTES;

/// The maximum length, in bytes, of an encoded public key.
pub(crate) const PUBLIC_KEY_MAX_LEN: usize = 1 + (2 * ELEM_MAX_BYTES);

fn verify_ec_key_nid(
    ec_key: &ConstPointer<EC_KEY>,
    expected_curve_nid: i32,
) -> Result<(), KeyRejected> {
    let ec_group = ConstPointer::new(unsafe { EC_KEY_get0_group(**ec_key) })?;
    let key_nid = unsafe { EC_GROUP_get_curve_name(*ec_group) };

    if key_nid != expected_curve_nid {
        return Err(KeyRejected::wrong_algorithm());
    }
    Ok(())
}

#[inline]
#[cfg(not(feature = "fips"))]
pub(crate) fn verify_evp_key_nid(
    evp_pkey: &ConstPointer<EVP_PKEY>,
    expected_curve_nid: i32,
) -> Result<(), KeyRejected> {
    let ec_key = ConstPointer::new(unsafe { EVP_PKEY_get0_EC_KEY(**evp_pkey) })?;
    verify_ec_key_nid(&ec_key, expected_curve_nid)?;

    Ok(())
}

#[inline]
pub(crate) fn validate_evp_key(
    evp_pkey: &ConstPointer<EVP_PKEY>,
    expected_curve_nid: i32,
) -> Result<(), KeyRejected> {
    let ec_key = ConstPointer::new(unsafe { EVP_PKEY_get0_EC_KEY(**evp_pkey) })?;
    verify_ec_key_nid(&ec_key, expected_curve_nid)?;

    #[cfg(not(feature = "fips"))]
    if 1 != unsafe { EC_KEY_check_key(*ec_key) } {
        return Err(KeyRejected::inconsistent_components());
    }

    #[cfg(feature = "fips")]
    if 1 != indicator_check!(unsafe { EC_KEY_check_fips(*ec_key) }) {
        return Err(KeyRejected::inconsistent_components());
    }

    Ok(())
}

pub(crate) fn marshal_private_key_to_buffer(
    private_size: usize,
    evp_pkey: &ConstPointer<EVP_PKEY>,
) -> Result<Vec<u8>, Unspecified> {
    let ec_key = ConstPointer::new(unsafe { EVP_PKEY_get0_EC_KEY(**evp_pkey) })?;
    let private_bn = ConstPointer::new(unsafe { EC_KEY_get0_private_key(*ec_key) })?;
    {
        let size: usize = unsafe { BN_num_bytes(*private_bn).try_into()? };
        debug_assert!(size <= private_size);
    }

    let mut buffer = vec![0u8; private_size];
    if 1 != unsafe { BN_bn2bin_padded(buffer.as_mut_ptr(), private_size, *private_bn) } {
        return Err(Unspecified);
    }

    Ok(buffer)
}

pub(crate) fn unmarshal_der_to_private_key(
    key_bytes: &[u8],
    nid: i32,
) -> Result<LcPtr<EVP_PKEY>, KeyRejected> {
    let mut out = null_mut();
    // `d2i_PrivateKey` -> ... -> `EC_KEY_parse_private_key` -> `EC_KEY_check_key`
    let evp_pkey = LcPtr::new(unsafe {
        d2i_PrivateKey(
            EVP_PKEY_EC,
            &mut out,
            &mut key_bytes.as_ptr(),
            key_bytes
                .len()
                .try_into()
                .map_err(|_| KeyRejected::too_large())?,
        )
    })?;
    #[cfg(not(feature = "fips"))]
    verify_evp_key_nid(&evp_pkey.as_const(), nid)?;
    #[cfg(feature = "fips")]
    validate_evp_key(&evp_pkey.as_const(), nid)?;

    Ok(evp_pkey)
}

pub(crate) fn marshal_public_key_to_buffer(
    buffer: &mut [u8],
    evp_pkey: &LcPtr<EVP_PKEY>,
    compressed: bool,
) -> Result<usize, Unspecified> {
    let ec_key = ConstPointer::new(unsafe { EVP_PKEY_get0_EC_KEY(*evp_pkey.as_const()) })?;
    marshal_ec_public_key_to_buffer(buffer, &ec_key, compressed)
}

pub(crate) fn marshal_ec_public_key_to_buffer(
    buffer: &mut [u8],
    ec_key: &ConstPointer<EC_KEY>,
    compressed: bool,
) -> Result<usize, Unspecified> {
    let ec_group = ConstPointer::new(unsafe { EC_KEY_get0_group(**ec_key) })?;

    let ec_point = ConstPointer::new(unsafe { EC_KEY_get0_public_key(**ec_key) })?;

    let point_conversion_form = if compressed {
        point_conversion_form_t::POINT_CONVERSION_COMPRESSED
    } else {
        point_conversion_form_t::POINT_CONVERSION_UNCOMPRESSED
    };

    let out_len = ec_point_to_bytes(&ec_group, &ec_point, buffer, point_conversion_form)?;
    Ok(out_len)
}

pub(crate) fn try_parse_public_key_bytes(
    key_bytes: &[u8],
    expected_curve_nid: i32,
) -> Result<LcPtr<EVP_PKEY>, KeyRejected> {
    LcPtr::<EVP_PKEY>::parse_rfc5280_public_key(key_bytes, EVP_PKEY_EC)
        .or(LcPtr::<EVP_PKEY>::parse_ec_public_point(
            key_bytes,
            expected_curve_nid,
        ))
        .and_then(|key| validate_evp_key(&key.as_const(), expected_curve_nid).map(|()| key))
}

#[inline]
pub(crate) fn evp_key_generate(nid: c_int) -> Result<LcPtr<EVP_PKEY>, Unspecified> {
    let mut pkey_ctx = LcPtr::new(unsafe { EVP_PKEY_CTX_new_id(EVP_PKEY_EC, null_mut()) })?;

    if 1 != unsafe { EVP_PKEY_keygen_init(*pkey_ctx.as_mut()) } {
        return Err(Unspecified);
    }

    if 1 != unsafe { EVP_PKEY_CTX_set_ec_paramgen_curve_nid(*pkey_ctx.as_mut(), nid) } {
        return Err(Unspecified);
    }

    let mut pkey = null_mut::<EVP_PKEY>();

    if 1 != indicator_check!(unsafe { EVP_PKEY_keygen(*pkey_ctx.as_mut(), &mut pkey) }) {
        return Err(Unspecified);
    }

    let pkey = LcPtr::new(pkey)?;

    Ok(pkey)
}

#[inline]
#[allow(non_upper_case_globals)]
pub(crate) fn ec_group_from_nid(nid: i32) -> Result<ConstPointer<EC_GROUP>, Unspecified> {
    Ok(ConstPointer::new(match nid {
        NID_secp224r1 => Ok(unsafe { EC_group_p224() }),
        NID_X9_62_prime256v1 => Ok(unsafe { EC_group_p256() }),
        NID_secp384r1 => Ok(unsafe { EC_group_p384() }),
        NID_secp521r1 => Ok(unsafe { EC_group_p521() }),
        NID_secp256k1 => Ok(unsafe { EC_group_secp256k1() }),
        _ => {
            // OPENSSL_PUT_ERROR(EC, EC_R_UNKNOWN_GROUP);
            Err(Unspecified)
        }
    }?)?)
}

#[inline]
pub(crate) fn ec_point_from_bytes(
    ec_group: &ConstPointer<EC_GROUP>,
    bytes: &[u8],
) -> Result<LcPtr<EC_POINT>, KeyRejected> {
    let mut ec_point = LcPtr::new(unsafe { EC_POINT_new(**ec_group) })?;

    if 1 != unsafe {
        EC_POINT_oct2point(
            **ec_group,
            *ec_point.as_mut(),
            bytes.as_ptr(),
            bytes.len(),
            null_mut(),
        )
    } {
        return Err(KeyRejected::invalid_encoding());
    }

    Ok(ec_point)
}

#[inline]
fn ec_point_to_bytes(
    ec_group: &ConstPointer<EC_GROUP>,
    ec_point: &ConstPointer<EC_POINT>,
    buf: &mut [u8],
    pt_conv_form: point_conversion_form_t,
) -> Result<usize, Unspecified> {
    let buf_len = buf.len();
    let out_len = unsafe {
        EC_POINT_point2oct(
            **ec_group,
            **ec_point,
            pt_conv_form,
            buf.as_mut_ptr(),
            buf_len,
            null_mut(),
        )
    };
    if out_len == 0 {
        return Err(Unspecified);
    }

    Ok(out_len)
}

#[inline]
fn ecdsa_asn1_to_fixed(alg_id: &'static AlgorithmID, sig: &[u8]) -> Result<Signature, Unspecified> {
    let expected_number_size = alg_id.private_key_size();

    let ecdsa_sig = LcPtr::new(unsafe { ECDSA_SIG_from_bytes(sig.as_ptr(), sig.len()) })?;

    let r_bn = ConstPointer::new(unsafe { ECDSA_SIG_get0_r(*ecdsa_sig.as_const()) })?;
    let r_buffer = r_bn.to_be_bytes();

    let s_bn = ConstPointer::new(unsafe { ECDSA_SIG_get0_s(*ecdsa_sig.as_const()) })?;
    let s_buffer = s_bn.to_be_bytes();

    Ok(Signature::new(|slice| {
        let (r_start, r_end) = (expected_number_size - r_buffer.len(), expected_number_size);
        let (s_start, s_end) = (
            2 * expected_number_size - s_buffer.len(),
            2 * expected_number_size,
        );

        slice[r_start..r_end].copy_from_slice(r_buffer.as_slice());
        slice[s_start..s_end].copy_from_slice(s_buffer.as_slice());
        2 * expected_number_size
    }))
}

#[inline]
pub(crate) const fn compressed_public_key_size_bytes(curve_field_bits: usize) -> usize {
    1 + (curve_field_bits + 7) / 8
}

#[inline]
pub(crate) const fn uncompressed_public_key_size_bytes(curve_field_bits: usize) -> usize {
    1 + 2 * ((curve_field_bits + 7) / 8)
}

#[cfg(test)]
mod tests {
    use crate::encoding::{
        AsBigEndian, AsDer, EcPublicKeyCompressedBin, EcPublicKeyUncompressedBin, PublicKeyX509Der,
    };
    use crate::signature::{
        EcdsaKeyPair, KeyPair, UnparsedPublicKey, ECDSA_P256_SHA256_FIXED,
        ECDSA_P256_SHA256_FIXED_SIGNING,
    };
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
        let der_pub_key: PublicKeyX509Der = pub_key.as_der().unwrap();

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

    #[test]
    fn public_key_formats() {
        const MESSAGE: &[u8] = b"message to be signed";

        let key_pair = EcdsaKeyPair::generate(&ECDSA_P256_SHA256_FIXED_SIGNING).unwrap();
        let public_key = key_pair.public_key();
        let as_ref_bytes = public_key.as_ref();
        let compressed = AsBigEndian::<EcPublicKeyCompressedBin>::as_be_bytes(public_key).unwrap();
        let uncompressed =
            AsBigEndian::<EcPublicKeyUncompressedBin>::as_be_bytes(public_key).unwrap();
        let pub_x509 = AsDer::<PublicKeyX509Der>::as_der(public_key).unwrap();
        assert_eq!(as_ref_bytes, uncompressed.as_ref());
        assert_ne!(compressed.as_ref()[0], 0x04);

        let rng = crate::rand::SystemRandom::new();

        let signature = key_pair.sign(&rng, MESSAGE).unwrap();

        for pub_key_bytes in [
            as_ref_bytes,
            compressed.as_ref(),
            uncompressed.as_ref(),
            pub_x509.as_ref(),
        ] {
            UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, pub_key_bytes)
                .verify(MESSAGE, signature.as_ref())
                .unwrap();
        }
    }
}
