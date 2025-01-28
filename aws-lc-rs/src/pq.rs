// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC
#![allow(unused)]

use crate::aws_lc::{
    d2i_PrivateKey, CBB_init, EVP_DigestSign, EVP_DigestVerify, EVP_PKEY_CTX_new_id,
    EVP_PKEY_CTX_pqdsa_set_params, EVP_PKEY_get_raw_private_key, EVP_PKEY_get_raw_public_key,
    EVP_PKEY_keygen, EVP_PKEY_keygen_init, EVP_PKEY_new, EVP_PKEY_pqdsa_new_raw_private_key,
    EVP_PKEY_pqdsa_new_raw_public_key, EVP_marshal_private_key, EVP_marshal_public_key,
    EVP_parse_public_key, CBB, EVP_PKEY, EVP_PKEY_PQDSA,
};
use crate::cbb::LcCBB;
use crate::cbs::build_CBS;
use crate::digest::digest_ctx::DigestContext;
use crate::error::KeyRejected;
use crate::evp_pkey::*;
use crate::signature::MAX_LEN;
use crate::{digest, error::Unspecified, fips::indicator_check, ptr::LcPtr};
use aws_lc_sys::{EVP_DigestSignInit, EVP_DigestVerifyInit};
use std::{ffi::c_int, ptr::null_mut};

pub(crate) fn evp_key_pqdsa_generate(nid: c_int) -> Result<LcPtr<EVP_PKEY>, Unspecified> {
    let mut pkey_ctx = LcPtr::new(unsafe { EVP_PKEY_CTX_new_id(EVP_PKEY_PQDSA, null_mut()) })?;

    if 1 != unsafe { EVP_PKEY_keygen_init(*pkey_ctx.as_mut()) } {
        return Err(Unspecified);
    }

    if 1 != unsafe { EVP_PKEY_CTX_pqdsa_set_params(*pkey_ctx.as_mut(), nid) } {
        return Err(Unspecified);
    }

    let mut pkey = null_mut::<EVP_PKEY>();

    if 1 != indicator_check!(unsafe { EVP_PKEY_keygen(*pkey_ctx.as_mut(), &mut pkey) }) {
        return Err(Unspecified);
    }

    let pkey = LcPtr::new(pkey)?;

    Ok(pkey)
}

#[cfg(test)]
mod tests {
    use crate::aws_lc::{
        EVP_PKEY_cmp, EVP_PKEY, EVP_PKEY_PQDSA, NID_MLDSA44, NID_MLDSA65, NID_MLDSA87,
    };
    use crate::digest;
    use crate::evp_pkey::*;
    use crate::hmac::sign;
    use crate::pkcs8::Version;
    use crate::pq::evp_key_pqdsa_generate;
    use crate::ptr::LcPtr;
    use std::ffi::c_int;

    #[test]
    fn test_keygen() {
        for nid in [NID_MLDSA44, NID_MLDSA65, NID_MLDSA87] {
            let key = evp_key_pqdsa_generate(nid).unwrap();
            println!("key size: {:?}", key.key_size_bytes());
            test_serialization_for(&key);
            test_signing_for(&key);
        }
    }

    fn test_serialization_for(evp_pkey: &LcPtr<EVP_PKEY>) {
        let public_buffer = evp_pkey.marshal_rfc5280_public_key().unwrap();
        println!("public marshall: {:?}", public_buffer);
        let key_public =
            LcPtr::<EVP_PKEY>::parse_rfc5280_public_key(&public_buffer, EVP_PKEY_PQDSA).unwrap();

        let private_buffer = evp_pkey.marshal_rfc5208_private_key(Version::V1).unwrap();
        println!("private marshall: {:?}", private_buffer);
        let key_private =
            LcPtr::<EVP_PKEY>::parse_rfc5208_private_key(&private_buffer, EVP_PKEY_PQDSA).unwrap();

        let raw_public_buffer = key_public.marshal_raw_public_key().unwrap();
        println!("raw public size: {}", raw_public_buffer.len());
        let key_public2 =
            LcPtr::<EVP_PKEY>::parse_raw_public_key(&raw_public_buffer, EVP_PKEY_PQDSA).unwrap();

        assert_eq!(1, unsafe {
            EVP_PKEY_cmp(*key_public.as_const(), *key_public2.as_const())
        });

        let raw_private_buffer = key_private.marshal_raw_private_key().unwrap();
        println!("raw private size: {}", raw_private_buffer.len());
        let key_private2 =
            LcPtr::<EVP_PKEY>::parse_raw_private_key(&raw_private_buffer, EVP_PKEY_PQDSA).unwrap();

        // TODO: Currently the public key is not populated
        // assert_eq!(1, unsafe {
        //     EVP_PKEY_cmp(*key_private.as_const(), *key_private2.as_const())
        // });
    }

    fn test_signing_for(evp_pkey: &LcPtr<EVP_PKEY>) {
        let message = b"hello world";
        let signature = evp_pkey.sign(message, None).unwrap();
        println!("signature size: {}", signature.len());
        assert_eq!(signature.len(), evp_pkey.signature_size_bytes());
        evp_pkey.verify(message, None, &signature).unwrap();
        println!("verified: {:?}", signature);
    }
}
