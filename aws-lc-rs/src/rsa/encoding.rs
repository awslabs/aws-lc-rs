// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

/// PKCS#8 Encoding Functions
pub(in crate::rsa) mod pkcs8 {
    use crate::aws_lc::{EVP_marshal_private_key, EVP_parse_private_key, EVP_PKEY};
    use crate::cbb::LcCBB;
    use crate::cbs;
    use crate::error::{KeyRejected, Unspecified};
    use crate::ptr::LcPtr;
    use crate::rsa::key::is_rsa_key;

    // Based on a measurement of a PKCS#8 v1 document containing an RSA-8192 key with an additional 1% capacity buffer
    // rounded to an even 64-bit words (4678 + 1% + padding ≈ 4728).
    const PKCS8_FIXED_CAPACITY_BUFFER: usize = 4728;

    pub(in crate::rsa) fn encode_v1_der(key: &LcPtr<EVP_PKEY>) -> Result<Vec<u8>, Unspecified> {
        let mut buffer = vec![0u8; PKCS8_FIXED_CAPACITY_BUFFER];
        let out_len = {
            let mut cbb = LcCBB::new_fixed(<&mut [u8; PKCS8_FIXED_CAPACITY_BUFFER]>::try_from(
                buffer.as_mut_slice(),
            )?);
            if 1 != unsafe { EVP_marshal_private_key(cbb.as_mut_ptr(), *key.as_const()) } {
                return Err(Unspecified);
            }
            cbb.finish()?
        };

        buffer.truncate(out_len);

        Ok(buffer)
    }

    // Supports v1 and v2 encodings through a single API entry-point.
    pub(in crate::rsa) fn decode_der(pkcs8: &[u8]) -> Result<LcPtr<EVP_PKEY>, KeyRejected> {
        let mut cbs = cbs::build_CBS(pkcs8);
        let key = LcPtr::new(unsafe { EVP_parse_private_key(&mut cbs) })
            .map_err(|()| KeyRejected::invalid_encoding())?;
        if !is_rsa_key(&key) {
            return Err(KeyRejected::unspecified());
        }
        Ok(key)
    }
}

/// [RFC 8017](https://www.rfc-editor.org/rfc/rfc8017.html)
///
/// PKCS #1: RSA Cryptography Specifications Version 2.2
pub(in crate::rsa) mod rfc8017 {
    use crate::aws_lc::{
        EVP_PKEY_assign_RSA, EVP_PKEY_new, RSA_parse_private_key, RSA_public_key_from_bytes,
        RSA_public_key_to_bytes, EVP_PKEY,
    };
    use crate::cbs;
    use crate::error::{KeyRejected, Unspecified};
    use crate::ptr::{DetachableLcPtr, LcPtr};
    use std::ptr::null_mut;

    /// DER encode a RSA public key to `RSAPublicKey` structure.
    pub(in crate::rsa) fn encode_public_key_der(
        pubkey: &LcPtr<EVP_PKEY>,
    ) -> Result<Box<[u8]>, Unspecified> {
        let mut pubkey_bytes = null_mut::<u8>();
        let mut outlen: usize = 0;
        if 1 != unsafe {
            RSA_public_key_to_bytes(
                &mut pubkey_bytes,
                &mut outlen,
                *pubkey.get_rsa()?.as_const(),
            )
        } {
            return Err(Unspecified);
        }
        let pubkey_bytes = LcPtr::new(pubkey_bytes)?;
        let pubkey_slice = unsafe { pubkey_bytes.as_slice(outlen) };
        let pubkey_vec = Vec::from(pubkey_slice);
        Ok(pubkey_vec.into_boxed_slice())
    }

    /// Decode a DER encoded `RSAPublicKey` structure.
    #[inline]
    pub(in crate::rsa) fn decode_public_key_der(
        public_key: &[u8],
    ) -> Result<LcPtr<EVP_PKEY>, KeyRejected> {
        let rsa = DetachableLcPtr::new(unsafe {
            RSA_public_key_from_bytes(public_key.as_ptr(), public_key.len())
        })?;

        let mut pkey = LcPtr::new(unsafe { EVP_PKEY_new() })?;

        if 1 != unsafe { EVP_PKEY_assign_RSA(*pkey.as_mut(), *rsa) } {
            return Err(KeyRejected::unspecified());
        }

        rsa.detach();

        Ok(pkey)
    }

    /// Decodes a DER encoded `RSAPrivateKey` structure.
    #[inline]
    pub(in crate::rsa) fn decode_private_key_der(
        private_key: &[u8],
    ) -> Result<LcPtr<EVP_PKEY>, KeyRejected> {
        let mut cbs = cbs::build_CBS(private_key);

        let rsa = DetachableLcPtr::new(unsafe { RSA_parse_private_key(&mut cbs) })?;

        let mut pkey = LcPtr::new(unsafe { EVP_PKEY_new() })?;

        if 1 != unsafe { EVP_PKEY_assign_RSA(*pkey.as_mut(), *rsa) } {
            return Err(KeyRejected::unspecified());
        }

        rsa.detach();

        Ok(pkey)
    }
}

/// [RFC 5280](https://www.rfc-editor.org/rfc/rfc5280.html)
///
/// Encodings that use the `SubjectPublicKeyInfo` structure.
pub(in crate::rsa) mod rfc5280 {
    use crate::aws_lc::{EVP_marshal_public_key, EVP_parse_public_key, EVP_PKEY};
    use crate::cbb::LcCBB;
    use crate::cbs;
    use crate::encoding::PublicKeyX509Der;
    use crate::error::{KeyRejected, Unspecified};
    use crate::ptr::LcPtr;
    use crate::rsa::key::{is_rsa_key, key_size_bytes};

    pub(in crate::rsa) fn encode_public_key_der(
        key: &LcPtr<EVP_PKEY>,
    ) -> Result<PublicKeyX509Der<'static>, Unspecified> {
        // Data shows that the SubjectPublicKeyInfo is roughly 356% to 375% increase in size compared to the RSA key
        // size in bytes for keys ranging from 2048-bit to 4096-bit. So size the initial capacity to be roughly
        // 400% as a conservative estimate to avoid needing to reallocate for any key in that range.
        let key_size_bytes = key_size_bytes(key);

        // key_size_bytes * 5 == key_size_bytes * (1 + 400%)
        let mut der = LcCBB::new(key_size_bytes * 5);

        if 1 != unsafe { EVP_marshal_public_key(der.as_mut_ptr(), *key.as_const()) } {
            return Err(Unspecified);
        }

        Ok(PublicKeyX509Der::from(der.into_buffer()?))
    }

    pub(in crate::rsa) fn decode_public_key_der(
        value: &[u8],
    ) -> Result<LcPtr<EVP_PKEY>, KeyRejected> {
        let mut der = cbs::build_CBS(value);
        let key = LcPtr::new(unsafe { EVP_parse_public_key(&mut der) })?;
        if !is_rsa_key(&key) {
            return Err(KeyRejected::unspecified());
        }
        Ok(key)
    }
}
