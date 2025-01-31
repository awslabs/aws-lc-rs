// Copyright 2017 Brian Smith.
// SPDX-License-Identifier: ISC
// Modifications copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

use aws_lc_rs::encoding::{AsDer, Pkcs8V1Der, PublicKeyX509Der};
use aws_lc_rs::rsa::{
    EncryptionAlgorithmId, KeySize, OaepPrivateDecryptingKey, OaepPublicEncryptingKey,
    Pkcs1PrivateDecryptingKey, Pkcs1PublicEncryptingKey, PrivateDecryptingKey, PublicEncryptingKey,
    OAEP_SHA1_MGF1SHA1, OAEP_SHA256_MGF1SHA256, OAEP_SHA384_MGF1SHA384, OAEP_SHA512_MGF1SHA512,
};
use aws_lc_rs::signature::{
    KeyPair, RsaKeyPair, RsaParameters, RsaPublicKeyComponents, RsaSubjectPublicKey,
};
use aws_lc_rs::test::to_hex_upper;
use aws_lc_rs::{rand, signature, test, test_file};

#[test]
fn rsa_traits() {
    test::compile_time_assert_send::<RsaKeyPair>();
    test::compile_time_assert_sync::<RsaKeyPair>();
    test::compile_time_assert_send::<RsaSubjectPublicKey>();
    test::compile_time_assert_sync::<RsaSubjectPublicKey>();
    test::compile_time_assert_send::<RsaPublicKeyComponents<&[u8]>>();
    test::compile_time_assert_sync::<RsaPublicKeyComponents<&[u8]>>();
    test::compile_time_assert_send::<RsaPublicKeyComponents<Vec<u8>>>();
    test::compile_time_assert_sync::<RsaPublicKeyComponents<Vec<u8>>>();
}

#[test]
fn rsa_from_pkcs8_test() {
    test::run(
        test_file!("data/rsa_from_pkcs8_tests.txt"),
        |section, test_case| {
            assert_eq!(section, "");

            let input = test_case.consume_bytes("Input");
            let error = test_case.consume_optional_string("Error");

            match (RsaKeyPair::from_pkcs8(&input), error) {
                (Ok(_), None) => (),
                (Err(e), None) => panic!("Failed with error \"{e}\", but expected to succeed"),
                (Ok(_), Some(e)) => panic!("Succeeded, but expected error \"{e}\""),
                (Err(actual), Some(expected)) => assert_eq!(
                    format!("{actual}"),
                    expected,
                    "Input: {}",
                    test::to_hex(input.as_slice())
                ),
            }

            Ok(())
        },
    );
}

#[test]
fn test_signature_rsa_pkcs1_sign() {
    let rng = rand::SystemRandom::new();
    test::run(
        test_file!("data/rsa_pkcs1_sign_tests.txt"),
        |section, test_case| {
            assert_eq!(section, "");
            let digest_name = test_case.consume_string("Digest");
            let alg = match digest_name.as_ref() {
                "SHA256" => &signature::RSA_PKCS1_SHA256,
                "SHA384" => &signature::RSA_PKCS1_SHA384,
                "SHA512" => &signature::RSA_PKCS1_SHA512,
                _ => panic!("Unsupported digest: {digest_name}"),
            };

            let private_key = test_case.consume_bytes("Key");
            let debug_msg = format!("Key = {}", test::to_hex(&private_key));
            let msg = test_case.consume_bytes("Msg");
            let expected = test_case.consume_bytes("Sig");
            let result = test_case.consume_string("Result");

            let key_pair = RsaKeyPair::from_der(&private_key);
            if result == "Fail-Invalid-Key" {
                assert!(key_pair.is_err(), "{}", &debug_msg);
                return Ok(());
            }
            let key_pair = key_pair.expect(&debug_msg);

            // XXX: This test is too slow on Android ARM Travis CI builds.
            // TODO: re-enable these tests on Android ARM.
            let mut actual = vec![0u8; key_pair.public_modulus_len()];
            key_pair
                .sign(alg, &rng, &msg, actual.as_mut_slice())
                .expect(&debug_msg);
            assert_eq!(actual.as_slice() == &expected[..], result == "Pass");
            Ok(())
        },
    );
}

#[test]
fn test_signature_rsa_pss_sign() {
    test::run(
        test_file!("data/rsa_pss_sign_tests.txt"),
        |section, test_case| {
            assert_eq!(section, "");

            let digest_name = test_case.consume_string("Digest");
            let alg = match digest_name.as_ref() {
                "SHA256" => &signature::RSA_PSS_SHA256,
                "SHA384" => &signature::RSA_PSS_SHA384,
                "SHA512" => &signature::RSA_PSS_SHA512,
                _ => panic!("Unsupported digest: {digest_name}"),
            };

            let result = test_case.consume_string("Result");
            let private_key = test_case.consume_bytes("Key");
            let key_pair = RsaKeyPair::from_der(&private_key);
            if key_pair.is_err() && result == "Fail-Invalid-Key" {
                return Ok(());
            }
            let key_pair = key_pair.unwrap();
            let msg = test_case.consume_bytes("Msg");
            let salt = test_case.consume_bytes("Salt");
            let _expected = test_case.consume_bytes("Sig");

            let rng = test::rand::FixedSliceRandom { bytes: &salt };

            let mut actual = vec![0u8; key_pair.public_modulus_len()];

            key_pair.sign(alg, &rng, &msg, actual.as_mut_slice())?;
            // TODO: *AWS-LC* does not allow the salt to be specified for PSS
            //assert_eq!(actual.as_slice() == &expected[..], result == "Pass");
            Ok(())
        },
    );
}

#[test]
fn test_signature_rsa_pkcs1_verify() {
    let sha1_params = &[
        &signature::RSA_PKCS1_1024_8192_SHA1_FOR_LEGACY_USE_ONLY,
        &signature::RSA_PKCS1_2048_8192_SHA1_FOR_LEGACY_USE_ONLY,
    ];
    let sha256_params = &[
        &signature::RSA_PKCS1_1024_8192_SHA256_FOR_LEGACY_USE_ONLY,
        &signature::RSA_PKCS1_2048_8192_SHA256,
    ];
    let sha384_params = &[
        &signature::RSA_PKCS1_2048_8192_SHA384,
        &signature::RSA_PKCS1_3072_8192_SHA384,
    ];
    let sha512_params = &[
        &signature::RSA_PKCS1_1024_8192_SHA512_FOR_LEGACY_USE_ONLY,
        &signature::RSA_PKCS1_2048_8192_SHA512,
    ];
    test::run(
        test_file!("data/rsa_pkcs1_verify_tests.txt"),
        |section, test_case| {
            assert_eq!(section, "");

            let digest_name = test_case.consume_string("Digest");
            let params: &[_] = match digest_name.as_ref() {
                "SHA1" => sha1_params,
                "SHA256" => sha256_params,
                "SHA384" => sha384_params,
                "SHA512" => sha512_params,
                _ => panic!("Unsupported digest: {digest_name}"),
            };
            let public_key = test_case.consume_bytes("Key");
            let msg = test_case.consume_bytes("Msg");
            let sig = test_case.consume_bytes("Sig");
            let is_valid = test_case.consume_string("Result") == "P";

            let key_bits = RsaParameters::public_modulus_len(&public_key);
            if key_bits.is_err() {
                assert!(!is_valid);
                return Ok(());
            }
            let key_bits = key_bits.unwrap();

            for &alg in params {
                let width_ok = key_bits >= alg.min_modulus_len();
                let width_ok = width_ok && key_bits <= alg.max_modulus_len();
                let actual_result =
                    signature::UnparsedPublicKey::new(alg, &public_key).verify(&msg, &sig);
                assert_eq!(actual_result.is_ok(), is_valid && width_ok);
            }

            Ok(())
        },
    );
}

#[test]
fn test_signature_rsa_pss_verify() {
    test::run(
        test_file!("data/rsa_pss_verify_tests.txt"),
        |section, test_case| {
            assert_eq!(section, "");

            let digest_name = test_case.consume_string("Digest");
            let alg = match digest_name.as_ref() {
                "SHA256" => &signature::RSA_PSS_2048_8192_SHA256,
                "SHA384" => &signature::RSA_PSS_2048_8192_SHA384,
                "SHA512" => &signature::RSA_PSS_2048_8192_SHA512,
                _ => panic!("Unsupported digest: {digest_name}"),
            };

            let public_key = test_case.consume_bytes("Key");
            let msg = test_case.consume_bytes("Msg");
            let sig = test_case.consume_bytes("Sig");
            let is_valid = test_case.consume_string("Result") == "P";

            let actual_result =
                signature::UnparsedPublicKey::new(alg, &public_key).verify(&msg, &sig);
            assert_eq!(actual_result.is_ok(), is_valid);

            Ok(())
        },
    );
}

// Test for `primitive::verify()`. Read public key parts from a file
// and use them to verify a signature.
#[test]
fn test_signature_rsa_primitive_verification() {
    test::run(
        test_file!("data/rsa_primitive_verify_tests.txt"),
        |section, test_case| {
            assert_eq!(section, "");
            let n = test_case.consume_bytes("n");
            let e = test_case.consume_bytes("e");
            let msg = test_case.consume_bytes("Msg");
            let sig = test_case.consume_bytes("Sig");
            let expected = test_case.consume_string("Result");
            let public_key = RsaPublicKeyComponents { n: &n, e: &e };
            let result = public_key.verify(&signature::RSA_PKCS1_2048_8192_SHA256, &msg, &sig);
            assert_eq!(
                result.is_ok(),
                expected == "Pass",
                "N = {}",
                to_hex_upper(n)
            );
            Ok(())
        },
    );
}

#[test]
fn rsa_test_public_key_coverage() {
    const PRIVATE_KEY: &[u8] = include_bytes!("data/rsa_test_private_key_2048.p8");
    const PUBLIC_KEY: &[u8] = include_bytes!("data/rsa_test_public_key_2048.der");
    const PUBLIC_KEY_DEBUG: &str = include_str!("data/rsa_test_public_key_2048_debug.txt");

    let key_pair = RsaKeyPair::from_pkcs8(PRIVATE_KEY).unwrap();

    let pubkey = key_pair.public_key();
    // Test `AsRef<[u8]>`
    assert_eq!(pubkey.as_ref(), PUBLIC_KEY);

    // Test `Clone`.
    #[allow(let_underscore_drop)]
    let _: RsaSubjectPublicKey = pubkey.clone();

    #[cfg(feature = "ring-io")]
    assert_eq!(
        &[0x01, 0x00, 0x01],
        key_pair
            .public_key()
            .exponent()
            .big_endian_without_leading_zero()
    );

    // Test `Debug`
    assert_eq!(PUBLIC_KEY_DEBUG, format!("{:?}", key_pair.public_key()));
    assert_eq!(
        format!("RsaKeyPair {{ public_key: {:?} }}", key_pair.public_key()),
        format!("{key_pair:?}")
    );
}

#[test]
fn keysize_len() {
    assert_eq!(KeySize::Rsa2048.len(), 256);
    assert_eq!(KeySize::Rsa3072.len(), 384);
    assert_eq!(KeySize::Rsa4096.len(), 512);
    assert_eq!(KeySize::Rsa8192.len(), 1024);
}

macro_rules! generate_encode_decode {
    ($name:ident, $size:expr) => {
        #[test]
        fn $name() {
            let private_key = RsaKeyPair::generate($size).expect("generation");

            let pkcs8v1 = private_key.as_der().expect("encoded");

            let private_key = RsaKeyPair::from_pkcs8(pkcs8v1.as_ref()).expect("decoded");

            let public_key = crate::signature::KeyPair::public_key(&private_key);

            let _ = public_key.as_ref();
        }
    };
}

generate_encode_decode!(rsa2048_generate_encode_decode, KeySize::Rsa2048);
// Key generation for large RSA keys is very slow
#[cfg(not(disable_slow_tests))]
generate_encode_decode!(rsa3072_generate_encode_decode, KeySize::Rsa3072);
// Key generation for large RSA keys is very slow
#[cfg(not(disable_slow_tests))]
generate_encode_decode!(rsa4096_generate_encode_decode, KeySize::Rsa4096);
// Key generation for large RSA keys is very slow
#[cfg(not(disable_slow_tests))]
generate_encode_decode!(rsa8192_generate_encode_decode, KeySize::Rsa8192);

macro_rules! generate_fips_encode_decode {
    ($name:ident, $size:expr) => {
        #[cfg(feature = "fips")]
        #[test]
        fn $name() {
            let private_key = RsaKeyPair::generate_fips($size).expect("generation");

            assert_eq!(true, private_key.is_valid_fips_key());

            let pkcs8v1 = private_key.as_der().expect("encoded");

            let private_key = RsaKeyPair::from_pkcs8(pkcs8v1.as_ref()).expect("decoded");

            let public_key = crate::signature::KeyPair::public_key(&private_key);

            let _ = public_key.as_ref();
        }
    };
    ($name:ident, $size:expr, false) => {
        #[cfg(feature = "fips")]
        #[test]
        fn $name() {
            let _ = RsaKeyPair::generate_fips($size).expect_err("should fail for key size");
        }
    };
}

generate_fips_encode_decode!(rsa2048_generate_fips_encode_decode, KeySize::Rsa2048);
// Key generation for large RSA keys is very slow
#[cfg(not(disable_slow_tests))]
generate_fips_encode_decode!(rsa3072_generate_fips_encode_decode, KeySize::Rsa3072);
// Key generation for large RSA keys is very slow
#[cfg(not(disable_slow_tests))]
generate_fips_encode_decode!(rsa4096_generate_fips_encode_decode, KeySize::Rsa4096);
// Key generation for large RSA keys is very slow
#[cfg(not(disable_slow_tests))]
generate_fips_encode_decode!(rsa8192_generate_fips_encode_decode, KeySize::Rsa8192);

macro_rules! encryption_generate_encode_decode {
    ($name:ident, $size:expr) => {
        #[test]
        fn $name() {
            let private_key = PrivateDecryptingKey::generate($size).expect("generation");

            let pkcs8v1 = private_key.as_der().expect("encoded");

            let private_key = PrivateDecryptingKey::from_pkcs8(pkcs8v1.as_ref()).expect("decoded");

            let public_key = private_key.public_key();

            drop(private_key);

            let public_key_der = public_key.as_der().expect("encoded");

            let _public_key =
                PublicEncryptingKey::from_der(public_key_der.as_ref()).expect("decoded");
        }
    };
}

encryption_generate_encode_decode!(rsa2048_encryption_generate_encode_decode, KeySize::Rsa2048);
// Key generation for large RSA keys is very slow
#[cfg(not(disable_slow_tests))]
encryption_generate_encode_decode!(rsa3072_encryption_generate_encode_decode, KeySize::Rsa3072);
// Key generation for large RSA keys is very slow
#[cfg(not(disable_slow_tests))]
encryption_generate_encode_decode!(rsa4096_encryption_generate_encode_decode, KeySize::Rsa4096);
// Key generation for large RSA keys is very slow
#[cfg(not(disable_slow_tests))]
encryption_generate_encode_decode!(rsa8192_encryption_generate_encode_decode, KeySize::Rsa8192);

macro_rules! encryption_generate_fips_encode_decode {
    ($name:ident, $size:expr) => {
        #[cfg(feature = "fips")]
        #[test]
        fn $name() {
            let private_key = PrivateDecryptingKey::generate_fips($size).expect("generation");

            assert_eq!(true, private_key.is_valid_fips_key());

            let pkcs8v1 = private_key.as_der().expect("encoded");

            let private_key = PrivateDecryptingKey::from_pkcs8(pkcs8v1.as_ref()).expect("decoded");

            let public_key = private_key.public_key();

            drop(private_key);

            let public_key_der = public_key.as_der().expect("encoded");

            let _public_key =
                PublicEncryptingKey::from_der(public_key_der.as_ref()).expect("decoded");
        }
    };
    ($name:ident, $size:expr, false) => {
        #[cfg(feature = "fips")]
        #[test]
        fn $name() {
            let _ =
                PrivateDecryptingKey::generate_fips($size).expect_err("should fail for key size");
        }
    };
}

encryption_generate_fips_encode_decode!(
    rsa2048_encryption_generate_fips_encode_decode,
    KeySize::Rsa2048
);
// Key generation for large RSA keys is very slow
#[cfg(not(disable_slow_tests))]
encryption_generate_fips_encode_decode!(
    rsa3072_encryption_generate_fips_encode_decode,
    KeySize::Rsa3072
);
// Key generation for large RSA keys is very slow
#[cfg(not(disable_slow_tests))]
encryption_generate_fips_encode_decode!(
    rsa4096_encryption_generate_fips_encode_decode,
    KeySize::Rsa4096
);
// Key generation for large RSA keys is very slow
#[cfg(not(disable_slow_tests))]
encryption_generate_fips_encode_decode!(
    rsa8192_encryption_generate_fips_encode_decode,
    KeySize::Rsa8192
);

#[test]
fn public_key_components_clone_debug() {
    let pkc = RsaPublicKeyComponents::<&[u8]> {
        n: &[0x63, 0x61, 0x6d, 0x65, 0x6c, 0x6f, 0x74],
        e: &[0x61, 0x76, 0x61, 0x6c, 0x6f, 0x6e],
    };
    assert_eq!("RsaPublicKeyComponents { n: [99, 97, 109, 101, 108, 111, 116], e: [97, 118, 97, 108, 111, 110] }", format!("{pkc:?}"));
}

#[test]
fn encryption_algorithm_id() {
    assert_eq!(
        OAEP_SHA1_MGF1SHA1.id(),
        EncryptionAlgorithmId::OaepSha1Mgf1sha1
    );
    assert_eq!(
        OAEP_SHA256_MGF1SHA256.id(),
        EncryptionAlgorithmId::OaepSha256Mgf1sha256
    );
    assert_eq!(
        OAEP_SHA384_MGF1SHA384.id(),
        EncryptionAlgorithmId::OaepSha384Mgf1sha384
    );
    assert_eq!(
        OAEP_SHA512_MGF1SHA512.id(),
        EncryptionAlgorithmId::OaepSha512Mgf1sha512
    );
}

#[test]
fn encryption_algorithm_debug() {
    assert_eq!("OaepSha1Mgf1sha1", format!("{OAEP_SHA1_MGF1SHA1:?}"));
}

macro_rules! round_trip_oaep_algorithm {
    ($name:ident, $alg:expr, $keysize:expr) => {
        #[test]
        fn $name() {
            const MESSAGE: &[u8] = b"Hello World!";

            let private_key = PrivateDecryptingKey::generate($keysize).expect("generation");
            let public_key = private_key.public_key();

            let (byte_len, bit_len) = match $keysize {
                KeySize::Rsa2048 => (256, 2048),
                KeySize::Rsa3072 => (384, 3072),
                KeySize::Rsa4096 => (512, 4096),
                KeySize::Rsa8192 => (1024, 8192),
                _ => panic!("missing KeySize match arm"),
            };

            assert_eq!(private_key.key_size_bytes(), byte_len);
            assert_eq!(public_key.key_size_bytes(), byte_len);
            assert_eq!(private_key.key_size_bits(), bit_len);
            assert_eq!(public_key.key_size_bits(), bit_len);

            let public_key = OaepPublicEncryptingKey::new(public_key)
                .expect("RSA-OAEP public key from public key");
            let private_key = OaepPrivateDecryptingKey::new(private_key)
                .expect("RSA-OAEP private key from private key");

            assert_eq!(private_key.key_size_bytes(), byte_len);
            assert_eq!(public_key.key_size_bytes(), byte_len);
            assert_eq!(private_key.key_size_bits(), bit_len);
            assert_eq!(public_key.key_size_bits(), bit_len);

            // fixed message, None (empty label)
            {
                let mut ciphertext = vec![0u8; public_key.ciphertext_size()];

                let ciphertext = public_key
                    .encrypt($alg, MESSAGE, ciphertext.as_mut(), None)
                    .expect("encrypted");

                let mut plaintext = vec![0u8; private_key.min_output_size()];

                let plaintext = private_key
                    .decrypt($alg, ciphertext, &mut plaintext, None)
                    .expect("decrypted");

                assert_eq!(MESSAGE, plaintext);
            }

            // fixed message, Some(&[0u8; 0])
            {
                let mut ciphertext = vec![0u8; public_key.ciphertext_size()];

                let ciphertext = public_key
                    .encrypt($alg, MESSAGE, ciphertext.as_mut(), Some(&[0u8; 0]))
                    .expect("encrypted");

                let mut plaintext = vec![0u8; private_key.min_output_size()];

                let plaintext = private_key
                    .decrypt($alg, ciphertext, &mut plaintext, Some(&[0u8; 0]))
                    .expect("decrypted");

                assert_eq!(MESSAGE, plaintext);
            }

            // fixed message, Some(label)
            {
                let mut ciphertext = vec![0u8; public_key.ciphertext_size()];

                let label: &[u8] = br"Testing Data Label";

                let ciphertext = public_key
                    .encrypt($alg, MESSAGE, ciphertext.as_mut(), Some(label))
                    .expect("encrypted");

                let mut plaintext = vec![0u8; private_key.min_output_size()];

                let plaintext = private_key
                    .decrypt($alg, ciphertext, &mut plaintext, Some(label))
                    .expect("decrypted");

                assert_eq!(MESSAGE, plaintext);
            }

            // zero-length message
            {
                let message: &[u8] = &[1u8; 0];
                let mut ciphertext = vec![0u8; public_key.ciphertext_size()];

                let ciphertext = public_key
                    .encrypt($alg, message, ciphertext.as_mut(), None)
                    .expect("encrypted");

                let mut plaintext = vec![0u8; private_key.min_output_size()];

                let plaintext = private_key
                    .decrypt($alg, ciphertext, &mut plaintext, None)
                    .expect("decrypted");

                assert_eq!(message, plaintext);
            }

            // max_plaintext_size message
            {
                let message = vec![1u8; public_key.max_plaintext_size($alg)];
                let mut ciphertext = vec![0u8; public_key.ciphertext_size()];

                let ciphertext = public_key
                    .encrypt($alg, &message, ciphertext.as_mut(), None)
                    .expect("encrypted");

                let mut plaintext = vec![0u8; private_key.min_output_size()];

                let plaintext = private_key
                    .decrypt($alg, ciphertext, &mut plaintext, None)
                    .expect("decrypted");

                assert_eq!(message, plaintext);
            }

            // max_plaintext_size+1 message
            {
                let message = vec![1u8; public_key.max_plaintext_size($alg) + 1];
                let mut ciphertext = vec![0u8; private_key.min_output_size()];

                public_key
                    .encrypt($alg, &message, ciphertext.as_mut(), None)
                    .expect_err("plaintext too large");
            }
        }
    };
}

round_trip_oaep_algorithm!(
    rsa2048_oaep_sha1_mgf1sha1,
    &OAEP_SHA1_MGF1SHA1,
    KeySize::Rsa2048
);
// Key generation for large RSA keys is very slow
#[cfg(not(disable_slow_tests))]
round_trip_oaep_algorithm!(
    rsa3072_oaep_sha1_mgf1sha1,
    &OAEP_SHA1_MGF1SHA1,
    KeySize::Rsa3072
);
// Key generation for large RSA keys is very slow
#[cfg(not(disable_slow_tests))]
round_trip_oaep_algorithm!(
    rsa4096_oaep_sha1_mgf1sha1,
    &OAEP_SHA1_MGF1SHA1,
    KeySize::Rsa4096
);
// Key generation for large RSA keys is very slow
#[cfg(not(disable_slow_tests))]
round_trip_oaep_algorithm!(
    rsa8192_oaep_sha1_mgf1sha1,
    &OAEP_SHA1_MGF1SHA1,
    KeySize::Rsa8192
);

round_trip_oaep_algorithm!(
    rsa2048_oaep_sha256_mgf1sha256,
    &OAEP_SHA256_MGF1SHA256,
    KeySize::Rsa2048
);
// Key generation for large RSA keys is very slow
#[cfg(not(disable_slow_tests))]
round_trip_oaep_algorithm!(
    rsa3072_oaep_sha256_mgf1sha256,
    &OAEP_SHA256_MGF1SHA256,
    KeySize::Rsa3072
);
// Key generation for large RSA keys is very slow
#[cfg(not(disable_slow_tests))]
round_trip_oaep_algorithm!(
    rsa4096_oaep_sha256_mgf1sha256,
    &OAEP_SHA256_MGF1SHA256,
    KeySize::Rsa4096
);
// Key generation for large RSA keys is very slow
#[cfg(not(disable_slow_tests))]
round_trip_oaep_algorithm!(
    rsa8192_oaep_sha256_mgf1sha256,
    &OAEP_SHA256_MGF1SHA256,
    KeySize::Rsa8192
);

round_trip_oaep_algorithm!(
    rsa2048_oaep_sha384_mgf1sha384,
    &OAEP_SHA384_MGF1SHA384,
    KeySize::Rsa2048
);
// Key generation for large RSA keys is very slow
#[cfg(not(disable_slow_tests))]
round_trip_oaep_algorithm!(
    rsa3072_oaep_sha384_mgf1sha384,
    &OAEP_SHA384_MGF1SHA384,
    KeySize::Rsa3072
);
// Key generation for large RSA keys is very slow
#[cfg(not(disable_slow_tests))]
round_trip_oaep_algorithm!(
    rsa4096_oaep_sha384_mgf1sha384,
    &OAEP_SHA384_MGF1SHA384,
    KeySize::Rsa4096
);
// Key generation for large RSA keys is very slow
#[cfg(not(disable_slow_tests))]
round_trip_oaep_algorithm!(
    rsa8192_oaep_sha384_mgf1sha384,
    &OAEP_SHA384_MGF1SHA384,
    KeySize::Rsa8192
);

round_trip_oaep_algorithm!(
    rsa2048_oaep_sha512_mgf1sha512,
    &OAEP_SHA512_MGF1SHA512,
    KeySize::Rsa2048
);
// Key generation for large RSA keys is very slow
#[cfg(not(disable_slow_tests))]
round_trip_oaep_algorithm!(
    rsa3072_oaep_sha512_mgf1sha512,
    &OAEP_SHA512_MGF1SHA512,
    KeySize::Rsa3072
);
// Key generation for large RSA keys is very slow
#[cfg(not(disable_slow_tests))]
round_trip_oaep_algorithm!(
    rsa4096_oaep_sha512_mgf1sha512,
    &OAEP_SHA512_MGF1SHA512,
    KeySize::Rsa4096
);
// Key generation for large RSA keys is very slow
#[cfg(not(disable_slow_tests))]
round_trip_oaep_algorithm!(
    rsa8192_oaep_sha512_mgf1sha512,
    &OAEP_SHA512_MGF1SHA512,
    KeySize::Rsa8192
);

#[test]
fn encrypting_keypair_debug() {
    let private_key = PrivateDecryptingKey::generate(KeySize::Rsa2048).expect("generation");

    assert_eq!("PrivateDecryptingKey", format!("{:?}", &private_key));

    let public_key = private_key.public_key();

    assert_eq!("PublicEncryptingKey", format!("{:?}", &public_key));

    let oaep_private_key =
        OaepPrivateDecryptingKey::new(private_key.clone()).expect("oaep private key");

    assert_eq!(
        "OaepPrivateDecryptingKey { .. }",
        format!("{:?}", &oaep_private_key)
    );

    let oaep_public_key =
        OaepPublicEncryptingKey::new(public_key.clone()).expect("oaep public key");

    assert_eq!(
        "OaepPublicEncryptingKey { .. }",
        format!("{:?}", &oaep_public_key)
    );

    let pkcs1_private_key =
        Pkcs1PrivateDecryptingKey::new(private_key.clone()).expect("oaep private key");

    assert_eq!(
        "Pkcs1PrivateDecryptingKey { .. }",
        format!("{:?}", &pkcs1_private_key)
    );

    let pkcs1_public_key =
        Pkcs1PublicEncryptingKey::new(public_key.clone()).expect("oaep public key");

    assert_eq!(
        "Pkcs1PublicEncryptingKey { .. }",
        format!("{:?}", &pkcs1_public_key)
    );
}

#[test]
fn clone_then_drop() {
    const MESSAGE: &[u8] = b"Hello World!";

    let private_key = PrivateDecryptingKey::generate(KeySize::Rsa2048).expect("generation");
    let public_key = private_key.public_key();

    let oaep_priv_key =
        OaepPrivateDecryptingKey::new(private_key.clone()).expect("oaep private key");
    let oaep_pub_key = OaepPublicEncryptingKey::new(public_key.clone()).expect("oaep public key");

    drop(private_key);
    drop(public_key);

    let mut ciphertext = vec![0u8; oaep_pub_key.ciphertext_size()];

    let ciphertext = oaep_pub_key
        .encrypt(&OAEP_SHA256_MGF1SHA256, MESSAGE, ciphertext.as_mut(), None)
        .expect("encrypted");

    let mut plaintext = vec![0u8; oaep_priv_key.key_size_bytes()];

    let plaintext = oaep_priv_key
        .decrypt(&OAEP_SHA256_MGF1SHA256, ciphertext, &mut plaintext, None)
        .expect("decrypted");

    assert_eq!(MESSAGE, plaintext);
}

#[test]
fn encrypt_decrypt_key_size() {
    let private_key = PrivateDecryptingKey::generate(KeySize::Rsa2048).expect("generation");
    let public_key = private_key.public_key();
    assert_eq!(private_key.key_size_bytes(), public_key.key_size_bytes());
    assert_eq!(private_key.key_size_bits(), public_key.key_size_bits());

    let oaep_priv_key =
        OaepPrivateDecryptingKey::new(private_key.clone()).expect("oaep private key");
    let oaep_pub_key = OaepPublicEncryptingKey::new(public_key.clone()).expect("oaep public key");
    assert_eq!(
        oaep_priv_key.key_size_bytes(),
        oaep_pub_key.key_size_bytes()
    );
    assert_eq!(oaep_priv_key.key_size_bits(), oaep_pub_key.key_size_bits());

    assert_eq!(private_key.key_size_bytes(), oaep_priv_key.key_size_bytes());
    assert_eq!(private_key.key_size_bits(), oaep_priv_key.key_size_bits());
}

#[test]
fn too_small_encrypt_key() {
    const PRIVATE_KEY: &[u8] = include_bytes!("data/rsa_test_private_key_1024.p8");
    PrivateDecryptingKey::from_pkcs8(PRIVATE_KEY).expect_err("key too small");
}

#[test]
fn min_encrypt_key() {
    const PRIVATE_KEY: &[u8] = include_bytes!("data/rsa_test_private_key_2048.p8");
    const PUBLIC_KEY: &[u8] = include_bytes!("data/rsa_test_public_key_2048.x509");

    let parsed_private_key = PrivateDecryptingKey::from_pkcs8(PRIVATE_KEY).expect("key supported");
    let parsed_public_key = PublicEncryptingKey::from_der(PUBLIC_KEY).expect("key supported");

    let public_key = parsed_private_key.public_key();

    let private_key_bytes =
        AsDer::<Pkcs8V1Der>::as_der(&parsed_private_key).expect("serializeable");
    let public_key_bytes = AsDer::<PublicKeyX509Der>::as_der(&public_key).expect("serializeable");

    assert_eq!(PRIVATE_KEY, private_key_bytes.as_ref());
    assert_eq!(PUBLIC_KEY, public_key_bytes.as_ref());

    let oaep_parsed_private =
        OaepPrivateDecryptingKey::new(parsed_private_key.clone()).expect("supported key");
    let oaep_parsed_public =
        OaepPublicEncryptingKey::new(parsed_public_key.clone()).expect("supported key");

    let message = vec![42u8; oaep_parsed_public.max_plaintext_size(&OAEP_SHA256_MGF1SHA256)];

    let mut ciphertext = vec![0u8; oaep_parsed_public.ciphertext_size()];
    let ciphertext = oaep_parsed_public
        .encrypt(&OAEP_SHA256_MGF1SHA256, &message, &mut ciphertext, None)
        .expect("encrypted");

    let mut plaintext = vec![0u8; oaep_parsed_private.min_output_size()];
    let plaintext = oaep_parsed_private
        .decrypt(&OAEP_SHA256_MGF1SHA256, ciphertext, &mut plaintext, None)
        .expect("decrypted");

    assert_eq!(message, plaintext);

    let pkcs1_parsed_private =
        Pkcs1PrivateDecryptingKey::new(parsed_private_key.clone()).expect("supported key");
    let pkcs1_parsed_public =
        Pkcs1PublicEncryptingKey::new(parsed_public_key.clone()).expect("supported key");

    let message = vec![42u8; pkcs1_parsed_public.max_plaintext_size()];

    let mut ciphertext = vec![0u8; pkcs1_parsed_public.ciphertext_size()];
    let ciphertext = pkcs1_parsed_public
        .encrypt(&message, &mut ciphertext)
        .expect("encrypted");

    let mut plaintext = vec![0u8; pkcs1_parsed_private.min_output_size()];
    let plaintext = pkcs1_parsed_private
        .decrypt(ciphertext, &mut plaintext)
        .expect("decrypted");

    assert_eq!(message, plaintext);
}

#[test]
fn max_encrypt_key() {
    const PRIVATE_KEY: &[u8] = include_bytes!("data/rsa_test_private_key_8192.p8");
    const PUBLIC_KEY: &[u8] = include_bytes!("data/rsa_test_public_key_8192.x509");

    let parsed_private_key = PrivateDecryptingKey::from_pkcs8(PRIVATE_KEY).expect("key supported");
    let parsed_public_key = PublicEncryptingKey::from_der(PUBLIC_KEY).expect("key supported");

    let public_key = parsed_private_key.public_key();

    let private_key_bytes =
        AsDer::<Pkcs8V1Der>::as_der(&parsed_private_key).expect("serializeable");
    let public_key_bytes = AsDer::<PublicKeyX509Der>::as_der(&public_key).expect("serializeable");

    assert_eq!(PRIVATE_KEY, private_key_bytes.as_ref());
    assert_eq!(PUBLIC_KEY, public_key_bytes.as_ref());

    let oaep_parsed_private =
        OaepPrivateDecryptingKey::new(parsed_private_key.clone()).expect("supported key");
    let oaep_parsed_public =
        OaepPublicEncryptingKey::new(parsed_public_key.clone()).expect("supported key");

    let message = vec![42u8; oaep_parsed_public.max_plaintext_size(&OAEP_SHA256_MGF1SHA256)];

    let mut ciphertext = vec![0u8; oaep_parsed_public.ciphertext_size()];
    let ciphertext = oaep_parsed_public
        .encrypt(&OAEP_SHA256_MGF1SHA256, &message, &mut ciphertext, None)
        .expect("encrypted");

    let mut plaintext = vec![0u8; oaep_parsed_private.key_size_bytes()];
    let plaintext = oaep_parsed_private
        .decrypt(&OAEP_SHA256_MGF1SHA256, ciphertext, &mut plaintext, None)
        .expect("decrypted");

    assert_eq!(message, plaintext);

    let pkcs1_parsed_private =
        Pkcs1PrivateDecryptingKey::new(parsed_private_key.clone()).expect("supported key");
    let pkcs1_parsed_public =
        Pkcs1PublicEncryptingKey::new(parsed_public_key.clone()).expect("supported key");

    let message = vec![42u8; pkcs1_parsed_public.max_plaintext_size()];

    let mut ciphertext = vec![0u8; pkcs1_parsed_public.ciphertext_size()];
    let ciphertext = pkcs1_parsed_public
        .encrypt(&message, &mut ciphertext)
        .expect("encrypted");

    let mut plaintext = vec![0u8; pkcs1_parsed_private.min_output_size()];
    let plaintext = pkcs1_parsed_private
        .decrypt(ciphertext, &mut plaintext)
        .expect("decrypted");

    assert_eq!(message, plaintext);
}

#[test]
fn errors_on_larger_than_max_plaintext() {
    const PUBLIC_KEY: &[u8] = include_bytes!("data/rsa_test_public_key_2048.x509");

    let parsed_public_key = PublicEncryptingKey::from_der(PUBLIC_KEY).expect("key supported");

    let oaep_parsed_public =
        OaepPublicEncryptingKey::new(parsed_public_key.clone()).expect("supported key");

    let message = vec![42u8; oaep_parsed_public.max_plaintext_size(&OAEP_SHA256_MGF1SHA256) + 1];

    let mut ciphertext = vec![0u8; oaep_parsed_public.ciphertext_size()];
    oaep_parsed_public
        .encrypt(&OAEP_SHA256_MGF1SHA256, &message, &mut ciphertext, None)
        .expect_err("plaintext too large");

    let pkcs1_parsed_public =
        Pkcs1PublicEncryptingKey::new(parsed_public_key.clone()).expect("supported key");

    let message = vec![42u8; pkcs1_parsed_public.max_plaintext_size() + 1];

    let mut ciphertext = vec![0u8; pkcs1_parsed_public.ciphertext_size()];
    pkcs1_parsed_public
        .encrypt(&message, &mut ciphertext)
        .expect_err("plaintext too large");
}

#[test]
fn too_big_encrypt_key() {
    const PRIVATE_KEY: &[u8] = include_bytes!("data/rsa_test_private_key_16384.p8");
    PrivateDecryptingKey::from_pkcs8(PRIVATE_KEY).expect_err("key too big");
}

macro_rules! round_trip_pkcs1_encryption {
    ($name:ident, $keysize:expr) => {
        #[test]
        fn $name() {
            const MESSAGE: &[u8] = b"Hello World";

            let priv_key = PrivateDecryptingKey::generate($keysize).expect("key generated");
            let pub_key = priv_key.public_key();

            let priv_key =
                Pkcs1PrivateDecryptingKey::new(priv_key).expect("construct PKCS1 private key");

            let pub_key =
                Pkcs1PublicEncryptingKey::new(pub_key).expect("construct PKCS1 private key");

            let (byte_len, bit_len) = match $keysize {
                KeySize::Rsa2048 => (256, 2048),
                KeySize::Rsa3072 => (384, 3072),
                KeySize::Rsa4096 => (512, 4096),
                KeySize::Rsa8192 => (1024, 8192),
                _ => panic!("missing KeySize match arm"),
            };

            assert_eq!(priv_key.key_size_bytes(), byte_len);
            assert_eq!(pub_key.key_size_bytes(), byte_len);
            assert_eq!(priv_key.key_size_bits(), bit_len);
            assert_eq!(pub_key.key_size_bits(), bit_len);

            let mut ciphertext = vec![0u8; pub_key.ciphertext_size()];

            let ciphertext: &[u8] = pub_key
                .encrypt(MESSAGE, &mut ciphertext)
                .expect("encrypted");

            let mut plaintext = vec![0u8; priv_key.min_output_size()];

            let plaintext: &[u8] = priv_key
                .decrypt(ciphertext, &mut plaintext)
                .expect("decrypt");

            assert_eq!(MESSAGE, plaintext);
        }
    };
}

round_trip_pkcs1_encryption!(rsa2048_pkcs1_encryption, KeySize::Rsa2048);
// Key generation for large RSA keys is very slow
#[cfg(not(disable_slow_tests))]
round_trip_pkcs1_encryption!(rsa3072_pkcs1_encryption, KeySize::Rsa3072);
// Key generation for large RSA keys is very slow
#[cfg(not(disable_slow_tests))]
round_trip_pkcs1_encryption!(rsa4096_pkcs1_encryption, KeySize::Rsa4096);
// Key generation for large RSA keys is very slow
#[cfg(not(disable_slow_tests))]
round_trip_pkcs1_encryption!(rsa8192_pkcs1_encryption, KeySize::Rsa8192);

// Generated by `echo -n "OpenSSL KAT" | openssl pkeyutl -inkey rsa_test_public_key_2048.x509 -pubin -encrypt -pkeyopt rsa_padding_mode:pkcs1 | xxd -i`
#[test]
fn rsa2048_pkcs1_openssl_kat() {
    const PRIVATE_KEY: &[u8] = include_bytes!("data/rsa_test_private_key_2048.p8");

    const EXPECTED_MESSAGE: &[u8] = b"OpenSSL KAT";
    const CIPHERTEXT: &[u8] = &[
        0x79, 0xc3, 0xf1, 0x0a, 0x69, 0xc7, 0x0b, 0x19, 0xc1, 0xfd, 0x62, 0xbe, 0x24, 0x85, 0x31,
        0xc1, 0x1d, 0x6c, 0x85, 0x34, 0x03, 0x78, 0x4a, 0x7e, 0xbe, 0xb8, 0xa2, 0xe5, 0xac, 0x79,
        0xaf, 0x1c, 0x6a, 0xff, 0x2f, 0xa5, 0xff, 0xaa, 0x5b, 0xb9, 0x6f, 0xa1, 0xaa, 0x42, 0x72,
        0xa5, 0x87, 0x92, 0x05, 0x97, 0xb4, 0xef, 0x42, 0x02, 0xd3, 0xc4, 0x9f, 0x6e, 0xe3, 0xed,
        0x51, 0xba, 0x52, 0xcf, 0x44, 0x14, 0xf8, 0x47, 0x53, 0x8c, 0xfc, 0x12, 0x0d, 0x53, 0x13,
        0x11, 0x00, 0x7f, 0x87, 0xf7, 0xb5, 0x56, 0xdc, 0xd7, 0xe9, 0xf4, 0xc5, 0xb0, 0x34, 0x85,
        0x10, 0x8a, 0x04, 0xe4, 0x62, 0x38, 0x91, 0xa4, 0xb3, 0x5e, 0x98, 0x15, 0x89, 0x98, 0xf2,
        0xf7, 0x4f, 0xb1, 0x30, 0xa2, 0x09, 0x23, 0x38, 0x43, 0x22, 0x58, 0xec, 0x3c, 0xeb, 0x8d,
        0x62, 0x75, 0x9f, 0xa9, 0x83, 0x0d, 0xe0, 0x43, 0x5a, 0x1c, 0xd5, 0xdb, 0xc6, 0x2c, 0x97,
        0x19, 0xfd, 0xa7, 0xb5, 0x71, 0x1b, 0x87, 0xab, 0x3d, 0xf2, 0x3c, 0x42, 0xc2, 0xea, 0xd8,
        0x57, 0x2a, 0x80, 0xdc, 0xc1, 0x00, 0x66, 0xa5, 0xf0, 0x95, 0x51, 0x56, 0xe8, 0x66, 0x8e,
        0xe9, 0x8e, 0x2a, 0xa6, 0x37, 0x16, 0xeb, 0xbf, 0xe5, 0x12, 0x25, 0x67, 0x0e, 0xc0, 0x3d,
        0x3c, 0x58, 0x15, 0x16, 0x54, 0x15, 0x04, 0xa2, 0xa2, 0x26, 0x46, 0x81, 0x36, 0x64, 0xc0,
        0x7f, 0x6a, 0x04, 0x10, 0x2a, 0x7f, 0x08, 0x6d, 0x4b, 0x23, 0x12, 0x30, 0x9b, 0x0c, 0xb4,
        0xa5, 0x10, 0x80, 0xaa, 0xf0, 0xe3, 0xf3, 0x1e, 0x3b, 0x59, 0x1d, 0x52, 0x68, 0x8e, 0xb9,
        0x9c, 0x89, 0x97, 0x46, 0xfb, 0x06, 0x32, 0xd6, 0xc2, 0x1c, 0x81, 0x8c, 0xa6, 0xf4, 0xa7,
        0xf8, 0xda, 0xb4, 0x4b, 0xd2, 0x49, 0x17, 0xd6, 0x6c, 0x19, 0xe3, 0xa1, 0xbd, 0xe3, 0x5a,
        0x99,
    ];

    let private_key = PrivateDecryptingKey::from_pkcs8(PRIVATE_KEY).expect("private key");
    let private_key = Pkcs1PrivateDecryptingKey::new(private_key).expect("private key");

    let mut plaintext = vec![0u8; private_key.min_output_size()];

    let plaintext = private_key
        .decrypt(CIPHERTEXT, &mut plaintext)
        .expect("decrypt");

    assert_eq!(EXPECTED_MESSAGE, plaintext);
}
