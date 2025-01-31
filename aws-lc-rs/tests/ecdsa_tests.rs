// Copyright 2015-2016 Brian Smith.
// SPDX-License-Identifier: ISC
// Modifications copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

use aws_lc_rs::encoding::{AsBigEndian, AsDer, EcPrivateKeyRfc5915Der};
use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{self, EcdsaKeyPair, KeyPair, Signature, UnparsedPublicKey};
use aws_lc_rs::{test, test_file};

#[test]
fn ecdsa_traits() {
    test::compile_time_assert_send::<EcdsaKeyPair>();
    test::compile_time_assert_sync::<EcdsaKeyPair>();
    test::compile_time_assert_send::<Signature>();
    test::compile_time_assert_sync::<Signature>();
    test::compile_time_assert_send::<UnparsedPublicKey<&[u8]>>();
    test::compile_time_assert_sync::<UnparsedPublicKey<&[u8]>>();
    test::compile_time_assert_send::<UnparsedPublicKey<Vec<u8>>>();
    test::compile_time_assert_sync::<UnparsedPublicKey<Vec<u8>>>();
}

#[test]
fn ecdsa_from_pkcs8_test() {
    test::run(
        test_file!("data/ecdsa_from_pkcs8_tests.txt"),
        |section, test_case| {
            assert_eq!(section, "");

            let curve_name = test_case.consume_string("Curve");
            let ((this_fixed, this_asn1), (other_fixed, other_asn1)) = match curve_name.as_str() {
                "P-256" => (
                    (
                        &signature::ECDSA_P256_SHA256_FIXED_SIGNING,
                        &signature::ECDSA_P256_SHA256_ASN1_SIGNING,
                    ),
                    (
                        &signature::ECDSA_P384_SHA384_FIXED_SIGNING,
                        &signature::ECDSA_P384_SHA384_ASN1_SIGNING,
                    ),
                ),
                "P-384" => (
                    (
                        &signature::ECDSA_P384_SHA384_FIXED_SIGNING,
                        &signature::ECDSA_P384_SHA384_ASN1_SIGNING,
                    ),
                    (
                        &signature::ECDSA_P256_SHA256_FIXED_SIGNING,
                        &signature::ECDSA_P256_SHA256_ASN1_SIGNING,
                    ),
                ),
                "P-521" => (
                    (
                        &signature::ECDSA_P521_SHA512_FIXED_SIGNING,
                        &signature::ECDSA_P521_SHA512_ASN1_SIGNING,
                    ),
                    (
                        &signature::ECDSA_P384_SHA384_FIXED_SIGNING,
                        &signature::ECDSA_P384_SHA384_ASN1_SIGNING,
                    ),
                ),
                _ => unreachable!(),
            };

            let input = test_case.consume_bytes("Input");

            let error = test_case.consume_optional_string("Error");

            match (EcdsaKeyPair::from_pkcs8(this_fixed, &input), error.clone()) {
                (Ok(_), None) => (),
                (Err(e), None) => panic!(
                    "Failed with error \"{}\", but expected to succeed. Input: {}",
                    e,
                    test::to_hex(&input)
                ),
                (Ok(_), Some(e)) => panic!(
                    "Succeeded, but expected error \"{}\" - Input: {}",
                    e,
                    test::to_hex(&input)
                ),
                (Err(actual), Some(expected)) => assert_eq!(
                    format!("{actual}"),
                    expected,
                    "Input: {}",
                    test::to_hex(&input)
                ),
            }

            match (EcdsaKeyPair::from_pkcs8(this_asn1, &input), error) {
                (Ok(_), None) => (),
                (Err(e), None) => {
                    panic!("Failed with error \"{e}\", but expected to succeed");
                }
                (Ok(_), Some(e)) => panic!("Succeeded, but expected error \"{e}\""),
                (Err(actual), Some(expected)) => assert_eq!(format!("{actual}"), expected),
            }

            assert!(
                EcdsaKeyPair::from_pkcs8(other_fixed, &input).is_err(),
                "Input: {}",
                test::to_hex(&input)
            );
            assert!(
                EcdsaKeyPair::from_pkcs8(other_asn1, &input).is_err(),
                "Input: {}",
                test::to_hex(&input)
            );

            Ok(())
        },
    );
}

// Verify that, at least, we generate PKCS#8 documents that we can read.
#[test]
fn ecdsa_generate_pkcs8_test() {
    let rng = SystemRandom::new();

    for alg in &[
        &signature::ECDSA_P256_SHA256_ASN1_SIGNING,
        &signature::ECDSA_P256_SHA256_FIXED_SIGNING,
        &signature::ECDSA_P384_SHA384_ASN1_SIGNING,
        &signature::ECDSA_P384_SHA384_FIXED_SIGNING,
        &signature::ECDSA_P384_SHA3_384_ASN1_SIGNING,
        &signature::ECDSA_P384_SHA3_384_FIXED_SIGNING,
        &signature::ECDSA_P521_SHA512_FIXED_SIGNING,
        &signature::ECDSA_P521_SHA512_ASN1_SIGNING,
        &signature::ECDSA_P521_SHA3_512_FIXED_SIGNING,
        &signature::ECDSA_P521_SHA3_512_ASN1_SIGNING,
        &signature::ECDSA_P256K1_SHA256_ASN1_SIGNING,
        &signature::ECDSA_P256K1_SHA256_FIXED_SIGNING,
        &signature::ECDSA_P256K1_SHA3_256_ASN1_SIGNING,
        &signature::ECDSA_P256K1_SHA3_256_FIXED_SIGNING,
    ] {
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(alg, &rng).unwrap();
        println!();
        for b in pkcs8.as_ref() {
            print!("{:02x}", *b);
        }
        println!();
        println!();

        EcdsaKeyPair::from_pkcs8(alg, pkcs8.as_ref()).unwrap();
    }
}

#[test]
fn signature_ecdsa_verify_asn1_test() {
    test_signature_ecdsa_verify_asn1(test_file!("data/ecdsa_verify_asn1_tests.txt"));
}

#[test]
fn signature_ecdsa_verify_asn1_sha3_test() {
    test_signature_ecdsa_verify_asn1(test_file!("data/ecdsa_verify_asn1_sha3_tests.txt"));
}

fn test_signature_ecdsa_verify_asn1(data_file: test::File) {
    test::run(data_file, |section, test_case| {
        assert_eq!(section, "");

        let curve_name = test_case.consume_string("Curve");
        let digest_name = test_case.consume_string("Digest");
        let msg = test_case.consume_bytes("Msg");
        let public_key = test_case.consume_bytes("Q");
        let sig = test_case.consume_bytes("Sig");
        let is_valid = test_case.consume_string("Result") == "P (0 )";

        let alg = match (curve_name.as_str(), digest_name.as_str()) {
            ("P-256", "SHA256") => &signature::ECDSA_P256_SHA256_ASN1,
            ("P-256", "SHA384") => &signature::ECDSA_P256_SHA384_ASN1,
            ("P-384", "SHA256") => &signature::ECDSA_P384_SHA256_ASN1,
            ("P-384", "SHA384") => &signature::ECDSA_P384_SHA384_ASN1,
            ("P-384", "SHA3-384") => &signature::ECDSA_P384_SHA3_384_ASN1,
            ("P-521", "SHA1") => &signature::ECDSA_P521_SHA1_ASN1,
            ("P-521", "SHA224") => &signature::ECDSA_P521_SHA224_ASN1,
            ("P-521", "SHA256") => &signature::ECDSA_P521_SHA256_ASN1,
            ("P-521", "SHA384") => &signature::ECDSA_P521_SHA384_ASN1,
            ("P-521", "SHA512") => &signature::ECDSA_P521_SHA512_ASN1,
            ("P-521", "SHA3-512") => &signature::ECDSA_P521_SHA3_512_ASN1,
            ("secp256k1", "SHA256") => &signature::ECDSA_P256K1_SHA256_ASN1,
            ("secp256k1", "SHA3-256") => &signature::ECDSA_P256K1_SHA3_256_ASN1,
            _ => {
                panic!("Unsupported curve+digest: {curve_name}+{digest_name}");
            }
        };

        let actual_result = UnparsedPublicKey::new(alg, &public_key).verify(&msg, &sig);
        assert_eq!(actual_result.is_ok(), is_valid);

        Ok(())
    });
}

#[test]
fn signature_ecdsa_verify_fixed_test() {
    test_signature_ecdsa_verify_fixed(test_file!("data/ecdsa_verify_fixed_tests.txt"));
}

#[test]
fn signature_ecdsa_verify_sha3_fixed_test() {
    test_signature_ecdsa_verify_fixed(test_file!("data/ecdsa_verify_fixed_sha3_tests.txt"));
}

fn test_signature_ecdsa_verify_fixed(data_file: test::File) {
    test::run(data_file, |section, test_case| {
        assert_eq!(section, "");

        let curve_name = test_case.consume_string("Curve");
        let digest_name = test_case.consume_string("Digest");

        let msg = test_case.consume_bytes("Msg");
        let public_key = test_case.consume_bytes("Q");
        let sig = test_case.consume_bytes("Sig");
        let expected_result = test_case.consume_string("Result");

        let alg = match (curve_name.as_str(), digest_name.as_str()) {
            ("P-256", "SHA256") => &signature::ECDSA_P256_SHA256_FIXED,
            ("P-384", "SHA384") => &signature::ECDSA_P384_SHA384_FIXED,
            ("P-384", "SHA3-384") => &signature::ECDSA_P384_SHA3_384_FIXED,
            ("P-521", "SHA1") => &signature::ECDSA_P521_SHA1_FIXED,
            ("P-521", "SHA224") => &signature::ECDSA_P521_SHA224_FIXED,
            ("P-521", "SHA256") => &signature::ECDSA_P521_SHA256_FIXED,
            ("P-521", "SHA384") => &signature::ECDSA_P521_SHA384_FIXED,
            ("P-521", "SHA512") => &signature::ECDSA_P521_SHA512_FIXED,
            ("P-521", "SHA3-512") => &signature::ECDSA_P521_SHA3_512_FIXED,
            ("secp256k1", "SHA256") => &signature::ECDSA_P256K1_SHA256_FIXED,
            ("secp256k1", "SHA3-256") => &signature::ECDSA_P256K1_SHA3_256_FIXED,
            _ => {
                panic!("Unsupported curve+digest: {curve_name}+{digest_name}");
            }
        };

        let is_valid = expected_result == "P (0 )";

        let actual_result = UnparsedPublicKey::new(alg, &public_key).verify(&msg, &sig);
        assert_eq!(actual_result.is_ok(), is_valid);

        Ok(())
    });
}

#[test]
fn ecdsa_test_public_key_coverage() {
    const PRIVATE_KEY: &[u8] = include_bytes!("data/ecdsa_test_private_key_p256.p8");
    const PUBLIC_KEY: &[u8] = include_bytes!("data/ecdsa_test_public_key_p256.der");
    const PUBLIC_KEY_DEBUG: &str = include_str!("data/ecdsa_test_public_key_p256_debug.txt");

    let key_pair =
        EcdsaKeyPair::from_pkcs8(&signature::ECDSA_P256_SHA256_FIXED_SIGNING, PRIVATE_KEY).unwrap();

    // Test `AsRef<[u8]>`
    assert_eq!(key_pair.public_key().as_ref(), PUBLIC_KEY);

    // Test `Clone`.
    #[allow(let_underscore_drop, clippy::let_underscore_untyped)]
    let _ = key_pair.public_key().clone();

    // Test `Copy`.
    #[allow(let_underscore_drop)]
    let _: <EcdsaKeyPair as KeyPair>::PublicKey = *key_pair.public_key();

    // Test `Debug`.
    assert_eq!(PUBLIC_KEY_DEBUG, format!("{:?}", key_pair.public_key()));
    assert_eq!(
        format!("EcdsaKeyPair {{ public_key: {:?} }}", key_pair.public_key()),
        format!("{key_pair:?}")
    );
}

#[test]
fn signature_ecdsa_sign_fixed_sign_and_verify_test() {
    test_signature_ecdsa_sign_fixed_sign_and_verify(test_file!("data/ecdsa_sign_fixed_tests.txt"));
}

#[test]
fn signature_ecdsa_sign_fixed_sign_and_verify_sha3_test() {
    test_signature_ecdsa_sign_fixed_sign_and_verify(test_file!(
        "data/ecdsa_sign_fixed_sha3_tests.txt"
    ));
}

// This test is not a known-answer test, though it re-uses the known-answer
// test vectors. Because the nonce is randomized, the signature will be
// different each time. Because of that, here we simply verify that the
// signature verifies correctly.
fn test_signature_ecdsa_sign_fixed_sign_and_verify(data_file: test::File) {
    let rng = SystemRandom::new();

    test::run(data_file, |section, test_case| {
        assert_eq!(section, "");

        let curve_name = test_case.consume_string("Curve");
        let digest_name = test_case.consume_string("Digest");

        let msg = test_case.consume_bytes("Msg");
        let d = test_case.consume_bytes("d");
        let q = test_case.consume_bytes("Q");

        // Ignored since the actual signature will use a randomized nonce.
        let _k = test_case.consume_optional_bytes("k");
        let _expected_result = test_case.consume_bytes("Sig");

        let (signing_alg, verification_alg) = match (curve_name.as_str(), digest_name.as_str()) {
            ("P-256", "SHA256") => (
                &signature::ECDSA_P256_SHA256_FIXED_SIGNING,
                &signature::ECDSA_P256_SHA256_FIXED,
            ),
            ("P-384", "SHA384") => (
                &signature::ECDSA_P384_SHA384_FIXED_SIGNING,
                &signature::ECDSA_P384_SHA384_FIXED,
            ),
            ("P-384", "SHA3-384") => (
                &signature::ECDSA_P384_SHA3_384_FIXED_SIGNING,
                &signature::ECDSA_P384_SHA3_384_FIXED,
            ),
            ("P-521", "SHA224") => (
                &signature::ECDSA_P521_SHA224_FIXED_SIGNING,
                &signature::ECDSA_P521_SHA224_FIXED,
            ),
            ("P-521", "SHA256") => (
                &signature::ECDSA_P521_SHA256_FIXED_SIGNING,
                &signature::ECDSA_P521_SHA256_FIXED,
            ),
            ("P-521", "SHA384") => (
                &signature::ECDSA_P521_SHA384_FIXED_SIGNING,
                &signature::ECDSA_P521_SHA384_FIXED,
            ),
            ("P-521", "SHA512") => (
                &signature::ECDSA_P521_SHA512_FIXED_SIGNING,
                &signature::ECDSA_P521_SHA512_FIXED,
            ),
            ("P-521", "SHA3-512") => (
                &signature::ECDSA_P521_SHA3_512_FIXED_SIGNING,
                &signature::ECDSA_P521_SHA3_512_FIXED,
            ),
            ("secp256k1", "SHA256") => (
                &signature::ECDSA_P256K1_SHA256_FIXED_SIGNING,
                &signature::ECDSA_P256K1_SHA256_FIXED,
            ),
            ("secp256k1", "SHA3-256") => (
                &signature::ECDSA_P256K1_SHA3_256_FIXED_SIGNING,
                &signature::ECDSA_P256K1_SHA3_256_FIXED,
            ),
            _ => {
                panic!("Unsupported curve+digest: {curve_name}+{digest_name}");
            }
        };

        let private_key =
            EcdsaKeyPair::from_private_key_and_public_key(signing_alg, &d, &q).unwrap();

        let signature = private_key.sign(&rng, &msg).unwrap();

        let public_key = UnparsedPublicKey::new(verification_alg, q);
        let vfy_result = public_key.verify(&msg, signature.as_ref());
        assert!(vfy_result.is_ok());

        Ok(())
    });
}

#[test]
fn signature_ecdsa_sign_asn1_test() {
    test_signature_ecdsa_sign_asn1(test_file!("data/ecdsa_sign_asn1_tests.txt"));
}

#[test]
fn signature_ecdsa_sign_asn1_sha3_test() {
    test_signature_ecdsa_sign_asn1(test_file!("data/ecdsa_sign_asn1_sha3_tests.txt"));
}

// This test is not a known-answer test, though it re-uses the known-answer
// test vectors. Because the nonce is randomized, the signature will be
// different each time. Because of that, here we simply verify that the
// signature verifies correctly.
fn test_signature_ecdsa_sign_asn1(data_file: test::File) {
    let rng = SystemRandom::new();

    test::run(data_file, |section, test_case| {
        assert_eq!(section, "");

        let curve_name = test_case.consume_string("Curve");
        let digest_name = test_case.consume_string("Digest");

        let msg = test_case.consume_bytes("Msg");
        let d = test_case.consume_bytes("d");
        let q = test_case.consume_bytes("Q");

        // Ignored since the actual signature will use a randomized nonce.
        let _k = test_case.consume_optional_bytes("k");
        let _expected_result = test_case.consume_bytes("Sig");

        let (signing_alg, verification_alg) = match (curve_name.as_str(), digest_name.as_str()) {
            ("P-256", "SHA256") => (
                &signature::ECDSA_P256_SHA256_ASN1_SIGNING,
                &signature::ECDSA_P256_SHA256_ASN1,
            ),
            ("P-384", "SHA384") => (
                &signature::ECDSA_P384_SHA384_ASN1_SIGNING,
                &signature::ECDSA_P384_SHA384_ASN1,
            ),
            ("P-384", "SHA3-384") => (
                &signature::ECDSA_P384_SHA3_384_ASN1_SIGNING,
                &signature::ECDSA_P384_SHA3_384_ASN1,
            ),
            ("P-521", "SHA224") => (
                &signature::ECDSA_P521_SHA224_ASN1_SIGNING,
                &signature::ECDSA_P521_SHA224_ASN1,
            ),
            ("P-521", "SHA256") => (
                &signature::ECDSA_P521_SHA256_ASN1_SIGNING,
                &signature::ECDSA_P521_SHA256_ASN1,
            ),
            ("P-521", "SHA384") => (
                &signature::ECDSA_P521_SHA384_ASN1_SIGNING,
                &signature::ECDSA_P521_SHA384_ASN1,
            ),
            ("P-521", "SHA512") => (
                &signature::ECDSA_P521_SHA512_ASN1_SIGNING,
                &signature::ECDSA_P521_SHA512_ASN1,
            ),
            ("P-521", "SHA3-512") => (
                &signature::ECDSA_P521_SHA3_512_ASN1_SIGNING,
                &signature::ECDSA_P521_SHA3_512_ASN1,
            ),
            ("secp256k1", "SHA256") => (
                &signature::ECDSA_P256K1_SHA256_ASN1_SIGNING,
                &signature::ECDSA_P256K1_SHA256_ASN1,
            ),
            ("secp256k1", "SHA3-256") => (
                &signature::ECDSA_P256K1_SHA3_256_ASN1_SIGNING,
                &signature::ECDSA_P256K1_SHA3_256_ASN1,
            ),
            _ => {
                panic!("Unsupported curve+digest: {curve_name}+{digest_name}");
            }
        };

        let private_key =
            EcdsaKeyPair::from_private_key_and_public_key(signing_alg, &d, &q).unwrap();

        let signature = private_key.sign(&rng, &msg).unwrap();

        let public_key = UnparsedPublicKey::new(verification_alg, q);
        assert_eq!(public_key.verify(&msg, signature.as_ref()), Ok(()));

        Ok(())
    });
}

#[test]
fn test_to_pkcs8() {
    for signing_alg in [
        &signature::ECDSA_P521_SHA3_512_ASN1_SIGNING,
        &signature::ECDSA_P521_SHA3_512_FIXED_SIGNING,
        &signature::ECDSA_P521_SHA512_ASN1_SIGNING,
        &signature::ECDSA_P521_SHA512_FIXED_SIGNING,
        &signature::ECDSA_P384_SHA3_384_ASN1_SIGNING,
        &signature::ECDSA_P384_SHA3_384_FIXED_SIGNING,
        &signature::ECDSA_P384_SHA384_ASN1_SIGNING,
        &signature::ECDSA_P384_SHA384_FIXED_SIGNING,
        &signature::ECDSA_P256_SHA256_ASN1_SIGNING,
        &signature::ECDSA_P256_SHA256_FIXED_SIGNING,
    ] {
        let rnd = SystemRandom::new();
        let key_pair_doc = EcdsaKeyPair::generate_pkcs8(signing_alg, &rnd).unwrap();
        let key_pair = EcdsaKeyPair::from_pkcs8(signing_alg, key_pair_doc.as_ref()).unwrap();

        let key_pair_export_doc = key_pair.to_pkcs8v1().unwrap();
        // Verify that the exported bytes match the original generated bytes
        assert_eq!(key_pair_doc.as_ref(), key_pair_export_doc.as_ref());
    }
}

#[test]
fn test_private_key() {
    for signing_alg in [
        &signature::ECDSA_P521_SHA3_512_ASN1_SIGNING,
        &signature::ECDSA_P521_SHA3_512_FIXED_SIGNING,
        &signature::ECDSA_P521_SHA512_ASN1_SIGNING,
        &signature::ECDSA_P521_SHA512_FIXED_SIGNING,
        &signature::ECDSA_P384_SHA3_384_ASN1_SIGNING,
        &signature::ECDSA_P384_SHA3_384_FIXED_SIGNING,
        &signature::ECDSA_P384_SHA384_ASN1_SIGNING,
        &signature::ECDSA_P384_SHA384_FIXED_SIGNING,
        &signature::ECDSA_P256_SHA256_ASN1_SIGNING,
        &signature::ECDSA_P256_SHA256_FIXED_SIGNING,
    ] {
        let rnd = SystemRandom::new();
        let key_pair_doc = EcdsaKeyPair::generate_pkcs8(signing_alg, &rnd).unwrap();
        let key_pair = EcdsaKeyPair::from_pkcs8(signing_alg, key_pair_doc.as_ref()).unwrap();

        {
            let private_key = key_pair.private_key().as_be_bytes().unwrap();
            let public_key = key_pair.public_key();
            let key_pair_copy = EcdsaKeyPair::from_private_key_and_public_key(
                signing_alg,
                private_key.as_ref(),
                public_key.as_ref(),
            )
            .unwrap();
            let key_pair_copy_doc = key_pair_copy.to_pkcs8v1().unwrap();
            assert_eq!(key_pair_doc.as_ref(), key_pair_copy_doc.as_ref());
        }
        {
            let private_key_der: EcPrivateKeyRfc5915Der = key_pair.private_key().as_der().unwrap();
            assert_eq!("EcPrivateKeyRfc5915Der", format!("{private_key_der:?}"));
            assert!(EcdsaKeyPair::from_pkcs8(signing_alg, private_key_der.as_ref()).is_err());

            let key_pair_copy =
                EcdsaKeyPair::from_private_key_der(signing_alg, private_key_der.as_ref()).unwrap();
            let key_pair_copy_doc = key_pair_copy.to_pkcs8v1().unwrap();
            assert_eq!(key_pair_doc.as_ref(), key_pair_copy_doc.as_ref());
        }
    }
}
