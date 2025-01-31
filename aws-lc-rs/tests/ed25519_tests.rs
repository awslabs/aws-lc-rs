// Copyright 2015-2017 Brian Smith.
// SPDX-License-Identifier: ISC
// Modifications copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

use aws_lc_rs::encoding::{AsBigEndian, Curve25519SeedBin};
use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{self, Ed25519KeyPair, KeyPair};
use aws_lc_rs::{error, test, test_file};

#[test]
fn test_ed25519_traits() {
    test::compile_time_assert_send::<Ed25519KeyPair>();
    test::compile_time_assert_sync::<Ed25519KeyPair>();
}

/// Test vectors from `BoringSSL`.
#[test]
fn test_signature_ed25519() {
    test::run(
        test_file!("data/ed25519_tests.txt"),
        |section, test_case| {
            assert_eq!(section, "");
            let seed = test_case.consume_bytes("SEED");
            assert_eq!(32, seed.len());

            let public_key = test_case.consume_bytes("PUB");
            assert_eq!(32, public_key.len());

            let msg = test_case.consume_bytes("MESSAGE");

            let expected_sig = test_case.consume_bytes("SIG");

            let key_pair = Ed25519KeyPair::from_seed_unchecked(&seed).unwrap();
            let actual_sig = key_pair.sign(&msg);
            assert_eq!(&expected_sig[..], actual_sig.as_ref());

            let key_pair = Ed25519KeyPair::from_seed_and_public_key(&seed, &public_key).unwrap();
            let actual_sig = key_pair.sign(&msg);
            assert_eq!(&expected_sig[..], actual_sig.as_ref());

            // Test Signature verification.
            test_signature_verification(&public_key, &msg, &expected_sig, Ok(()));

            let mut tampered_sig = expected_sig;
            tampered_sig[0] ^= 1;

            test_signature_verification(&public_key, &msg, &tampered_sig, Err(error::Unspecified));

            Ok(())
        },
    );
}

/// Test vectors from `BoringSSL`.
#[test]
fn test_signature_ed25519_verify() {
    test::run(
        test_file!("data/ed25519_verify_tests.txt"),
        |section, test_case| {
            assert_eq!(section, "");

            let public_key = test_case.consume_bytes("PUB");
            let msg = test_case.consume_bytes("MESSAGE");
            let sig = test_case.consume_bytes("SIG");
            let expected_result = match test_case.consume_string("Result").as_str() {
                "P" => Ok(()),
                "F" => Err(error::Unspecified),
                s => panic!("{s:?} is not a valid result"),
            };
            test_signature_verification(&public_key, &msg, &sig, expected_result);
            Ok(())
        },
    );
}
fn test_signature_verification(
    public_key: &[u8],
    msg: &[u8],
    sig: &[u8],
    expected_result: Result<(), error::Unspecified>,
) {
    assert_eq!(
        expected_result,
        signature::UnparsedPublicKey::new(&signature::ED25519, public_key).verify(msg, sig)
    );
}

#[test]
fn test_ed25519_from_seed_and_public_key_misuse() {
    const PRIVATE_KEY: &[u8] = include_bytes!("data/ed25519_test_private_key.bin");
    const PUBLIC_KEY: &[u8] = include_bytes!("data/ed25519_test_public_key.bin");

    assert!(Ed25519KeyPair::from_seed_and_public_key(PRIVATE_KEY, PUBLIC_KEY).is_ok());

    // Truncated private key.
    assert!(Ed25519KeyPair::from_seed_and_public_key(&PRIVATE_KEY[..31], PUBLIC_KEY).is_err());

    // Truncated public key.
    assert!(Ed25519KeyPair::from_seed_and_public_key(PRIVATE_KEY, &PUBLIC_KEY[..31]).is_err());

    // Swapped public and private key.
    assert!(Ed25519KeyPair::from_seed_and_public_key(PUBLIC_KEY, PRIVATE_KEY).is_err());

    // From a private seed
    assert!(Ed25519KeyPair::from_seed_unchecked(PRIVATE_KEY).is_ok());

    // From a truncated private seed
    assert!(Ed25519KeyPair::from_seed_unchecked(PRIVATE_KEY).is_ok());
}

#[test]
fn test_ed25519_from_pkcs8() {
    fn check_result(
        input: &Vec<u8>,
        result: Result<Ed25519KeyPair, error::KeyRejected>,
        error: Option<String>,
    ) {
        match (result, error) {
            (Ok(_), None) => (),
            (Err(e), None) => panic!(
                "Failed with error \"{}\", but expected to succeed: \"{}\"",
                e,
                test::to_hex(input)
            ),
            (Ok(_), Some(e)) => panic!(
                "Succeeded, but expected error \"{}\": {}",
                e,
                test::to_hex(input)
            ),
            (Err(actual), Some(expected)) => {
                assert_eq!(
                    actual.description_(),
                    expected,
                    "Input: {}",
                    test::to_hex(input)
                );
            }
        }
    }

    // Just test that we can parse the input.
    test::run(
        test_file!("data/ed25519_from_pkcs8_tests.txt"),
        |section, test_case| {
            assert_eq!(section, "");
            let input = test_case.consume_bytes("Input");
            let error = test_case.consume_optional_string("Error");

            check_result(&input, Ed25519KeyPair::from_pkcs8(&input), error);

            Ok(())
        },
    );

    // Just test that we can parse the input.
    test::run(
        test_file!("data/ed25519_from_pkcs8_tests.txt"),
        |section, test_case| {
            assert_eq!(section, "");
            let input = test_case.consume_bytes("Input");
            let error = test_case.consume_optional_string("Error");

            check_result(
                &input,
                Ed25519KeyPair::from_pkcs8_maybe_unchecked(&input),
                error,
            );

            Ok(())
        },
    );
}

#[test]
fn ed25519_test_public_key_coverage() {
    const PRIVATE_KEY: &[u8] = include_bytes!("data/ed25519_test_private_key.p8");
    const PUBLIC_KEY: &[u8] = include_bytes!("data/ed25519_test_public_key.der");
    const PUBLIC_KEY_DEBUG: &str =
        "PublicKey(\"0590d26d769c711c3d8cbffc41f5b4665d63feb3d17765c3b630d50bf5c188fb\")";

    let key_pair = Ed25519KeyPair::from_pkcs8_maybe_unchecked(PRIVATE_KEY).unwrap();

    // Test `AsRef<[u8]>`
    assert_eq!(key_pair.public_key().as_ref(), PUBLIC_KEY);

    // Test `Clone`.
    #[allow(clippy::clone_on_copy)]
    let _: <Ed25519KeyPair as KeyPair>::PublicKey = key_pair.public_key().clone();

    // Test `Copy`.
    let _: <Ed25519KeyPair as KeyPair>::PublicKey = *key_pair.public_key();

    // Test `Debug`.
    assert_eq!(PUBLIC_KEY_DEBUG, format!("{:?}", key_pair.public_key()));
    assert_eq!(
        format!(
            "Ed25519KeyPair {{ public_key: {:?} }}",
            key_pair.public_key()
        ),
        format!("{key_pair:?}")
    );
}

#[test]
fn test_to_pkcs8() {
    let rnd = SystemRandom::new();
    let key_pair_doc = Ed25519KeyPair::generate_pkcs8(&rnd).unwrap();
    let key_pair = Ed25519KeyPair::from_pkcs8(key_pair_doc.as_ref()).unwrap();

    let key_pair_export_doc = key_pair.to_pkcs8().unwrap();
    // Verify that the exported bytes match the original generated bytes
    assert_eq!(key_pair_doc.as_ref(), key_pair_export_doc.as_ref());
}

#[test]
fn test_to_pkcs8v1() {
    let rnd = SystemRandom::new();
    let key_pair_doc = Ed25519KeyPair::generate_pkcs8v1(&rnd).unwrap();
    let key_pair = Ed25519KeyPair::from_pkcs8(key_pair_doc.as_ref()).unwrap();

    let key_pair_export_doc = key_pair.to_pkcs8v1().unwrap();
    // Verify that the exported bytes match the original generated bytes
    assert_eq!(key_pair_doc.as_ref(), key_pair_export_doc.as_ref());
}

#[test]
fn test_seed() {
    let rnd = SystemRandom::new();
    let key_pair_doc = Ed25519KeyPair::generate_pkcs8(&rnd).unwrap();

    let key_pair = Ed25519KeyPair::from_pkcs8(key_pair_doc.as_ref()).unwrap();
    let seed = key_pair.seed().unwrap();
    let seed_buffer: Curve25519SeedBin = seed.as_be_bytes().unwrap();

    let pub_key = key_pair.public_key();

    let key_pair_copy =
        Ed25519KeyPair::from_seed_and_public_key(seed_buffer.as_ref(), pub_key.as_ref()).unwrap();
    let key_pair_copy_doc = key_pair_copy.to_pkcs8().unwrap();

    assert_eq!(key_pair_doc.as_ref(), key_pair_copy_doc.as_ref());

    let key_pair_seed_copy = Ed25519KeyPair::from_seed_unchecked(seed_buffer.as_ref()).unwrap();
    let key_pair_seed_copy_doc = key_pair_seed_copy.to_pkcs8().unwrap();

    assert_eq!(key_pair_doc.as_ref(), key_pair_seed_copy_doc.as_ref());
}
