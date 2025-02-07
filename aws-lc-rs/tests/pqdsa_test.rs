// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC
#![cfg(all(not(feature = "fips"), feature = "unstable"))]

use aws_lc_rs::signature::{KeyPair, VerificationAlgorithm};
use aws_lc_rs::unstable::signature::{
    PqdsaKeyPair, MLDSA_44, MLDSA_44_SIGNING, MLDSA_65, MLDSA_65_SIGNING, MLDSA_87,
    MLDSA_87_SIGNING,
};
use aws_lc_rs::{test, test_file};

macro_rules! mldsa_keygen_test {
    ($file:literal, $signing:expr) => {
        test::run(test_file!($file), |section, test_case| {
            assert_eq!(section, "");
            let seed = test_case.consume_bytes("SEED");
            let public = test_case.consume_bytes("PUBLIC");
            let secret = test_case.consume_bytes("SECRET");

            let key_pair_seed = PqdsaKeyPair::from_raw_seed($signing, seed.as_slice())?;
            let key_pair_secret = PqdsaKeyPair::from_raw_private_key($signing, secret.as_slice())?;
            let public_seed = key_pair_seed.public_key();
            let public_secret = key_pair_secret.public_key();
            assert_eq!(public_seed.as_ref(), public_secret.as_ref());
            assert_eq!(public_seed.as_ref(), public.as_slice());

            Ok(())
        });
    };
}

macro_rules! mldsa_sigver_test {
    ($file:literal, $verification:expr) => {
        test::run(test_file!($file), |section, test_case| {
            assert_eq!(section, "");
            let public_key = test_case.consume_bytes("PUBLIC");
            let message = test_case.consume_bytes("MESSAGE");
            let signature = test_case.consume_bytes("SIGNATURE");
            let context = test_case.consume_bytes("CONTEXT");
            let expected_result = test_case.consume_bool("RESULT");

            if !context.is_empty() {
                // skip test
                return Ok(());
            }

            let result =
                $verification.verify_sig(public_key.as_ref(), message.as_ref(), signature.as_ref());
            if expected_result {
                assert!(result.is_ok());
            } else {
                assert!(result.is_err());
            }

            Ok(())
        });
    };
}

#[test]
fn mldsa_44_keygen_test() {
    mldsa_keygen_test!("data/MLDSA_44_ACVP_keyGen.txt", &MLDSA_44_SIGNING);
}

#[test]
fn mldsa_65_keygen_test() {
    mldsa_keygen_test!("data/MLDSA_65_ACVP_keyGen.txt", &MLDSA_65_SIGNING);
}

#[test]
fn mldsa_87_keygen_test() {
    mldsa_keygen_test!("data/MLDSA_87_ACVP_keyGen.txt", &MLDSA_87_SIGNING);
}

#[test]
fn mldsa_44_sigver_test() {
    mldsa_sigver_test!("data/MLDSA_44_sigVer.txt", &MLDSA_44);
}

#[test]
fn mldsa_65_sigver_test() {
    mldsa_sigver_test!("data/MLDSA_65_sigVer.txt", &MLDSA_65);
}

#[test]
fn mldsa_87_sigver_test() {
    mldsa_sigver_test!("data/MLDSA_87_sigVer.txt", &MLDSA_87);
}
