// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

use aws_lc_rs::{
    digest::{SHA1_OUTPUT_LEN, SHA224_OUTPUT_LEN, SHA256_OUTPUT_LEN, SHA512_OUTPUT_LEN},
    hmac::{
        sign, verify, Key, HMAC_SHA1_FOR_LEGACY_USE_ONLY, HMAC_SHA224, HMAC_SHA256, HMAC_SHA384,
        HMAC_SHA512,
    },
    rand::{self, SystemRandom},
    FipsServiceStatus,
};

use crate::common::{assert_fips_status_indicator, TEST_MESSAGE};

macro_rules! hmac_api {
    ($name:ident, $alg:expr, $out_len:expr) => {
        #[test]
        fn $name() {
            let rng = SystemRandom::new();

            let key_value: [u8; $out_len] = rand::generate(&rng).unwrap().expose();

            let s_key = Key::new($alg, key_value.as_ref());

            let tag = assert_fips_status_indicator!(
                sign(&s_key, TEST_MESSAGE.as_bytes()),
                FipsServiceStatus::ApprovedMode
            );

            let v_key = Key::new($alg, key_value.as_ref());

            assert_fips_status_indicator!(
                verify(&v_key, TEST_MESSAGE.as_bytes(), tag.as_ref()).unwrap(),
                FipsServiceStatus::ApprovedMode
            );
        }
    };
}

hmac_api!(sha1, HMAC_SHA1_FOR_LEGACY_USE_ONLY, SHA1_OUTPUT_LEN);
hmac_api!(sha224, HMAC_SHA224, SHA224_OUTPUT_LEN);
hmac_api!(sha256, HMAC_SHA256, SHA256_OUTPUT_LEN);
hmac_api!(sha384, HMAC_SHA384, SHA256_OUTPUT_LEN);
hmac_api!(sha512, HMAC_SHA512, SHA512_OUTPUT_LEN);
