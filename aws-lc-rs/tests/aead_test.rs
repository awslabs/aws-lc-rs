// Copyright 2015-2016 Brian Smith.
// SPDX-License-Identifier: ISC
// Modifications copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

use aws_lc_rs::aead::nonce_sequence::Counter32Builder;
use aws_lc_rs::{aead, error, test, test_file};

use aws_lc_rs::aead::{
    Aad, BoundKey, Nonce, OpeningKey, SealingKey, UnboundKey, AES_128_GCM, NONCE_LEN,
};
use core::ops::RangeFrom;

#[test]
fn aead_aes_gcm_128() {
    test_aead_all(
        &aead::AES_128_GCM,
        test_file!("data/aead_aes_128_gcm_tests.txt"),
    );
}

#[test]
fn aead_aes_gcm_192() {
    test_aead_all(
        &aead::AES_192_GCM,
        test_file!("data/aead_aes_192_gcm_tests.txt"),
    );
}

#[test]
fn aead_aes_gcm_256() {
    test_aead_all(
        &aead::AES_256_GCM,
        test_file!("data/aead_aes_256_gcm_tests.txt"),
    );
}

#[test]
fn aead_aes_gcm_siv_256() {
    test_aead_all(
        &aead::AES_256_GCM_SIV,
        test_file!("data/aes_256_gcm_siv_tests.txt"),
    );
}

#[test]
fn aead_aes_gcm_siv_128() {
    test_aead_all(
        &aead::AES_128_GCM_SIV,
        test_file!("data/aes_128_gcm_siv_tests.txt"),
    );
}

#[test]
fn aead_chacha20_poly1305() {
    test_aead_all(
        &aead::CHACHA20_POLY1305,
        test_file!("data/aead_chacha20_poly1305_tests.txt"),
    );
}

/// Tests all combinations of sealer and opener functions
fn test_aead_all(aead_alg: &'static aead::Algorithm, test_file: test::File) {
    let mut sealers = vec![seal_with_key, seal_with_less_safe_key];
    let mut openers = vec![open_with_key, open_with_less_safe_key];

    // SIV doesn't support scatter/gather APIs
    if !(aead_alg == &aead::AES_128_GCM_SIV || aead_alg == &aead::AES_256_GCM_SIV) {
        sealers.push(seal_with_less_safe_key_scatter);
        openers.push(open_with_less_safe_key_gather);
    }

    for seal in &sealers {
        for open in &openers {
            test_aead(aead_alg, seal, open, test_file);
        }
    }
}

#[allow(clippy::too_many_lines)]
fn test_aead<Seal, Open>(
    aead_alg: &'static aead::Algorithm,
    seal: Seal,
    open: Open,
    test_file: test::File,
) where
    Seal: Fn(
        &'static aead::Algorithm,
        &[u8],
        Nonce,
        aead::Aad<&[u8]>,
        &mut Vec<u8>,
    ) -> Result<(), error::Unspecified>,
    Open: for<'a> Fn(
        &'static aead::Algorithm,
        &[u8],
        Nonce,
        aead::Aad<&[u8]>,
        &'a mut [u8],
        RangeFrom<usize>,
    ) -> Result<&'a mut [u8], error::Unspecified>,
{
    // TLS record headers are 5 bytes long.
    // TLS explicit nonces for AES-GCM are 8 bytes long.
    static MINIMAL_IN_PREFIX_LENS: [usize; 36] = [
        // No input prefix to overwrite; i.e. the opening is exactly
        // "in place."
        0,
        1,
        2,
        // Proposed TLS 1.3 header (no explicit nonce).
        5,
        8,
        // Probably the most common use of a non-zero `in_prefix_len`
        // would be to write a decrypted TLS record over the top of the
        // TLS header and nonce.
        5 /* record header */ + 8, /* explicit nonce */
        // The stitched AES-GCM x86-64 code works on 6-block (96 byte)
        // units. Some of the ChaCha20 code is even weirder.
        15,  // The maximum partial AES block.
        16,  // One AES block.
        17,  // One byte more than a full AES block.
        31,  // 2 AES blocks or 1 ChaCha20 block, minus 1.
        32,  // Two AES blocks, one ChaCha20 block.
        33,  // 2 AES blocks or 1 ChaCha20 block, plus 1.
        47,  // Three AES blocks - 1.
        48,  // Three AES blocks.
        49,  // Three AES blocks + 1.
        63,  // Four AES blocks or two ChaCha20 blocks, minus 1.
        64,  // Four AES blocks or two ChaCha20 blocks.
        65,  // Four AES blocks or two ChaCha20 blocks, plus 1.
        79,  // Five AES blocks, minus 1.
        80,  // Five AES blocks.
        81,  // Five AES blocks, plus 1.
        95,  // Six AES blocks or three ChaCha20 blocks, minus 1.
        96,  // Six AES blocks or three ChaCha20 blocks.
        97,  // Six AES blocks or three ChaCha20 blocks, plus 1.
        111, // Seven AES blocks, minus 1.
        112, // Seven AES blocks.
        113, // Seven AES blocks, plus 1.
        127, // Eight AES blocks or four ChaCha20 blocks, minus 1.
        128, // Eight AES blocks or four ChaCha20 blocks.
        129, // Eight AES blocks or four ChaCha20 blocks, plus 1.
        143, // Nine AES blocks, minus 1.
        144, // Nine AES blocks.
        145, // Nine AES blocks, plus 1.
        255, // 16 AES blocks or 8 ChaCha20 blocks, minus 1.
        256, // 16 AES blocks or 8 ChaCha20 blocks.
        257, // 16 AES blocks or 8 ChaCha20 blocks, plus 1.
    ];

    test_aead_key_sizes(aead_alg);

    test::run(test_file, |section, test_case| {
        assert_eq!(section, "");
        let key_bytes = test_case.consume_bytes("KEY");
        let nonce_bytes = test_case.consume_bytes("NONCE");
        let plaintext = test_case.consume_bytes("IN");
        let aad = test_case.consume_bytes("AD");
        let mut ct = test_case.consume_bytes("CT");
        let tag = test_case.consume_bytes("TAG");
        let error = test_case.consume_optional_string("FAILS");

        match &error {
            Some(err) if err == "WRONG_NONCE_LENGTH" => {
                assert!(Nonce::try_assume_unique_for_key(&nonce_bytes).is_err());
                return Ok(());
            }
            _ => (),
        }

        let mut s_in_out = plaintext.clone();
        let nonce = Nonce::try_assume_unique_for_key(&nonce_bytes).unwrap();
        let s_result = seal(
            aead_alg,
            &key_bytes[..],
            nonce,
            aead::Aad::from(&aad[..]),
            &mut s_in_out,
        );

        ct.extend(tag);

        if s_result.is_ok() {
            assert_eq!(&ct, &s_in_out);
        }

        // In release builds, test all prefix lengths from 0 to 4096 bytes.
        // Debug builds are too slow for this, so for those builds, only
        // test a smaller subset.

        let mut more_comprehensive_in_prefix_lengths = vec![0; 4096].into_boxed_slice();
        let in_prefix_lengths = if cfg!(any(debug_assertions, disable_slow_tests)) {
            &MINIMAL_IN_PREFIX_LENS[..]
        } else {
            #[allow(clippy::needless_range_loop)]
            for b in 0..more_comprehensive_in_prefix_lengths.len() {
                more_comprehensive_in_prefix_lengths[b] = b;
            }
            &more_comprehensive_in_prefix_lengths[..]
        };
        let mut o_in_out = vec![123u8; 4096];

        for &in_prefix_len in in_prefix_lengths {
            o_in_out.truncate(0);
            o_in_out.resize(in_prefix_len, 123);
            o_in_out.extend_from_slice(&ct[..]);

            let o_in_out_clone = o_in_out.clone();
            let nonce = Nonce::try_assume_unique_for_key(&nonce_bytes).unwrap();
            let o_result = open(
                aead_alg,
                &key_bytes,
                nonce,
                aead::Aad::from(&aad[..]),
                &mut o_in_out,
                in_prefix_len..,
            );
            match error {
                None => {
                    assert!(s_result.is_ok());
                    assert!(o_result.is_ok(), "Not ok: {o_result:?}");
                    let result = o_result.unwrap();
                    assert_eq!(&plaintext[..], result);

                    for bad_func in [aead_open_bad_tag, aead_open_bad_nonce, aead_open_bad_aad] {
                        bad_func(
                            aead_alg,
                            &key_bytes,
                            &nonce_bytes,
                            aad.as_slice(),
                            &o_in_out_clone,
                            in_prefix_len,
                            &open,
                        );
                    }
                }
                Some(ref error) if error == "WRONG_NONCE_LENGTH" => {
                    assert_eq!(Err(error::Unspecified), s_result);
                    assert_eq!(Err(error::Unspecified), o_result);
                }
                Some(error) => {
                    panic!("Unexpected error test case: {error}");
                }
            }
        }

        Ok(())
    });
}

fn aead_open_bad_tag<Open>(
    aead_alg: &'static aead::Algorithm,
    key_bytes: &[u8],
    nonce_bytes: &[u8],
    aad_bytes: &[u8],
    in_out: &[u8],
    in_prefix_len: usize,
    open: Open,
) where
    Open: for<'a> Fn(
        &'static aead::Algorithm,
        &[u8],
        Nonce,
        aead::Aad<&[u8]>,
        &'a mut [u8],
        RangeFrom<usize>,
    ) -> Result<&'a mut [u8], error::Unspecified>,
{
    let mut in_out = Vec::from(in_out);
    let in_out_len = in_out.len();
    in_out[in_out_len - 1] ^= 0x08;
    let nonce_bytes = Vec::from(nonce_bytes);
    let aad_bytes = Vec::from(aad_bytes);
    let nonce = Nonce::try_assume_unique_for_key(&nonce_bytes).unwrap();
    let aad = aead::Aad::from(aad_bytes.as_slice());
    let err_result = open(
        aead_alg,
        key_bytes,
        nonce,
        aad,
        &mut in_out,
        in_prefix_len..,
    );
    assert!(err_result.is_err());
}

fn aead_open_bad_nonce<Open>(
    aead_alg: &'static aead::Algorithm,
    key_bytes: &[u8],
    nonce_bytes: &[u8],
    aad_bytes: &[u8],
    in_out: &[u8],
    in_prefix_len: usize,
    open: Open,
) where
    Open: for<'a> Fn(
        &'static aead::Algorithm,
        &[u8],
        Nonce,
        aead::Aad<&[u8]>,
        &'a mut [u8],
        RangeFrom<usize>,
    ) -> Result<&'a mut [u8], error::Unspecified>,
{
    let mut in_out = Vec::from(in_out);
    let mut nonce_bytes = Vec::from(nonce_bytes);
    nonce_bytes[NONCE_LEN - 1] ^= 0x80;
    let aad_bytes = Vec::from(aad_bytes);
    let nonce = Nonce::try_assume_unique_for_key(&nonce_bytes).unwrap();
    let aad = aead::Aad::from(aad_bytes.as_slice());
    let err_result = open(
        aead_alg,
        key_bytes,
        nonce,
        aad,
        &mut in_out,
        in_prefix_len..,
    );
    assert!(err_result.is_err());
}

fn aead_open_bad_aad<Open>(
    aead_alg: &'static aead::Algorithm,
    key_bytes: &[u8],
    nonce_bytes: &[u8],
    aad_bytes: &[u8],
    in_out: &[u8],
    in_prefix_len: usize,
    open: Open,
) where
    Open: for<'a> Fn(
        &'static aead::Algorithm,
        &[u8],
        Nonce,
        aead::Aad<&[u8]>,
        &'a mut [u8],
        RangeFrom<usize>,
    ) -> Result<&'a mut [u8], error::Unspecified>,
{
    let mut in_out = Vec::from(in_out);
    let nonce_bytes = Vec::from(nonce_bytes);
    let mut aad_bytes = Vec::from(aad_bytes);
    let aad_len = aad_bytes.len();
    if aad_len == 0 {
        aad_bytes.push(0x08);
    } else {
        aad_bytes[aad_len - 1] ^= 0x08;
    }
    let nonce = Nonce::try_assume_unique_for_key(&nonce_bytes).unwrap();
    let aad = aead::Aad::from(aad_bytes.as_slice());
    let err_result = open(
        aead_alg,
        key_bytes,
        nonce,
        aad,
        &mut in_out,
        in_prefix_len..,
    );
    assert!(err_result.is_err());
}

fn seal_with_key(
    algorithm: &'static aead::Algorithm,
    key: &[u8],
    nonce: Nonce,
    aad: aead::Aad<&[u8]>,
    in_out: &mut Vec<u8>,
) -> Result<(), error::Unspecified> {
    let mut s_key: aead::SealingKey<OneNonceSequence> = make_key(algorithm, key, nonce);
    s_key.seal_in_place_append_tag(aad, in_out)
}

fn open_with_key<'a>(
    algorithm: &'static aead::Algorithm,
    key: &[u8],
    nonce: Nonce,
    aad: aead::Aad<&[u8]>,
    in_out: &'a mut [u8],
    ciphertext_and_tag: RangeFrom<usize>,
) -> Result<&'a mut [u8], error::Unspecified> {
    let mut o_key: aead::OpeningKey<OneNonceSequence> = make_key(algorithm, key, nonce);
    o_key.open_within(aad, in_out, ciphertext_and_tag)
}

fn seal_with_less_safe_key(
    algorithm: &'static aead::Algorithm,
    key: &[u8],
    nonce: Nonce,
    aad: aead::Aad<&[u8]>,
    in_out: &mut Vec<u8>,
) -> Result<(), error::Unspecified> {
    let key = make_less_safe_key(algorithm, key);
    key.seal_in_place_append_tag(nonce, aad, in_out)
}

fn seal_with_less_safe_key_scatter(
    algorithm: &'static aead::Algorithm,
    key: &[u8],
    nonce: Nonce,
    aad: aead::Aad<&[u8]>,
    in_out: &mut Vec<u8>,
) -> Result<(), error::Unspecified> {
    // choose a split point for the `extra` data
    let split_point = if in_out.is_empty() {
        0
    } else {
        let split_point = u32::from_ne_bytes(key[..4].try_into().unwrap());
        split_point as usize % in_out.len()
    };

    // create an extra bit of data to be encrypted
    let extra_in = in_out[split_point..].to_vec();
    let key = make_less_safe_key(algorithm, key);

    // reserve space at the end for the tag
    in_out.extend_from_slice(&[0u8; aead::MAX_TAG_LEN][..algorithm.tag_len()]);

    let (in_out, extra_out_and_tag) = in_out.split_at_mut(split_point);

    key.seal_in_place_scatter(nonce, aad, in_out, &extra_in, extra_out_and_tag)
}

fn open_with_less_safe_key<'a>(
    algorithm: &'static aead::Algorithm,
    key: &[u8],
    nonce: Nonce,
    aad: aead::Aad<&[u8]>,
    in_out: &'a mut [u8],
    ciphertext_and_tag: RangeFrom<usize>,
) -> Result<&'a mut [u8], error::Unspecified> {
    let key = make_less_safe_key(algorithm, key);
    key.open_within(nonce, aad, in_out, ciphertext_and_tag)
}

fn open_with_less_safe_key_gather<'a>(
    algorithm: &'static aead::Algorithm,
    key: &[u8],
    nonce: Nonce,
    aad: aead::Aad<&[u8]>,
    in_out: &'a mut [u8],
    ciphertext_and_tag: RangeFrom<usize>,
) -> Result<&'a mut [u8], error::Unspecified> {
    let key = make_less_safe_key(algorithm, key);

    // clone the ciphertext and tag to a separate buffer, since it doesn't get modified in place
    let ciphertext = in_out[ciphertext_and_tag].to_vec();
    let (in_ciphertext, in_tag) = ciphertext.split_at(ciphertext.len() - algorithm.tag_len());

    let out_plaintext = &mut in_out[..in_ciphertext.len()];

    key.open_separate_gather(nonce, aad, in_ciphertext, in_tag, out_plaintext)?;

    Ok(out_plaintext)
}

#[allow(clippy::range_plus_one)]
fn test_aead_key_sizes(aead_alg: &'static aead::Algorithm) {
    let key_len = aead_alg.key_len();
    let key_data = vec![1u8; key_len * 2];

    // Key is the right size.
    assert!(aead::UnboundKey::new(aead_alg, &key_data[..key_len]).is_ok());

    // Key is one byte too small.
    assert!(aead::UnboundKey::new(aead_alg, &key_data[..(key_len - 1)]).is_err());

    // Key is one byte too large.
    assert!(aead::UnboundKey::new(aead_alg, &key_data[..(key_len + 1)]).is_err());

    // Key is half the required size.
    assert!(aead::UnboundKey::new(aead_alg, &key_data[..(key_len / 2)]).is_err());

    // Key is twice the required size.
    assert!(aead::UnboundKey::new(aead_alg, &key_data[..(key_len * 2)]).is_err());

    // Key is empty.
    assert!(aead::UnboundKey::new(aead_alg, &[]).is_err());

    // Key is one byte.
    assert!(aead::UnboundKey::new(aead_alg, &[0]).is_err());
}

// Test that we reject non-standard nonce sizes.
#[allow(clippy::range_plus_one)]
#[test]
fn test_aead_nonce_sizes() {
    let nonce_len = NONCE_LEN;
    let nonce = vec![0u8; nonce_len * 2];

    assert!(Nonce::try_assume_unique_for_key(&nonce[..nonce_len]).is_ok());
    assert!(Nonce::try_assume_unique_for_key(&nonce[..(nonce_len - 1)]).is_err());
    assert!(Nonce::try_assume_unique_for_key(&nonce[..(nonce_len + 1)]).is_err());
    assert!(Nonce::try_assume_unique_for_key(&nonce[..(nonce_len / 2)]).is_err());
    assert!(Nonce::try_assume_unique_for_key(&nonce[..(nonce_len * 2)]).is_err());
    assert!(Nonce::try_assume_unique_for_key(&[]).is_err());
    assert!(Nonce::try_assume_unique_for_key(&nonce[..1]).is_err());
    assert!(Nonce::try_assume_unique_for_key(&nonce[..16]).is_err()); // 128 bits.
}

#[allow(clippy::range_plus_one, clippy::cast_possible_truncation)]
#[test]
fn aead_chacha20_poly1305_openssh() {
    // TODO: test_aead_key_sizes(...);

    test::run(
        test_file!("data/aead_chacha20_poly1305_openssh_tests.txt"),
        |section, test_case| {
            assert_eq!(section, "");

            // XXX: `polyfill::convert` isn't available here.
            let key_bytes = {
                let as_vec = test_case.consume_bytes("KEY");
                let mut as_array = [0u8; aead::chacha20_poly1305_openssh::KEY_LEN];
                as_array.copy_from_slice(&as_vec);
                as_array
            };

            let sequence_number = test_case.consume_usize("SEQUENCE_NUMBER");
            assert_eq!(sequence_number as u32 as usize, sequence_number);
            let sequence_num = sequence_number as u32;
            let plaintext = test_case.consume_bytes("IN");
            let ct = test_case.consume_bytes("CT");
            let expected_tag = test_case.consume_bytes("TAG");

            // TODO: Add some tests for when things fail.
            //let error = test_case.consume_optional_string("FAILS");

            let mut tag = [0u8; aead::chacha20_poly1305_openssh::TAG_LEN];
            let mut s_in_out = plaintext.clone();
            let s_key = aead::chacha20_poly1305_openssh::SealingKey::new(&key_bytes);
            s_key.seal_in_place(sequence_num, &mut s_in_out[..], &mut tag);
            assert_eq!(&ct, &s_in_out);
            assert_eq!(&expected_tag, &tag);
            let o_key = aead::chacha20_poly1305_openssh::OpeningKey::new(&key_bytes);
            {
                let mut cipher_text_clone = Vec::from(&s_in_out[..]);
                let mut tag_clone = [0u8; aead::chacha20_poly1305_openssh::TAG_LEN];
                tag_clone.copy_from_slice(&tag);
                tag_clone[0] = 1;
                let o_result =
                    o_key.open_in_place(sequence_num, &mut cipher_text_clone[..], &tag_clone);
                assert!(o_result.is_err());
            }
            {
                let mut cipher_text_clone = Vec::from(&s_in_out[..]);
                let o_result = o_key.open_in_place(
                    sequence_num.checked_add(1).unwrap(),
                    &mut cipher_text_clone[..],
                    &tag,
                );
                assert!(o_result.is_err());
            }
            {
                let o_result = o_key.open_in_place(sequence_num, &mut s_in_out[..], &tag);
                assert_eq!(o_result, Ok(&plaintext[4..]));
            }
            assert_eq!(&s_in_out[..4], &ct[..4]);
            assert_eq!(&s_in_out[4..], &plaintext[4..]);

            Ok(())
        },
    );
}

#[test]
fn test_aead_traits() {
    test::compile_time_assert_send::<aead::Tag>();
    test::compile_time_assert_sync::<aead::Tag>();
    test::compile_time_assert_send::<aead::UnboundKey>();
    test::compile_time_assert_sync::<aead::UnboundKey>();
    test::compile_time_assert_send::<aead::LessSafeKey>();
    test::compile_time_assert_sync::<aead::LessSafeKey>();
}

#[test]
fn test_aead_thread_safeness() {
    lazy_static::lazy_static! {
        /// Compute the Initial salt once, as the seed is constant
        static ref SECRET_KEY: aead::LessSafeKey = aead::LessSafeKey::new(
            aead::UnboundKey::new(&aead::AES_128_GCM, b"this is a test! ").unwrap(),
        );
    }
    use std::thread;

    let tag = SECRET_KEY
        .seal_in_place_separate_tag(
            Nonce::try_assume_unique_for_key(&[0; NONCE_LEN]).unwrap(),
            aead::Aad::empty(),
            &mut [],
        )
        .unwrap();

    let mut join_handles = Vec::new();
    for _ in 1..100 {
        let join_handle = thread::spawn(|| {
            SECRET_KEY
                .seal_in_place_separate_tag(
                    Nonce::try_assume_unique_for_key(&[0; NONCE_LEN]).unwrap(),
                    aead::Aad::empty(),
                    &mut [],
                )
                .unwrap()
        });
        join_handles.push(join_handle);
    }
    for handle in join_handles {
        let thread_tag = handle.join().unwrap();
        assert_eq!(thread_tag.as_ref(), tag.as_ref());
    }
}

#[test]
fn test_aead_key_debug() {
    let key_bytes = [0; 32];
    let nonce = [0; NONCE_LEN];

    let key = aead::UnboundKey::new(&aead::AES_256_GCM, &key_bytes).unwrap();
    assert_eq!("UnboundKey { algorithm: AES_256_GCM }", format!("{key:?}"));

    let sealing_key: aead::SealingKey<OneNonceSequence> = make_key(
        &aead::AES_256_GCM,
        &key_bytes,
        Nonce::try_assume_unique_for_key(&nonce).unwrap(),
    );
    assert_eq!(
        "SealingKey { algorithm: AES_256_GCM }",
        format!("{sealing_key:?}")
    );

    let opening_key: aead::OpeningKey<OneNonceSequence> = make_key(
        &aead::AES_256_GCM,
        &key_bytes,
        Nonce::try_assume_unique_for_key(&nonce).unwrap(),
    );
    assert_eq!(
        "OpeningKey { algorithm: AES_256_GCM }",
        format!("{opening_key:?}")
    );
    let key: aead::LessSafeKey = make_less_safe_key(&aead::AES_256_GCM, &key_bytes);
    assert_eq!("LessSafeKey { algorithm: AES_256_GCM }", format!("{key:?}"));
}

fn make_key<K: aead::BoundKey<OneNonceSequence>>(
    algorithm: &'static aead::Algorithm,
    key: &[u8],
    nonce: Nonce,
) -> K {
    let key = aead::UnboundKey::new(algorithm, key).unwrap();
    let nonce_sequence = OneNonceSequence::new(nonce);
    K::new(key, nonce_sequence)
}

fn make_less_safe_key(algorithm: &'static aead::Algorithm, key: &[u8]) -> aead::LessSafeKey {
    let key = aead::UnboundKey::new(algorithm, key).unwrap();
    aead::LessSafeKey::new(key)
}

struct OneNonceSequence(Option<Nonce>);

impl OneNonceSequence {
    /// Constructs the sequence allowing `advance()` to be called
    /// `allowed_invocations` times.
    fn new(nonce: Nonce) -> Self {
        Self(Some(nonce))
    }
}

impl aead::NonceSequence for OneNonceSequence {
    fn advance(&mut self) -> Result<Nonce, error::Unspecified> {
        self.0.take().ok_or(error::Unspecified)
    }
}

#[test]
fn prepare_nonce() {
    const KEY: &[u8] = &[
        0x52, 0x05, 0x19, 0x7a, 0xcc, 0x88, 0xdb, 0x78, 0x39, 0x59, 0xbc, 0x03, 0xb8, 0x1d, 0x4a,
        0x6c,
    ];
    const MESSAGE: &[u8] = &[
        0x52, 0x61, 0x63, 0x63, 0x6f, 0x6f, 0x6e, 0x20, 0x4d, 0x69, 0x73, 0x63, 0x68, 0x69, 0x65,
        0x66,
    ];
    const LIMIT: u32 = 10;

    let mut sk = SealingKey::new(
        UnboundKey::new(&AES_128_GCM, KEY).unwrap(),
        Counter32Builder::new().limit(LIMIT).build(),
    );
    let mut ok = OpeningKey::new(
        UnboundKey::new(&AES_128_GCM, KEY).unwrap(),
        Counter32Builder::new().limit(LIMIT).build(),
    );

    let mut nonces: Vec<Vec<u8>> = vec![];

    for _ in 0..(LIMIT / 2) {
        let skpn = sk.prepare_nonce().unwrap();
        let okpn = ok.prepare_nonce().unwrap();
        let so_nonce = Vec::from(skpn.nonce().as_ref());
        let oo_nonce = Vec::from(okpn.nonce().as_ref());

        assert_eq!(so_nonce.as_slice(), oo_nonce.as_slice());
        assert!(!nonces.contains(&so_nonce));
        nonces.push(so_nonce);
        nonces.push(oo_nonce);

        let mut message: Vec<u8> = vec![];
        message.extend_from_slice(MESSAGE);

        skpn.seal_in_place_append_tag(Aad::empty(), &mut message)
            .unwrap();
        assert_ne!(MESSAGE, message.as_slice());

        let message = okpn.open_in_place(Aad::empty(), &mut message).unwrap();
        assert_eq!(MESSAGE, message);

        let so = sk.prepare_nonce().unwrap();
        let oo = ok.prepare_nonce().unwrap();
        let so_nonce = Vec::from(so.nonce().as_ref());
        let oo_nonce = Vec::from(oo.nonce().as_ref());

        assert_eq!(so_nonce.as_slice(), oo_nonce.as_slice());
        assert!(!nonces.contains(&so_nonce));
        nonces.push(so_nonce);
        nonces.push(oo_nonce);

        let mut message: Vec<u8> = vec![];
        message.extend_from_slice(MESSAGE);

        let tag = so
            .seal_in_place_separate_tag(Aad::empty(), &mut message)
            .unwrap();
        assert_ne!(MESSAGE, message.as_slice());
        message.extend_from_slice(tag.as_ref());

        let message = oo.open_within(Aad::empty(), &mut message, 0..).unwrap();
        assert_eq!(MESSAGE, message);
    }

    let nonce_chunks = nonces.chunks_exact(2);
    assert_eq!(0, nonce_chunks.remainder().len());
    for chunk in nonce_chunks {
        assert_eq!(chunk[0].as_slice(), chunk[1].as_slice());
    }

    let mut message: Vec<u8> = vec![];
    message.extend_from_slice(MESSAGE);

    // Subsequent usage should fail now since the sequence is exhausted in each key.
    sk.prepare_nonce().expect_err("sequence limit reached");
    ok.prepare_nonce().expect_err("sequence limit reached");
    sk.seal_in_place_append_tag(Aad::empty(), &mut message)
        .expect_err("sequence limit reached");
    sk.seal_in_place_separate_tag(Aad::empty(), &mut message)
        .expect_err("sequence limit reached");
    ok.open_in_place(Aad::empty(), &mut message)
        .expect_err("sequence limit reached");
}
