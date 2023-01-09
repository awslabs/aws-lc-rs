// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 or ISC

use crate::aead::block::Block;
use crate::aead::cipher::SymmetricCipherKey;
use crate::aead::{Nonce, NonceSequence, NONCE_LEN};
use crate::error::Unspecified;
use crate::rand;
use crate::rand::SystemRandom;
use zeroize::Zeroize;

/// `PredictableNonceSequence` is an implementation of the `NonceSequence` trait.
/// As its name indicates, the next nonce is the sequence is predictable by observing the
/// previous nonces produced.
/// The internal state of a `PredictableNonceSequence` is a 64-bit unsigned counter that
/// increments on each call to `advance`. This counter is used as the nonce.
#[allow(clippy::module_name_repetitions)]
pub struct PredictableNonceSequence {
    position: u64,
}

impl Default for PredictableNonceSequence {
    /// Produces a new `PredictableNonceSequence` in its default state.
    fn default() -> Self {
        Self::new()
    }
}

impl PredictableNonceSequence {
    /// Produces a new `PredictableNonceSequence` with the internal counter set to 0.
    #[must_use]
    pub fn new() -> PredictableNonceSequence {
        PredictableNonceSequence::starting_from(0)
    }

    /// Produces a new `PredictableNonceSequence` with the internal counter set to the value
    /// indicated.
    #[must_use]
    pub fn starting_from(position: u64) -> PredictableNonceSequence {
        PredictableNonceSequence { position }
    }
}

impl NonceSequence for PredictableNonceSequence {
    fn advance(&mut self) -> Result<Nonce, Unspecified> {
        self.position = self.position.wrapping_add(1);
        let bytes: [u8; 8] = self.position.to_be_bytes();
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[4..].copy_from_slice(&bytes);
        Ok(Nonce(nonce_bytes))
    }
}

#[derive(Clone)]
#[allow(clippy::module_name_repetitions)]
/// `NonceSequenceKey` wraps a `[u8; 16]`. The value is zero'd when dropped.
pub struct NonceSequenceKey([u8; 16]);

impl NonceSequenceKey {
    fn new() -> Self {
        let key: [u8; 16] = rand::generate(&SystemRandom::new()).unwrap().expose();
        Self(key)
    }
}

impl From<&[u8; 16]> for NonceSequenceKey {
    fn from(value: &[u8; 16]) -> Self {
        let mut key = [0u8; 16];
        key.copy_from_slice(value);
        Self(key)
    }
}

impl From<NonceSequenceKey> for [u8; 16] {
    fn from(value: NonceSequenceKey) -> Self {
        value.0
    }
}

impl Drop for NonceSequenceKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// `UnpredictableNonceSequence` is an implementation of the `NonceSequence` trait.
/// The nonces in the sequence this produces appear random to an outside observer w/o
/// knowledge of the key being used.
/// The internal state of an `UnpredictableNonceSequence` is a unsigned 64-bit counter and an
/// AES128 key. The key is determined at construction and is immutable. The counter increments on
/// each call to `advance`. Each nonce is generated by encrypting the counter using the AES128 key.
#[allow(clippy::module_name_repetitions)]
pub struct UnpredictableNonceSequence {
    aes_key: SymmetricCipherKey,
    position: u64,
}

impl UnpredictableNonceSequence {
    /// Generates a random 128-bit AES128 key and uses it to construct a
    /// `UnpredictableNonceSequence` with an internal counter at 0.
    /// # Panics
    /// Function panics if unable to generate random key.
    #[must_use]
    pub fn new() -> (NonceSequenceKey, UnpredictableNonceSequence) {
        let key = NonceSequenceKey::new();
        (
            key.clone(),
            UnpredictableNonceSequence::using_key_and_position(&key, 0),
        )
    }

    /// Generates a random 128-bit AES128 key and uses it to construct a
    /// `UnpredictableNonceSequence` with an internal counter at the indicated value.
    /// # Panics
    /// Function panics if unable to generate random key.
    #[must_use]
    pub fn starting_from(position: u64) -> (NonceSequenceKey, UnpredictableNonceSequence) {
        let key = NonceSequenceKey::new();
        (
            key.clone(),
            UnpredictableNonceSequence::using_key_and_position(&key, position),
        )
    }

    /// Uses the provided `NonceSequenceKey` to construct an
    /// `UnpredictableNonceSequence` with an internal counter at 0.
    /// # Panics
    /// Function panics if unable to construct key.
    #[must_use]
    pub fn using_key(key: &NonceSequenceKey) -> UnpredictableNonceSequence {
        UnpredictableNonceSequence::using_key_and_position(key, 0)
    }

    /// Uses the provided `NonceSequenceKey` to construct an
    /// `UnpredictableNonceSequence` with an internal counter at the indicated value.
    /// # Panics
    /// Function panics if unable to construct key.
    #[must_use]
    pub fn using_key_and_position(
        key: &NonceSequenceKey,
        position: u64,
    ) -> UnpredictableNonceSequence {
        UnpredictableNonceSequence {
            aes_key: SymmetricCipherKey::aes128(&key.0).unwrap(),
            position,
        }
    }
}

impl NonceSequence for UnpredictableNonceSequence {
    fn advance(&mut self) -> Result<Nonce, Unspecified> {
        self.position = self.position.wrapping_add(1);
        let mut block_bytes = [0u8; 16];
        block_bytes[4..12].copy_from_slice(&self.position.to_be_bytes());
        let encrypted_block = self.aes_key.encrypt_block(Block::from(&block_bytes))?;
        let encrypted_bytes = encrypted_block.as_ref();
        let mut nonce_bytes = [0u8; NONCE_LEN];
        nonce_bytes.copy_from_slice(&encrypted_bytes[0..NONCE_LEN]);
        Ok(Nonce(nonce_bytes))
    }
}

#[cfg(test)]
mod tests {
    use crate::aead::nonce_sequence::{PredictableNonceSequence, UnpredictableNonceSequence};
    use crate::aead::NonceSequence;

    #[test]
    fn test_predictable() {
        let value = 0x0002_4CB0_16EA_u64; // 9_876_543_210
        let mut predicatable_ns = PredictableNonceSequence::starting_from(value);
        let nonce = predicatable_ns.advance().unwrap().0;
        assert_eq!(nonce, [0, 0, 0, 0, 0, 0, 0, 0x02, 0x4C, 0xB0, 0x16, 0xEB]);
    }

    #[test]
    fn test_predictable_new() {
        let mut predictable_ns = PredictableNonceSequence::new();
        let nonce = predictable_ns.advance().unwrap().0;
        assert_eq!(nonce, [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    }

    #[test]
    fn test_unpredictable() {
        const STARTING_POS: u64 = 9_876_543_210u64;
        let (key, mut uns1) = UnpredictableNonceSequence::starting_from(STARTING_POS);
        let mut uns2 = UnpredictableNonceSequence::using_key_and_position(&key, STARTING_POS);

        for _ in 0..100 {
            assert_eq!(uns1.advance().unwrap().0, uns2.advance().unwrap().0);
        }
    }

    #[test]
    fn test_unpredictable_new() {
        let (key, mut uns1) = UnpredictableNonceSequence::new();
        let mut uns2 = UnpredictableNonceSequence::using_key(&key);

        for _ in 0..100 {
            assert_eq!(uns1.advance().unwrap().0, uns2.advance().unwrap().0);
        }
    }
}
