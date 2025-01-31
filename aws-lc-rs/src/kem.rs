// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

//! Key-Encapsulation Mechanisms (KEMs), including support for Kyber Round 3 Submission.
//!
//! # Example
//!
//! Note that this example uses the Kyber-512 Round 3 algorithm, but other algorithms can be used
//! in the exact same way by substituting
//! `kem::<desired_algorithm_here>` for `kem::KYBER512_R3`.
//!
//! ```rust
//! use aws_lc_rs::{
//!     kem::{Ciphertext, DecapsulationKey, EncapsulationKey},
//!     kem::{ML_KEM_512}
//! };
//!
//! // Alice generates their (private) decapsulation key.
//! let decapsulation_key = DecapsulationKey::generate(&ML_KEM_512)?;
//!
//! // Alices computes the (public) encapsulation key.
//! let encapsulation_key = decapsulation_key.encapsulation_key()?;
//!
//! let encapsulation_key_bytes = encapsulation_key.key_bytes()?;
//!
//! // Alice sends the encapsulation key bytes to bob through some
//! // protocol message.
//! let encapsulation_key_bytes = encapsulation_key_bytes.as_ref();
//!
//! // Bob constructs the (public) encapsulation key from the key bytes provided by Alice.
//! let retrieved_encapsulation_key = EncapsulationKey::new(&ML_KEM_512, encapsulation_key_bytes)?;
//!
//! // Bob executes the encapsulation algorithm to to produce their copy of the secret, and associated ciphertext.
//! let (ciphertext, bob_secret) = retrieved_encapsulation_key.encapsulate()?;
//!
//! // Alice receives ciphertext bytes from bob
//! let ciphertext_bytes = ciphertext.as_ref();
//!
//! // Bob sends Alice the ciphertext computed from the encapsulation algorithm, Alice runs decapsulation to derive their
//! // copy of the secret.
//! let alice_secret = decapsulation_key.decapsulate(Ciphertext::from(ciphertext_bytes))?;
//!
//! // Alice and Bob have now arrived to the same secret
//! assert_eq!(alice_secret.as_ref(), bob_secret.as_ref());
//!
//! # Ok::<(), aws_lc_rs::error::Unspecified>(())
//! ```
use crate::aws_lc::{
    EVP_PKEY_CTX_kem_set_params, EVP_PKEY_decapsulate, EVP_PKEY_encapsulate,
    EVP_PKEY_kem_new_raw_public_key, EVP_PKEY, EVP_PKEY_KEM,
};
use crate::buffer::Buffer;
use crate::encoding::generated_encodings;
use crate::error::{KeyRejected, Unspecified};
use crate::ptr::LcPtr;
use alloc::borrow::Cow;
use core::cmp::Ordering;
use zeroize::Zeroize;

const ML_KEM_512_SHARED_SECRET_LENGTH: usize = 32;
const ML_KEM_512_PUBLIC_KEY_LENGTH: usize = 800;
const ML_KEM_512_SECRET_KEY_LENGTH: usize = 1632;
const ML_KEM_512_CIPHERTEXT_LENGTH: usize = 768;

const ML_KEM_768_SHARED_SECRET_LENGTH: usize = 32;
const ML_KEM_768_PUBLIC_KEY_LENGTH: usize = 1184;
const ML_KEM_768_SECRET_KEY_LENGTH: usize = 2400;
const ML_KEM_768_CIPHERTEXT_LENGTH: usize = 1088;

const ML_KEM_1024_SHARED_SECRET_LENGTH: usize = 32;
const ML_KEM_1024_PUBLIC_KEY_LENGTH: usize = 1568;
const ML_KEM_1024_SECRET_KEY_LENGTH: usize = 3168;
const ML_KEM_1024_CIPHERTEXT_LENGTH: usize = 1568;

/// NIST FIPS 203 ML-KEM-512 algorithm.
pub const ML_KEM_512: Algorithm<AlgorithmId> = Algorithm {
    id: AlgorithmId::MlKem512,
    decapsulate_key_size: ML_KEM_512_SECRET_KEY_LENGTH,
    encapsulate_key_size: ML_KEM_512_PUBLIC_KEY_LENGTH,
    ciphertext_size: ML_KEM_512_CIPHERTEXT_LENGTH,
    shared_secret_size: ML_KEM_512_SHARED_SECRET_LENGTH,
};

/// NIST FIPS 203 ML-KEM-768 algorithm.
pub const ML_KEM_768: Algorithm<AlgorithmId> = Algorithm {
    id: AlgorithmId::MlKem768,
    decapsulate_key_size: ML_KEM_768_SECRET_KEY_LENGTH,
    encapsulate_key_size: ML_KEM_768_PUBLIC_KEY_LENGTH,
    ciphertext_size: ML_KEM_768_CIPHERTEXT_LENGTH,
    shared_secret_size: ML_KEM_768_SHARED_SECRET_LENGTH,
};

/// NIST FIPS 203 ML-KEM-1024 algorithm.
pub const ML_KEM_1024: Algorithm<AlgorithmId> = Algorithm {
    id: AlgorithmId::MlKem1024,
    decapsulate_key_size: ML_KEM_1024_SECRET_KEY_LENGTH,
    encapsulate_key_size: ML_KEM_1024_PUBLIC_KEY_LENGTH,
    ciphertext_size: ML_KEM_1024_CIPHERTEXT_LENGTH,
    shared_secret_size: ML_KEM_1024_SHARED_SECRET_LENGTH,
};

use crate::aws_lc::{NID_MLKEM1024, NID_MLKEM512, NID_MLKEM768};

/// An identifier for a KEM algorithm.
pub trait AlgorithmIdentifier:
    Copy + Clone + Debug + PartialEq + crate::sealed::Sealed + 'static
{
    /// Returns the algorithm's associated AWS-LC nid.
    fn nid(self) -> i32;
}

/// A KEM algorithm
#[derive(PartialEq)]
pub struct Algorithm<Id = AlgorithmId>
where
    Id: AlgorithmIdentifier,
{
    pub(crate) id: Id,
    pub(crate) decapsulate_key_size: usize,
    pub(crate) encapsulate_key_size: usize,
    pub(crate) ciphertext_size: usize,
    pub(crate) shared_secret_size: usize,
}

impl<Id> Algorithm<Id>
where
    Id: AlgorithmIdentifier,
{
    /// Returns the identifier for this algorithm.
    #[must_use]
    pub fn id(&self) -> Id {
        self.id
    }

    #[inline]
    #[allow(dead_code)]
    pub(crate) fn decapsulate_key_size(&self) -> usize {
        self.decapsulate_key_size
    }

    #[inline]
    pub(crate) fn encapsulate_key_size(&self) -> usize {
        self.encapsulate_key_size
    }

    #[inline]
    pub(crate) fn ciphertext_size(&self) -> usize {
        self.ciphertext_size
    }

    #[inline]
    pub(crate) fn shared_secret_size(&self) -> usize {
        self.shared_secret_size
    }
}

impl<Id> Debug for Algorithm<Id>
where
    Id: AlgorithmIdentifier,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        Debug::fmt(&self.id, f)
    }
}

/// A serializable decapulsation key usable with KEMs. This can be randomly generated with `DecapsulationKey::generate`.
pub struct DecapsulationKey<Id = AlgorithmId>
where
    Id: AlgorithmIdentifier,
{
    algorithm: &'static Algorithm<Id>,
    evp_pkey: LcPtr<EVP_PKEY>,
}

/// Identifier for a KEM algorithm.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum AlgorithmId {
    /// NIST FIPS 203 ML-KEM-512 algorithm.
    MlKem512,

    /// NIST FIPS 203 ML-KEM-768 algorithm.
    MlKem768,

    /// NIST FIPS 203 ML-KEM-1024 algorithm.
    MlKem1024,
}

impl AlgorithmIdentifier for AlgorithmId {
    fn nid(self) -> i32 {
        match self {
            AlgorithmId::MlKem512 => NID_MLKEM512,
            AlgorithmId::MlKem768 => NID_MLKEM768,
            AlgorithmId::MlKem1024 => NID_MLKEM1024,
        }
    }
}

impl crate::sealed::Sealed for AlgorithmId {}

impl<Id> DecapsulationKey<Id>
where
    Id: AlgorithmIdentifier,
{
    /// Generate a new KEM decapsulation key for the given algorithm.
    ///
    /// # Errors
    /// `error::Unspecified` when operation fails due to internal error.
    pub fn generate(alg: &'static Algorithm<Id>) -> Result<Self, Unspecified> {
        let kyber_key = kem_key_generate(alg.id.nid())?;
        Ok(DecapsulationKey {
            algorithm: alg,
            evp_pkey: kyber_key,
        })
    }

    /// Return the algorithm associated with the given KEM decapsulation key.
    #[must_use]
    pub fn algorithm(&self) -> &'static Algorithm<Id> {
        self.algorithm
    }

    /// Computes the KEM encapsulation key from the KEM decapsulation key.
    ///
    /// # Errors
    /// `error::Unspecified` when operation fails due to internal error.
    #[allow(clippy::missing_panics_doc)]
    pub fn encapsulation_key(&self) -> Result<EncapsulationKey<Id>, Unspecified> {
        let evp_pkey = self.evp_pkey.clone();

        Ok(EncapsulationKey {
            algorithm: self.algorithm,
            evp_pkey,
        })
    }

    /// Performs the decapsulate operation using this KEM decapsulation key on the given ciphertext.
    ///
    /// `ciphertext` is the ciphertext generated by the encapsulate operation using the KEM encapsulation key
    /// associated with this KEM decapsulation key.
    ///
    /// # Errors
    /// `Unspecified` when operation fails due to internal error.
    #[allow(clippy::needless_pass_by_value)]
    pub fn decapsulate(&self, ciphertext: Ciphertext<'_>) -> Result<SharedSecret, Unspecified> {
        let mut shared_secret_len = self.algorithm.shared_secret_size();
        let mut shared_secret: Vec<u8> = vec![0u8; shared_secret_len];

        let mut ctx = self.evp_pkey.create_EVP_PKEY_CTX()?;

        let ciphertext = ciphertext.as_ref();

        if 1 != unsafe {
            EVP_PKEY_decapsulate(
                *ctx.as_mut(),
                shared_secret.as_mut_ptr(),
                &mut shared_secret_len,
                // AWS-LC incorrectly has this as an unqualified `uint8_t *`, it should be qualified with const
                ciphertext.as_ptr() as *mut u8,
                ciphertext.len(),
            )
        } {
            return Err(Unspecified);
        }

        // This is currently pedantic but done for safety in-case the shared_secret buffer
        // size changes in the future. `EVP_PKEY_decapsulate` updates `shared_secret_len` with
        // the length of the shared secret in the event the buffer provided was larger then the secret.
        // This truncates the buffer to the proper length to match the shared secret written.
        debug_assert_eq!(shared_secret_len, shared_secret.len());
        shared_secret.truncate(shared_secret_len);

        Ok(SharedSecret(shared_secret.into_boxed_slice()))
    }
}

unsafe impl<Id> Send for DecapsulationKey<Id> where Id: AlgorithmIdentifier {}

unsafe impl<Id> Sync for DecapsulationKey<Id> where Id: AlgorithmIdentifier {}

impl<Id> Debug for DecapsulationKey<Id>
where
    Id: AlgorithmIdentifier,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DecapsulationKey")
            .field("algorithm", &self.algorithm)
            .finish_non_exhaustive()
    }
}

use paste::paste;

generated_encodings!(EncapsulationKeyBytes);

/// A serializable encapsulation key usable with KEM algorithms. Constructed
/// from either a `DecapsulationKey` or raw bytes.
pub struct EncapsulationKey<Id = AlgorithmId>
where
    Id: AlgorithmIdentifier,
{
    algorithm: &'static Algorithm<Id>,
    evp_pkey: LcPtr<EVP_PKEY>,
}

impl<Id> EncapsulationKey<Id>
where
    Id: AlgorithmIdentifier,
{
    /// Return the algorithm associated with the given KEM encapsulation key.
    #[must_use]
    pub fn algorithm(&self) -> &'static Algorithm<Id> {
        self.algorithm
    }

    /// Performs the encapsulate operation using this KEM encapsulation key, generating a ciphertext
    /// and associated shared secret.
    ///
    /// # Errors
    /// `error::Unspecified` when operation fails due to internal error.
    pub fn encapsulate(&self) -> Result<(Ciphertext<'static>, SharedSecret), Unspecified> {
        let mut ciphertext_len = self.algorithm.ciphertext_size();
        let mut shared_secret_len = self.algorithm.shared_secret_size();
        let mut ciphertext: Vec<u8> = vec![0u8; ciphertext_len];
        let mut shared_secret: Vec<u8> = vec![0u8; shared_secret_len];

        let mut ctx = self.evp_pkey.create_EVP_PKEY_CTX()?;

        if 1 != unsafe {
            EVP_PKEY_encapsulate(
                *ctx.as_mut(),
                ciphertext.as_mut_ptr(),
                &mut ciphertext_len,
                shared_secret.as_mut_ptr(),
                &mut shared_secret_len,
            )
        } {
            return Err(Unspecified);
        }

        // The following two steps are currently pedantic but done for safety in-case the buffer allocation
        // sizes change in the future. `EVP_PKEY_encapsulate` updates `ciphertext_len` and `shared_secret_len` with
        // the length of the ciphertext and shared secret respectivly in the event the buffer provided for each was
        // larger then the actual values. Thus these two steps truncate the buffers to the proper length to match the
        // value lengths written.
        debug_assert_eq!(ciphertext_len, ciphertext.len());
        ciphertext.truncate(ciphertext_len);
        debug_assert_eq!(shared_secret_len, shared_secret.len());
        shared_secret.truncate(shared_secret_len);

        Ok((
            Ciphertext::new(ciphertext),
            SharedSecret::new(shared_secret.into_boxed_slice()),
        ))
    }

    /// Returns the `EnscapsulationKey` bytes.
    ///
    /// # Errors
    /// * `Unspecified`: Any failure to retrieve the `EnscapsulationKey` bytes.
    pub fn key_bytes(&self) -> Result<EncapsulationKeyBytes<'static>, Unspecified> {
        let mut encapsulate_bytes = vec![0u8; self.algorithm.encapsulate_key_size()];
        let encapsulate_key_size = self
            .evp_pkey
            .marshal_raw_public_to_buffer(&mut encapsulate_bytes)?;

        debug_assert_eq!(encapsulate_key_size, encapsulate_bytes.len());
        encapsulate_bytes.truncate(encapsulate_key_size);

        Ok(EncapsulationKeyBytes::new(encapsulate_bytes))
    }

    /// Creates a new KEM encapsulation key from raw bytes. This method MUST NOT be used to generate
    /// a new encapsulation key, rather it MUST be used to construct `EncapsulationKey` previously serialized
    /// to raw bytes.
    ///
    /// `alg` is the [`Algorithm`] to be associated with the generated `EncapsulationKey`.
    ///
    /// `bytes` is a slice of raw bytes representing a `EncapsulationKey`.
    ///
    /// # Errors
    /// `error::KeyRejected` when operation fails during key creation.
    pub fn new(alg: &'static Algorithm<Id>, bytes: &[u8]) -> Result<Self, KeyRejected> {
        match bytes.len().cmp(&alg.encapsulate_key_size()) {
            Ordering::Less => Err(KeyRejected::too_small()),
            Ordering::Greater => Err(KeyRejected::too_large()),
            Ordering::Equal => Ok(()),
        }?;
        let pubkey = LcPtr::new(unsafe {
            EVP_PKEY_kem_new_raw_public_key(alg.id.nid(), bytes.as_ptr(), bytes.len())
        })?;
        Ok(EncapsulationKey {
            algorithm: alg,
            evp_pkey: pubkey,
        })
    }
}

unsafe impl<Id> Send for EncapsulationKey<Id> where Id: AlgorithmIdentifier {}

unsafe impl<Id> Sync for EncapsulationKey<Id> where Id: AlgorithmIdentifier {}

impl<Id> Debug for EncapsulationKey<Id>
where
    Id: AlgorithmIdentifier,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("EncapsulationKey")
            .field("algorithm", &self.algorithm)
            .finish_non_exhaustive()
    }
}

/// A set of encrypted bytes produced by [`EncapsulationKey::encapsulate`],
/// and used as an input to [`DecapsulationKey::decapsulate`].
pub struct Ciphertext<'a>(Cow<'a, [u8]>);

impl<'a> Ciphertext<'a> {
    fn new(value: Vec<u8>) -> Ciphertext<'a> {
        Self(Cow::Owned(value))
    }
}

impl Drop for Ciphertext<'_> {
    fn drop(&mut self) {
        if let Cow::Owned(ref mut v) = self.0 {
            v.zeroize();
        }
    }
}

impl AsRef<[u8]> for Ciphertext<'_> {
    fn as_ref(&self) -> &[u8] {
        match self.0 {
            Cow::Borrowed(v) => v,
            Cow::Owned(ref v) => v.as_ref(),
        }
    }
}

impl<'a> From<&'a [u8]> for Ciphertext<'a> {
    fn from(value: &'a [u8]) -> Self {
        Self(Cow::Borrowed(value))
    }
}

/// The cryptographic shared secret output from the KEM encapsulate / decapsulate process.
pub struct SharedSecret(Box<[u8]>);

impl SharedSecret {
    fn new(value: Box<[u8]>) -> Self {
        Self(value)
    }
}

impl Drop for SharedSecret {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl AsRef<[u8]> for SharedSecret {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

// Returns an LcPtr to an EVP_PKEY
#[inline]
fn kem_key_generate(nid: i32) -> Result<LcPtr<EVP_PKEY>, Unspecified> {
    let params_fn = |ctx| {
        if 1 == unsafe { EVP_PKEY_CTX_kem_set_params(ctx, nid) } {
            Ok(())
        } else {
            Err(())
        }
    };

    LcPtr::<EVP_PKEY>::generate(EVP_PKEY_KEM, Some(params_fn))
}

#[cfg(test)]
mod tests {
    use super::{Ciphertext, DecapsulationKey, EncapsulationKey, SharedSecret};
    use crate::error::KeyRejected;

    use crate::kem::{ML_KEM_1024, ML_KEM_512, ML_KEM_768};

    #[test]
    fn ciphertext() {
        let ciphertext_bytes = vec![42u8; 4];
        let ciphertext = Ciphertext::from(ciphertext_bytes.as_ref());
        assert_eq!(ciphertext.as_ref(), &[42, 42, 42, 42]);
        drop(ciphertext);

        let ciphertext_bytes = vec![42u8; 4];
        let ciphertext = Ciphertext::<'static>::new(ciphertext_bytes);
        assert_eq!(ciphertext.as_ref(), &[42, 42, 42, 42]);
    }

    #[test]
    fn shared_secret() {
        let secret_bytes = vec![42u8; 4];
        let shared_secret = SharedSecret::new(secret_bytes.into_boxed_slice());
        assert_eq!(shared_secret.as_ref(), &[42, 42, 42, 42]);
    }

    #[test]
    fn test_kem_serialize() {
        for algorithm in [&ML_KEM_512, &ML_KEM_768, &ML_KEM_1024] {
            let priv_key = DecapsulationKey::generate(algorithm).unwrap();
            assert_eq!(priv_key.algorithm(), algorithm);

            let pub_key = priv_key.encapsulation_key().unwrap();
            let pubkey_raw_bytes = pub_key.key_bytes().unwrap();
            let pub_key_from_bytes =
                EncapsulationKey::new(algorithm, pubkey_raw_bytes.as_ref()).unwrap();

            assert_eq!(
                pub_key.key_bytes().unwrap().as_ref(),
                pub_key_from_bytes.key_bytes().unwrap().as_ref()
            );
            assert_eq!(pub_key.algorithm(), pub_key_from_bytes.algorithm());
        }
    }

    #[test]
    fn test_kem_wrong_sizes() {
        for algorithm in [&ML_KEM_512, &ML_KEM_768, &ML_KEM_1024] {
            let too_long_bytes = vec![0u8; algorithm.encapsulate_key_size() + 1];
            let long_pub_key_from_bytes = EncapsulationKey::new(algorithm, &too_long_bytes);
            assert_eq!(
                long_pub_key_from_bytes.err(),
                Some(KeyRejected::too_large())
            );

            let too_short_bytes = vec![0u8; algorithm.encapsulate_key_size() - 1];
            let short_pub_key_from_bytes = EncapsulationKey::new(algorithm, &too_short_bytes);
            assert_eq!(
                short_pub_key_from_bytes.err(),
                Some(KeyRejected::too_small())
            );
        }
    }

    #[test]
    fn test_kem_e2e() {
        for algorithm in [&ML_KEM_512, &ML_KEM_768, &ML_KEM_1024] {
            let priv_key = DecapsulationKey::generate(algorithm).unwrap();
            assert_eq!(priv_key.algorithm(), algorithm);

            let pub_key = priv_key.encapsulation_key().unwrap();

            let (alice_ciphertext, alice_secret) =
                pub_key.encapsulate().expect("encapsulate successful");

            let bob_secret = priv_key
                .decapsulate(alice_ciphertext)
                .expect("decapsulate successful");

            assert_eq!(alice_secret.as_ref(), bob_secret.as_ref());
        }
    }

    #[test]
    fn test_serialized_kem_e2e() {
        for algorithm in [&ML_KEM_512, &ML_KEM_768, &ML_KEM_1024] {
            let priv_key = DecapsulationKey::generate(algorithm).unwrap();
            assert_eq!(priv_key.algorithm(), algorithm);

            let pub_key = priv_key.encapsulation_key().unwrap();

            // Generate public key bytes to send to bob
            let pub_key_bytes = pub_key.key_bytes().unwrap();

            // Test that priv_key's EVP_PKEY isn't entirely freed since we remove this pub_key's reference.
            drop(pub_key);

            let retrieved_pub_key =
                EncapsulationKey::new(algorithm, pub_key_bytes.as_ref()).unwrap();
            let (ciphertext, bob_secret) = retrieved_pub_key
                .encapsulate()
                .expect("encapsulate successful");

            let alice_secret = priv_key
                .decapsulate(ciphertext)
                .expect("decapsulate successful");

            assert_eq!(alice_secret.as_ref(), bob_secret.as_ref());
        }
    }

    #[test]
    fn test_debug_fmt() {
        let private = DecapsulationKey::generate(&ML_KEM_512).expect("successful generation");
        assert_eq!(
            format!("{private:?}"),
            "DecapsulationKey { algorithm: MlKem512, .. }"
        );
        assert_eq!(
            format!(
                "{:?}",
                private.encapsulation_key().expect("public key retrievable")
            ),
            "EncapsulationKey { algorithm: MlKem512, .. }"
        );
    }
}
