// Copyright 2015-2017 Brian Smith.
// SPDX-License-Identifier: ISC
// Modifications copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

//! Public key signatures: signing and verification.
//!
//! Use the `verify` function to verify signatures, passing a reference to the
//! algorithm that identifies the algorithm. See the documentation for `verify`
//! for examples.
//!
//! For signature verification, this API treats each combination of parameters
//! as a separate algorithm. For example, instead of having a single "RSA"
//! algorithm with a verification function that takes a bunch of parameters,
//! there are `RSA_PKCS1_2048_8192_SHA256`, `RSA_PKCS1_2048_8192_SHA384`, etc.,
//! which encode sets of parameter choices into objects. This is designed to
//! reduce the risks of algorithm agility and to provide consistency with ECDSA
//! and `EdDSA`.
//!
//! Currently this module does not support digesting the message to be signed
//! separately from the public key operation, as it is currently being
//! optimized for Ed25519 and for the implementation of protocols that do not
//! requiring signing large messages. An interface for efficiently supporting
//! larger messages may be added later.
//!
//!
//! # Algorithm Details
//!
//! ## `ECDSA_*_ASN1` Details: ASN.1-encoded ECDSA Signatures
//!
//! The signature is a ASN.1 DER-encoded `Ecdsa-Sig-Value` as described in
//! [RFC 3279 Section 2.2.3]. This is the form of ECDSA signature used in
//! X.509-related structures and in TLS's `ServerKeyExchange` messages.
//!
//! The public key is encoding in uncompressed form using the
//! Octet-String-to-Elliptic-Curve-Point algorithm in
//! [SEC 1: Elliptic Curve Cryptography, Version 2.0].
//!
//! During verification, the public key is validated using the ECC Partial
//! Public-Key Validation Routine from Section 5.6.2.3.3 of
//! [NIST Special Publication 800-56A, revision 2] and Appendix A.3 of the
//! NSA's [Suite B implementer's guide to FIPS 186-3]. Note that, as explained
//! in the NSA guide, ECC Partial Public-Key Validation is equivalent to ECC
//! Full Public-Key Validation for prime-order curves like this one.
//!
//! ## `ECDSA_*_FIXED` Details: Fixed-length (PKCS#11-style) ECDSA Signatures
//!
//! The signature is *r*||*s*, where || denotes concatenation, and where both
//! *r* and *s* are both big-endian-encoded values that are left-padded to the
//! maximum length. A P-256 signature will be 64 bytes long (two 32-byte
//! components) and a P-384 signature will be 96 bytes long (two 48-byte
//! components). This is the form of ECDSA signature used PKCS#11 and DNSSEC.
//!
//! The public key is encoding in uncompressed form using the
//! Octet-String-to-Elliptic-Curve-Point algorithm in
//! [SEC 1: Elliptic Curve Cryptography, Version 2.0].
//!
//! During verification, the public key is validated using the ECC Partial
//! Public-Key Validation Routine from Section 5.6.2.3.3 of
//! [NIST Special Publication 800-56A, revision 2] and Appendix A.3 of the
//! NSA's [Suite B implementer's guide to FIPS 186-3]. Note that, as explained
//! in the NSA guide, ECC Partial Public-Key Validation is equivalent to ECC
//! Full Public-Key Validation for prime-order curves like this one.
//!
//! ## `RSA_PKCS1_*` Details: RSA PKCS#1 1.5 Signatures
//!
//! The signature is an RSASSA-PKCS1-v1_5 signature as described in
//! [RFC 3447 Section 8.2].
//!
//! The public key is encoded as an ASN.1 `RSAPublicKey` as described in
//! [RFC 3447 Appendix-A.1.1]. The public key modulus length, rounded *up* to
//! the nearest (larger) multiple of 8 bits, must be in the range given in the
//! name of the algorithm. The public exponent must be an odd integer of 2-33
//! bits, inclusive.
//!
//!
//! ## `RSA_PSS_*` Details: RSA PSS Signatures
//!
//! The signature is an RSASSA-PSS signature as described in
//! [RFC 3447 Section 8.1].
//!
//! The public key is encoded as an ASN.1 `RSAPublicKey` as described in
//! [RFC 3447 Appendix-A.1.1]. The public key modulus length, rounded *up* to
//! the nearest (larger) multiple of 8 bits, must be in the range given in the
//! name of the algorithm. The public exponent must be an odd integer of 2-33
//! bits, inclusive.
//!
//! During verification, signatures will only be accepted if the MGF1 digest
//! algorithm is the same as the message digest algorithm and if the salt
//! length is the same length as the message digest. This matches the
//! requirements in TLS 1.3 and other recent specifications.
//!
//! During signing, the message digest algorithm will be used as the MGF1
//! digest algorithm. The salt will be the same length as the message digest.
//! This matches the requirements in TLS 1.3 and other recent specifications.
//! Additionally, the entire salt is randomly generated separately for each
//! signature using the secure random number generator passed to `sign()`.
//!
//!
//! [SEC 1: Elliptic Curve Cryptography, Version 2.0]:
//!     http://www.secg.org/sec1-v2.pdf
//! [NIST Special Publication 800-56A, revision 2]:
//!     http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-56Ar2.pdf
//! [Suite B implementer's guide to FIPS 186-3]:
//!     https://github.com/briansmith/ring/blob/main/doc/ecdsa.pdf
//! [RFC 3279 Section 2.2.3]:
//!     https://tools.ietf.org/html/rfc3279#section-2.2.3
//! [RFC 3447 Section 8.2]:
//!     https://tools.ietf.org/html/rfc3447#section-7.2
//! [RFC 3447 Section 8.1]:
//!     https://tools.ietf.org/html/rfc3447#section-8.1
//! [RFC 3447 Appendix-A.1.1]:
//!     https://tools.ietf.org/html/rfc3447#appendix-A.1.1
//!
//!
//! # Examples
//!
//! ## Signing and verifying with Ed25519
//!
//! ```
//! use aws_lc_rs::{
//!     rand,
//!     signature::{self, KeyPair},
//! };
//!
//! fn main() -> Result<(), aws_lc_rs::error::Unspecified> {
//!     // Generate a new key pair for Ed25519.
//!     let key_pair = signature::Ed25519KeyPair::generate()?;
//!
//!     // Sign the message "hello, world".
//!     const MESSAGE: &[u8] = b"hello, world";
//!     let sig = key_pair.sign(MESSAGE);
//!
//!     // Normally an application would extract the bytes of the signature and
//!     // send them in a protocol message to the peer(s). Here we just get the
//!     // public key key directly from the key pair.
//!     let peer_public_key_bytes = key_pair.public_key().as_ref();
//!
//!     // Verify the signature of the message using the public key. Normally the
//!     // verifier of the message would parse the inputs to this code out of the
//!     // protocol message(s) sent by the signer.
//!     let peer_public_key =
//!         signature::UnparsedPublicKey::new(&signature::ED25519, peer_public_key_bytes);
//!     peer_public_key.verify(MESSAGE, sig.as_ref())?;
//!
//!     Ok(())
//! }
//! ```
//!
//! ## Signing and verifying with RSA (PKCS#1 1.5 padding)
//!
//! By default OpenSSL writes RSA public keys in `SubjectPublicKeyInfo` format,
//! not `RSAPublicKey` format, and Base64-encodes them (“PEM” format).
//!
//! To convert the PEM `SubjectPublicKeyInfo` format (“BEGIN PUBLIC KEY”) to the
//! binary `RSAPublicKey` format needed by `verify()`, use:
//!
//! ```sh
//! openssl rsa -pubin \
//!             -in public_key.pem \
//!             -inform PEM \
//!             -RSAPublicKey_out \
//!             -outform DER \
//!             -out public_key.der
//! ```
//!
//! To extract the RSAPublicKey-formatted public key from an ASN.1 (binary)
//! DER-encoded `RSAPrivateKey` format private key file, use:
//!
//! ```sh
//! openssl rsa -in private_key.der \
//!             -inform DER \
//!             -RSAPublicKey_out \
//!             -outform DER \
//!             -out public_key.der
//! ```
//!
//! ```
//! use aws_lc_rs::{rand, signature};
//!
//! fn sign_and_verify_rsa(
//!     private_key_path: &std::path::Path,
//!     public_key_path: &std::path::Path,
//! ) -> Result<(), MyError> {
//!     // Create an `RsaKeyPair` from the DER-encoded bytes. This example uses
//!     // a 2048-bit key, but larger keys are also supported.
//!     let private_key_der = read_file(private_key_path)?;
//!     let key_pair = signature::RsaKeyPair::from_der(&private_key_der)
//!         .map_err(|_| MyError::BadPrivateKey)?;
//!
//!     // Sign the message "hello, world", using PKCS#1 v1.5 padding and the
//!     // SHA256 digest algorithm.
//!     const MESSAGE: &'static [u8] = b"hello, world";
//!     let rng = rand::SystemRandom::new();
//!     let mut signature = vec![0; key_pair.public_modulus_len()];
//!     key_pair
//!         .sign(&signature::RSA_PKCS1_SHA256, &rng, MESSAGE, &mut signature)
//!         .map_err(|_| MyError::OOM)?;
//!
//!     // Verify the signature.
//!     let public_key = signature::UnparsedPublicKey::new(
//!         &signature::RSA_PKCS1_2048_8192_SHA256,
//!         read_file(public_key_path)?,
//!     );
//!     public_key
//!         .verify(MESSAGE, &signature)
//!         .map_err(|_| MyError::BadSignature)
//! }
//!
//! #[derive(Debug)]
//! enum MyError {
//!     IO(std::io::Error),
//!     BadPrivateKey,
//!     OOM,
//!     BadSignature,
//! }
//!
//! fn read_file(path: &std::path::Path) -> Result<Vec<u8>, MyError> {
//!     use std::io::Read;
//!
//!     let mut file = std::fs::File::open(path).map_err(|e| MyError::IO(e))?;
//!     let mut contents: Vec<u8> = Vec::new();
//!     file.read_to_end(&mut contents)
//!         .map_err(|e| MyError::IO(e))?;
//!     Ok(contents)
//! }
//!
//! fn main() {
//!     let private_key_path =
//!         std::path::Path::new("tests/data/signature_rsa_example_private_key.der");
//!     let public_key_path =
//!         std::path::Path::new("tests/data/signature_rsa_example_public_key.der");
//!     sign_and_verify_rsa(&private_key_path, &public_key_path).unwrap()
//! }
//! ```
use core::fmt::{Debug, Formatter};

#[cfg(feature = "ring-sig-verify")]
use untrusted::Input;

pub use crate::rsa::signature::RsaEncoding;
pub use crate::rsa::{
    KeyPair as RsaKeyPair, PublicKey as RsaSubjectPublicKey,
    PublicKeyComponents as RsaPublicKeyComponents, RsaParameters,
};

use crate::rsa::signature::{RsaSignatureEncoding, RsaSigningAlgorithmId};
use crate::rsa::RsaVerificationAlgorithmId;

pub use crate::ec::key_pair::{EcdsaKeyPair, PrivateKey as EcdsaPrivateKey};
use crate::ec::signature::EcdsaSignatureFormat;
pub use crate::ec::signature::{
    EcdsaSigningAlgorithm, EcdsaVerificationAlgorithm, PublicKey as EcdsaPublicKey,
};
pub use crate::ed25519::{
    Ed25519KeyPair, EdDSAParameters, Seed as Ed25519Seed, ED25519_PUBLIC_KEY_LEN,
};

use crate::{digest, ec, error, hex, rsa, sealed};

/// The longest signature is for ML-DSA-87
pub(crate) const MAX_LEN: usize = 4627;

/// A public key signature returned from a signing operation.
#[derive(Clone, Copy)]
pub struct Signature {
    value: [u8; MAX_LEN],
    len: usize,
}

impl Signature {
    // Panics if `value` is too long.
    pub(crate) fn new<F>(fill: F) -> Self
    where
        F: FnOnce(&mut [u8; MAX_LEN]) -> usize,
    {
        let mut r = Self {
            value: [0; MAX_LEN],
            len: 0,
        };
        r.len = fill(&mut r.value);
        r
    }
}

impl AsRef<[u8]> for Signature {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        &self.value[..self.len]
    }
}

/// Key pairs for signing messages (private key and public key).
pub trait KeyPair: Debug + Send + Sized + Sync {
    /// The type of the public key.
    type PublicKey: AsRef<[u8]> + Debug + Clone + Send + Sized + Sync;

    /// The public key for the key pair.
    fn public_key(&self) -> &Self::PublicKey;
}

/// A signature verification algorithm.
pub trait VerificationAlgorithm: Debug + Sync + sealed::Sealed {
    /// Verify the signature `signature` of message `msg` with the public key
    /// `public_key`.
    ///
    // # FIPS
    // The following conditions must be met:
    // * RSA Key Sizes: 1024, 2048, 3072, 4096
    // * NIST Elliptic Curves: P256, P384, P521
    // * Digest Algorithms: SHA1, SHA256, SHA384, SHA512
    //
    /// # Errors
    /// `error::Unspecified` if inputs not verified.
    #[cfg(feature = "ring-sig-verify")]
    #[deprecated(note = "please use `VerificationAlgorithm::verify_sig` instead")]
    fn verify(
        &self,
        public_key: Input<'_>,
        msg: Input<'_>,
        signature: Input<'_>,
    ) -> Result<(), error::Unspecified>;

    /// Verify the signature `signature` of message `msg` with the public key
    /// `public_key`.
    ///
    // # FIPS
    // The following conditions must be met:
    // * RSA Key Sizes: 1024, 2048, 3072, 4096
    // * NIST Elliptic Curves: P256, P384, P521
    // * Digest Algorithms: SHA1, SHA256, SHA384, SHA512
    //
    /// # Errors
    /// `error::Unspecified` if inputs not verified.
    fn verify_sig(
        &self,
        public_key: &[u8],
        msg: &[u8],
        signature: &[u8],
    ) -> Result<(), error::Unspecified>;
}

/// An unparsed, possibly malformed, public key for signature verification.
#[derive(Clone)]
pub struct UnparsedPublicKey<B: AsRef<[u8]>> {
    algorithm: &'static dyn VerificationAlgorithm,
    bytes: B,
}

impl<B: Copy + AsRef<[u8]>> Copy for UnparsedPublicKey<B> {}

impl<B: AsRef<[u8]>> Debug for UnparsedPublicKey<B> {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        f.write_str(&format!(
            "UnparsedPublicKey {{ algorithm: {:?}, bytes: \"{}\" }}",
            self.algorithm,
            hex::encode(self.bytes.as_ref())
        ))
    }
}

impl<B: AsRef<[u8]>> UnparsedPublicKey<B> {
    /// Construct a new `UnparsedPublicKey`.
    ///
    /// No validation of `bytes` is done until `verify()` is called.
    #[inline]
    pub fn new(algorithm: &'static dyn VerificationAlgorithm, bytes: B) -> Self {
        Self { algorithm, bytes }
    }

    /// Parses the public key and verifies `signature` is a valid signature of
    /// `message` using it.
    ///
    /// See the [`crate::signature`] module-level documentation for examples.
    ///
    // # FIPS
    // The following conditions must be met:
    // * RSA Key Sizes: 1024, 2048, 3072, 4096
    // * NIST Elliptic Curves: P256, P384, P521
    // * Digest Algorithms: SHA1, SHA256, SHA384, SHA512
    //
    /// # Errors
    /// `error::Unspecified` if inputs not verified.
    #[inline]
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), error::Unspecified> {
        self.algorithm
            .verify_sig(self.bytes.as_ref(), message, signature)
    }
}

/// Verification of signatures using RSA keys of 1024-8192 bits, PKCS#1.5 padding, and SHA-1.
pub static RSA_PKCS1_1024_8192_SHA1_FOR_LEGACY_USE_ONLY: RsaParameters = RsaParameters::new(
    &digest::SHA1_FOR_LEGACY_USE_ONLY,
    &rsa::signature::RsaPadding::RSA_PKCS1_PADDING,
    1024..=8192,
    &RsaVerificationAlgorithmId::RSA_PKCS1_1024_8192_SHA1_FOR_LEGACY_USE_ONLY,
);

/// Verification of signatures using RSA keys of 1024-8192 bits, PKCS#1.5 padding, and SHA-256.
pub static RSA_PKCS1_1024_8192_SHA256_FOR_LEGACY_USE_ONLY: RsaParameters = RsaParameters::new(
    &digest::SHA256,
    &rsa::signature::RsaPadding::RSA_PKCS1_PADDING,
    1024..=8192,
    &RsaVerificationAlgorithmId::RSA_PKCS1_1024_8192_SHA256_FOR_LEGACY_USE_ONLY,
);

/// Verification of signatures using RSA keys of 1024-8192 bits, PKCS#1.5 padding, and SHA-512.
pub static RSA_PKCS1_1024_8192_SHA512_FOR_LEGACY_USE_ONLY: RsaParameters = RsaParameters::new(
    &digest::SHA512,
    &rsa::signature::RsaPadding::RSA_PKCS1_PADDING,
    1024..=8192,
    &RsaVerificationAlgorithmId::RSA_PKCS1_1024_8192_SHA512_FOR_LEGACY_USE_ONLY,
);

/// Verification of signatures using RSA keys of 2048-8192 bits, PKCS#1.5 padding, and SHA-1.
pub static RSA_PKCS1_2048_8192_SHA1_FOR_LEGACY_USE_ONLY: RsaParameters = RsaParameters::new(
    &digest::SHA1_FOR_LEGACY_USE_ONLY,
    &rsa::signature::RsaPadding::RSA_PKCS1_PADDING,
    2048..=8192,
    &RsaVerificationAlgorithmId::RSA_PKCS1_2048_8192_SHA1_FOR_LEGACY_USE_ONLY,
);

/// Verification of signatures using RSA keys of 2048-8192 bits, PKCS#1.5 padding, and SHA-256.
pub static RSA_PKCS1_2048_8192_SHA256: RsaParameters = RsaParameters::new(
    &digest::SHA256,
    &rsa::signature::RsaPadding::RSA_PKCS1_PADDING,
    2048..=8192,
    &RsaVerificationAlgorithmId::RSA_PKCS1_2048_8192_SHA256,
);

/// Verification of signatures using RSA keys of 2048-8192 bits, PKCS#1.5 padding, and SHA-384.
pub static RSA_PKCS1_2048_8192_SHA384: RsaParameters = RsaParameters::new(
    &digest::SHA384,
    &rsa::signature::RsaPadding::RSA_PKCS1_PADDING,
    2048..=8192,
    &RsaVerificationAlgorithmId::RSA_PKCS1_2048_8192_SHA384,
);

/// Verification of signatures using RSA keys of 2048-8192 bits, PKCS#1.5 padding, and SHA-512.
pub static RSA_PKCS1_2048_8192_SHA512: RsaParameters = RsaParameters::new(
    &digest::SHA512,
    &rsa::signature::RsaPadding::RSA_PKCS1_PADDING,
    2048..=8192,
    &RsaVerificationAlgorithmId::RSA_PKCS1_2048_8192_SHA512,
);

/// Verification of signatures using RSA keys of 3072-8192 bits, PKCS#1.5 padding, and SHA-384.
pub static RSA_PKCS1_3072_8192_SHA384: RsaParameters = RsaParameters::new(
    &digest::SHA384,
    &rsa::signature::RsaPadding::RSA_PKCS1_PADDING,
    3072..=8192,
    &RsaVerificationAlgorithmId::RSA_PKCS1_3072_8192_SHA384,
);

/// Verification of signatures using RSA keys of 2048-8192 bits, PSS padding, and SHA-256.
pub static RSA_PSS_2048_8192_SHA256: RsaParameters = RsaParameters::new(
    &digest::SHA256,
    &rsa::signature::RsaPadding::RSA_PKCS1_PSS_PADDING,
    2048..=8192,
    &RsaVerificationAlgorithmId::RSA_PSS_2048_8192_SHA256,
);

/// Verification of signatures using RSA keys of 2048-8192 bits, PSS padding, and SHA-384.
pub static RSA_PSS_2048_8192_SHA384: RsaParameters = RsaParameters::new(
    &digest::SHA384,
    &rsa::signature::RsaPadding::RSA_PKCS1_PSS_PADDING,
    2048..=8192,
    &RsaVerificationAlgorithmId::RSA_PSS_2048_8192_SHA384,
);

/// Verification of signatures using RSA keys of 2048-8192 bits, PSS padding, and SHA-512.
pub static RSA_PSS_2048_8192_SHA512: RsaParameters = RsaParameters::new(
    &digest::SHA512,
    &rsa::signature::RsaPadding::RSA_PKCS1_PSS_PADDING,
    2048..=8192,
    &RsaVerificationAlgorithmId::RSA_PSS_2048_8192_SHA512,
);

/// RSA PSS padding using SHA-256 for RSA signatures.
pub static RSA_PSS_SHA256: RsaSignatureEncoding = RsaSignatureEncoding::new(
    &digest::SHA256,
    &rsa::signature::RsaPadding::RSA_PKCS1_PSS_PADDING,
    &RsaSigningAlgorithmId::RSA_PSS_SHA256,
);

/// RSA PSS padding using SHA-384 for RSA signatures.
pub static RSA_PSS_SHA384: RsaSignatureEncoding = RsaSignatureEncoding::new(
    &digest::SHA384,
    &rsa::signature::RsaPadding::RSA_PKCS1_PSS_PADDING,
    &RsaSigningAlgorithmId::RSA_PSS_SHA384,
);

/// RSA PSS padding using SHA-512 for RSA signatures.
pub static RSA_PSS_SHA512: RsaSignatureEncoding = RsaSignatureEncoding::new(
    &digest::SHA512,
    &rsa::signature::RsaPadding::RSA_PKCS1_PSS_PADDING,
    &RsaSigningAlgorithmId::RSA_PSS_SHA512,
);

/// PKCS#1 1.5 padding using SHA-256 for RSA signatures.
pub static RSA_PKCS1_SHA256: RsaSignatureEncoding = RsaSignatureEncoding::new(
    &digest::SHA256,
    &rsa::signature::RsaPadding::RSA_PKCS1_PADDING,
    &RsaSigningAlgorithmId::RSA_PKCS1_SHA256,
);

/// PKCS#1 1.5 padding using SHA-384 for RSA signatures.
pub static RSA_PKCS1_SHA384: RsaSignatureEncoding = RsaSignatureEncoding::new(
    &digest::SHA384,
    &rsa::signature::RsaPadding::RSA_PKCS1_PADDING,
    &RsaSigningAlgorithmId::RSA_PKCS1_SHA384,
);

/// PKCS#1 1.5 padding using SHA-512 for RSA signatures.
pub static RSA_PKCS1_SHA512: RsaSignatureEncoding = RsaSignatureEncoding::new(
    &digest::SHA512,
    &rsa::signature::RsaPadding::RSA_PKCS1_PADDING,
    &RsaSigningAlgorithmId::RSA_PKCS1_SHA512,
);

/// Verification of fixed-length (PKCS#11 style) ECDSA signatures using the P-256 curve and SHA-256.
pub static ECDSA_P256_SHA256_FIXED: EcdsaVerificationAlgorithm = EcdsaVerificationAlgorithm {
    id: &ec::signature::AlgorithmID::ECDSA_P256,
    digest: &digest::SHA256,
    sig_format: EcdsaSignatureFormat::Fixed,
};

/// Verification of fixed-length (PKCS#11 style) ECDSA signatures using the P-384 curve and SHA-384.
pub static ECDSA_P384_SHA384_FIXED: EcdsaVerificationAlgorithm = EcdsaVerificationAlgorithm {
    id: &ec::signature::AlgorithmID::ECDSA_P384,
    digest: &digest::SHA384,
    sig_format: EcdsaSignatureFormat::Fixed,
};

/// Verification of fixed-length (PKCS#11 style) ECDSA signatures using the P-384 curve and SHA3-384.
pub static ECDSA_P384_SHA3_384_FIXED: EcdsaVerificationAlgorithm = EcdsaVerificationAlgorithm {
    id: &ec::signature::AlgorithmID::ECDSA_P384,
    digest: &digest::SHA3_384,
    sig_format: EcdsaSignatureFormat::Fixed,
};

/// Verification of fixed-length (PKCS#11 style) ECDSA signatures using the P-521 curve and SHA-1.
pub static ECDSA_P521_SHA1_FIXED: EcdsaVerificationAlgorithm = EcdsaVerificationAlgorithm {
    id: &ec::signature::AlgorithmID::ECDSA_P521,
    digest: &digest::SHA1_FOR_LEGACY_USE_ONLY,
    sig_format: EcdsaSignatureFormat::Fixed,
};

/// Verification of fixed-length (PKCS#11 style) ECDSA signatures using the P-521 curve and SHA-224.
pub static ECDSA_P521_SHA224_FIXED: EcdsaVerificationAlgorithm = EcdsaVerificationAlgorithm {
    id: &ec::signature::AlgorithmID::ECDSA_P521,
    digest: &digest::SHA224,
    sig_format: EcdsaSignatureFormat::Fixed,
};

/// Verification of fixed-length (PKCS#11 style) ECDSA signatures using the P-521 curve and SHA-256.
pub static ECDSA_P521_SHA256_FIXED: EcdsaVerificationAlgorithm = EcdsaVerificationAlgorithm {
    id: &ec::signature::AlgorithmID::ECDSA_P521,
    digest: &digest::SHA256,
    sig_format: EcdsaSignatureFormat::Fixed,
};

/// Verification of fixed-length (PKCS#11 style) ECDSA signatures using the P-521 curve and SHA-384.
pub static ECDSA_P521_SHA384_FIXED: EcdsaVerificationAlgorithm = EcdsaVerificationAlgorithm {
    id: &ec::signature::AlgorithmID::ECDSA_P521,
    digest: &digest::SHA384,
    sig_format: EcdsaSignatureFormat::Fixed,
};

/// Verification of fixed-length (PKCS#11 style) ECDSA signatures using the P-521 curve and SHA-512.
pub static ECDSA_P521_SHA512_FIXED: EcdsaVerificationAlgorithm = EcdsaVerificationAlgorithm {
    id: &ec::signature::AlgorithmID::ECDSA_P521,
    digest: &digest::SHA512,
    sig_format: EcdsaSignatureFormat::Fixed,
};

/// Verification of fixed-length (PKCS#11 style) ECDSA signatures using the P-521 curve and SHA3-512.
pub static ECDSA_P521_SHA3_512_FIXED: EcdsaVerificationAlgorithm = EcdsaVerificationAlgorithm {
    id: &ec::signature::AlgorithmID::ECDSA_P521,
    digest: &digest::SHA3_512,
    sig_format: EcdsaSignatureFormat::Fixed,
};

/// Verification of fixed-length (PKCS#11 style) ECDSA signatures using the P-256K1 curve and SHA-256.
pub static ECDSA_P256K1_SHA256_FIXED: EcdsaVerificationAlgorithm = EcdsaVerificationAlgorithm {
    id: &ec::signature::AlgorithmID::ECDSA_P256K1,
    digest: &digest::SHA256,
    sig_format: EcdsaSignatureFormat::Fixed,
};

/// Verification of fixed-length (PKCS#11 style) ECDSA signatures using the P-256K1 curve and SHA3-256.
pub static ECDSA_P256K1_SHA3_256_FIXED: EcdsaVerificationAlgorithm = EcdsaVerificationAlgorithm {
    id: &ec::signature::AlgorithmID::ECDSA_P256K1,
    digest: &digest::SHA3_256,
    sig_format: EcdsaSignatureFormat::Fixed,
};

/// Verification of ASN.1 DER-encoded ECDSA signatures using the P-256 curve and SHA-256.
pub static ECDSA_P256_SHA256_ASN1: EcdsaVerificationAlgorithm = EcdsaVerificationAlgorithm {
    id: &ec::signature::AlgorithmID::ECDSA_P256,
    digest: &digest::SHA256,
    sig_format: EcdsaSignatureFormat::ASN1,
};

/// *Not recommended.* Verification of ASN.1 DER-encoded ECDSA signatures using the P-256 curve and SHA-384.
pub static ECDSA_P256_SHA384_ASN1: EcdsaVerificationAlgorithm = EcdsaVerificationAlgorithm {
    id: &ec::signature::AlgorithmID::ECDSA_P256,
    digest: &digest::SHA384,
    sig_format: EcdsaSignatureFormat::ASN1,
};

/// *Not recommended.* Verification of ASN.1 DER-encoded ECDSA signatures using the P-384 curve and SHA-256.
pub static ECDSA_P384_SHA256_ASN1: EcdsaVerificationAlgorithm = EcdsaVerificationAlgorithm {
    id: &ec::signature::AlgorithmID::ECDSA_P384,
    digest: &digest::SHA256,
    sig_format: EcdsaSignatureFormat::ASN1,
};

/// Verification of ASN.1 DER-encoded ECDSA signatures using the P-384 curve and SHA-384.
pub static ECDSA_P384_SHA384_ASN1: EcdsaVerificationAlgorithm = EcdsaVerificationAlgorithm {
    id: &ec::signature::AlgorithmID::ECDSA_P384,
    digest: &digest::SHA384,
    sig_format: EcdsaSignatureFormat::ASN1,
};

/// Verification of ASN.1 DER-encoded ECDSA signatures using the P-384 curve and SHA3-384.
pub static ECDSA_P384_SHA3_384_ASN1: EcdsaVerificationAlgorithm = EcdsaVerificationAlgorithm {
    id: &ec::signature::AlgorithmID::ECDSA_P384,
    digest: &digest::SHA3_384,
    sig_format: EcdsaSignatureFormat::ASN1,
};

/// Verification of ASN.1 DER-encoded ECDSA signatures using the P-521 curve and SHA-1.
pub static ECDSA_P521_SHA1_ASN1: EcdsaVerificationAlgorithm = EcdsaVerificationAlgorithm {
    id: &ec::signature::AlgorithmID::ECDSA_P521,
    digest: &digest::SHA1_FOR_LEGACY_USE_ONLY,
    sig_format: EcdsaSignatureFormat::ASN1,
};

/// Verification of ASN.1 DER-encoded ECDSA signatures using the P-521 curve and SHA-224.
pub static ECDSA_P521_SHA224_ASN1: EcdsaVerificationAlgorithm = EcdsaVerificationAlgorithm {
    id: &ec::signature::AlgorithmID::ECDSA_P521,
    digest: &digest::SHA224,
    sig_format: EcdsaSignatureFormat::ASN1,
};

/// Verification of ASN.1 DER-encoded ECDSA signatures using the P-521 curve and SHA-256.
pub static ECDSA_P521_SHA256_ASN1: EcdsaVerificationAlgorithm = EcdsaVerificationAlgorithm {
    id: &ec::signature::AlgorithmID::ECDSA_P521,
    digest: &digest::SHA256,
    sig_format: EcdsaSignatureFormat::ASN1,
};

/// Verification of ASN.1 DER-encoded ECDSA signatures using the P-521 curve and SHA-384.
pub static ECDSA_P521_SHA384_ASN1: EcdsaVerificationAlgorithm = EcdsaVerificationAlgorithm {
    id: &ec::signature::AlgorithmID::ECDSA_P521,
    digest: &digest::SHA384,
    sig_format: EcdsaSignatureFormat::ASN1,
};

/// Verification of ASN.1 DER-encoded ECDSA signatures using the P-521 curve and SHA-512.
pub static ECDSA_P521_SHA512_ASN1: EcdsaVerificationAlgorithm = EcdsaVerificationAlgorithm {
    id: &ec::signature::AlgorithmID::ECDSA_P521,
    digest: &digest::SHA512,
    sig_format: EcdsaSignatureFormat::ASN1,
};

/// Verification of ASN.1 DER-encoded ECDSA signatures using the P-521 curve and SHA3-512.
pub static ECDSA_P521_SHA3_512_ASN1: EcdsaVerificationAlgorithm = EcdsaVerificationAlgorithm {
    id: &ec::signature::AlgorithmID::ECDSA_P521,
    digest: &digest::SHA3_512,
    sig_format: EcdsaSignatureFormat::ASN1,
};

/// Verification of ASN.1 DER-encoded ECDSA signatures using the P-256K1 curve and SHA-256.
pub static ECDSA_P256K1_SHA256_ASN1: EcdsaVerificationAlgorithm = EcdsaVerificationAlgorithm {
    id: &ec::signature::AlgorithmID::ECDSA_P256K1,
    digest: &digest::SHA256,
    sig_format: EcdsaSignatureFormat::ASN1,
};

/// Verification of ASN.1 DER-encoded ECDSA signatures using the P-256K1 curve and SHA3-256.
pub static ECDSA_P256K1_SHA3_256_ASN1: EcdsaVerificationAlgorithm = EcdsaVerificationAlgorithm {
    id: &ec::signature::AlgorithmID::ECDSA_P256K1,
    digest: &digest::SHA3_256,
    sig_format: EcdsaSignatureFormat::ASN1,
};

/// Signing of fixed-length (PKCS#11 style) ECDSA signatures using the P-256 curve and SHA-256.
pub static ECDSA_P256_SHA256_FIXED_SIGNING: EcdsaSigningAlgorithm =
    EcdsaSigningAlgorithm(&ECDSA_P256_SHA256_FIXED);

/// Signing of fixed-length (PKCS#11 style) ECDSA signatures using the P-384 curve and SHA-384.
pub static ECDSA_P384_SHA384_FIXED_SIGNING: EcdsaSigningAlgorithm =
    EcdsaSigningAlgorithm(&ECDSA_P384_SHA384_FIXED);

/// Signing of fixed-length (PKCS#11 style) ECDSA signatures using the P-384 curve and SHA3-384.
pub static ECDSA_P384_SHA3_384_FIXED_SIGNING: EcdsaSigningAlgorithm =
    EcdsaSigningAlgorithm(&ECDSA_P384_SHA3_384_FIXED);

/// Signing of fixed-length (PKCS#11 style) ECDSA signatures using the P-521 curve and SHA-224.
/// # ⚠️ Warning
/// The security design strength of SHA-224 digests is less then security strength of P-521.
/// This scheme should only be used for backwards compatibility purposes.
pub static ECDSA_P521_SHA224_FIXED_SIGNING: EcdsaSigningAlgorithm =
    EcdsaSigningAlgorithm(&ECDSA_P521_SHA224_FIXED);

/// Signing of fixed-length (PKCS#11 style) ECDSA signatures using the P-521 curve and SHA-256.
/// # ⚠️ Warning
/// The security design strength of SHA-256 digests is less then security strength of P-521.
/// This scheme should only be used for backwards compatibility purposes.
pub static ECDSA_P521_SHA256_FIXED_SIGNING: EcdsaSigningAlgorithm =
    EcdsaSigningAlgorithm(&ECDSA_P521_SHA256_FIXED);

/// Signing of fixed-length (PKCS#11 style) ECDSA signatures using the P-521 curve and SHA-384.
/// # ⚠️ Warning
/// The security design strength of SHA-384 digests is less then security strength of P-521.
/// This scheme should only be used for backwards compatibility purposes.
pub static ECDSA_P521_SHA384_FIXED_SIGNING: EcdsaSigningAlgorithm =
    EcdsaSigningAlgorithm(&ECDSA_P521_SHA384_FIXED);

/// Signing of fixed-length (PKCS#11 style) ECDSA signatures using the P-521 curve and SHA-512.
pub static ECDSA_P521_SHA512_FIXED_SIGNING: EcdsaSigningAlgorithm =
    EcdsaSigningAlgorithm(&ECDSA_P521_SHA512_FIXED);

/// Signing of fixed-length (PKCS#11 style) ECDSA signatures using the P-521 curve and SHA3-512.
pub static ECDSA_P521_SHA3_512_FIXED_SIGNING: EcdsaSigningAlgorithm =
    EcdsaSigningAlgorithm(&ECDSA_P521_SHA3_512_FIXED);

/// Signing of fixed-length (PKCS#11 style) ECDSA signatures using the P-256K1 curve and SHA-256.
pub static ECDSA_P256K1_SHA256_FIXED_SIGNING: EcdsaSigningAlgorithm =
    EcdsaSigningAlgorithm(&ECDSA_P256K1_SHA256_FIXED);

/// Signing of fixed-length (PKCS#11 style) ECDSA signatures using the P-256K1 curve and SHA3-256.
pub static ECDSA_P256K1_SHA3_256_FIXED_SIGNING: EcdsaSigningAlgorithm =
    EcdsaSigningAlgorithm(&ECDSA_P256K1_SHA3_256_FIXED);

/// Signing of ASN.1 DER-encoded ECDSA signatures using the P-256 curve and SHA-256.
pub static ECDSA_P256_SHA256_ASN1_SIGNING: EcdsaSigningAlgorithm =
    EcdsaSigningAlgorithm(&ECDSA_P256_SHA256_ASN1);

/// Signing of ASN.1 DER-encoded ECDSA signatures using the P-384 curve and SHA-384.
pub static ECDSA_P384_SHA384_ASN1_SIGNING: EcdsaSigningAlgorithm =
    EcdsaSigningAlgorithm(&ECDSA_P384_SHA384_ASN1);

/// Signing of ASN.1 DER-encoded ECDSA signatures using the P-384 curve and SHA3-384.
pub static ECDSA_P384_SHA3_384_ASN1_SIGNING: EcdsaSigningAlgorithm =
    EcdsaSigningAlgorithm(&ECDSA_P384_SHA3_384_ASN1);

/// Signing of ASN.1 DER-encoded ECDSA signatures using the P-521 curve and SHA-224.
/// # ⚠️ Warning
/// The security design strength of SHA-224 digests is less then security strength of P-521.
/// This scheme should only be used for backwards compatibility purposes.
pub static ECDSA_P521_SHA224_ASN1_SIGNING: EcdsaSigningAlgorithm =
    EcdsaSigningAlgorithm(&ECDSA_P521_SHA224_ASN1);

/// Signing of ASN.1 DER-encoded ECDSA signatures using the P-521 curve and SHA-256.
/// # ⚠️ Warning
/// The security design strength of SHA-256 digests is less then security strength of P-521.
/// This scheme should only be used for backwards compatibility purposes.
pub static ECDSA_P521_SHA256_ASN1_SIGNING: EcdsaSigningAlgorithm =
    EcdsaSigningAlgorithm(&ECDSA_P521_SHA256_ASN1);

/// Signing of ASN.1 DER-encoded ECDSA signatures using the P-521 curve and SHA-384.
/// # ⚠️ Warning
/// The security design strength of SHA-384 digests is less then security strength of P-521.
/// This scheme should only be used for backwards compatibility purposes.
pub static ECDSA_P521_SHA384_ASN1_SIGNING: EcdsaSigningAlgorithm =
    EcdsaSigningAlgorithm(&ECDSA_P521_SHA384_ASN1);

/// Signing of ASN.1 DER-encoded ECDSA signatures using the P-521 curve and SHA-512.
pub static ECDSA_P521_SHA512_ASN1_SIGNING: EcdsaSigningAlgorithm =
    EcdsaSigningAlgorithm(&ECDSA_P521_SHA512_ASN1);

/// Signing of ASN.1 DER-encoded ECDSA signatures using the P-521 curve and SHA3-512.
pub static ECDSA_P521_SHA3_512_ASN1_SIGNING: EcdsaSigningAlgorithm =
    EcdsaSigningAlgorithm(&ECDSA_P521_SHA3_512_ASN1);

/// Signing of ASN.1 DER-encoded ECDSA signatures using the P-256K1 curve and SHA-256.
pub static ECDSA_P256K1_SHA256_ASN1_SIGNING: EcdsaSigningAlgorithm =
    EcdsaSigningAlgorithm(&ECDSA_P256K1_SHA256_ASN1);

/// Signing of ASN.1 DER-encoded ECDSA signatures using the P-256K1 curve and SHA3-256.
pub static ECDSA_P256K1_SHA3_256_ASN1_SIGNING: EcdsaSigningAlgorithm =
    EcdsaSigningAlgorithm(&ECDSA_P256K1_SHA3_256_ASN1);

/// Verification of Ed25519 signatures.
pub static ED25519: EdDSAParameters = EdDSAParameters {};

#[cfg(test)]
mod tests {
    use regex::Regex;

    use crate::rand::{generate, SystemRandom};
    use crate::signature::{UnparsedPublicKey, ED25519};

    #[cfg(feature = "fips")]
    mod fips;

    #[test]
    fn test_unparsed_public_key() {
        let random_pubkey: [u8; 32] = generate(&SystemRandom::new()).unwrap().expose();
        let unparsed_pubkey = UnparsedPublicKey::new(&ED25519, random_pubkey);
        let unparsed_pubkey_debug = format!("{:?}", &unparsed_pubkey);

        #[allow(clippy::clone_on_copy)]
        let unparsed_pubkey_clone = unparsed_pubkey.clone();
        assert_eq!(unparsed_pubkey_debug, format!("{unparsed_pubkey_clone:?}"));
        let pubkey_re = Regex::new(
            "UnparsedPublicKey \\{ algorithm: EdDSAParameters, bytes: \"[0-9a-f]{64}\" \\}",
        )
        .unwrap();

        assert!(pubkey_re.is_match(&unparsed_pubkey_debug));
    }
}
