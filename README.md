# AWS Libcrypto for Rust (aws-lc-rust)
*aws-lc-rust* is a cryptographic library using [AWS-LC](https://github.com/aws/aws-lc) for its cryptographic operations.
This library strives to be API-compatible with the popular Rust library named 
[ring](https://github.com/briansmith/ring).

## Build
See [BUILDING.md](BUILDING.md) for instructions on building.

### Feature Flags
* `alloc` (*default*)
Allows implementation to allocate values of unbounded size. (The meaning of this feature differs from the “alloc” 
feature of *ring*.) Currently, this is only required by the `io::writer` module.

* `ring-io` (*default*)
This feature enables the `io` module. Requires `untrusted = "0.7.1"`.

* `ring-sig-verify` (*default*)
This feature enables Trait method `signature::VerificationAlgorithm::verify`. This method is deprecated,
use `signature::VerificationAlgorithm::verify_sig` instead. Requires `untrusted = "0.7.1"`.

* `ring-benchmarks`
This feature enables benchmarks to run against `ring`.

* `asan`
Performs an “address sanitizer” build of *AWS-LC*. This can be used to help detect memory leaks. See the
“[Sanitizer](https://doc.rust-lang.org/beta/unstable-book/compiler-flags/sanitizer.html)”
section of the Rust Unstable Book.

* `bindgen`
Enables generation and building of the *aws-lc-sys* dependency crate on platforms not provided with pre-generated bindings.

## *ring*-compatibility

Although this library attempts to be fully compatible with *ring*, there are a few places where our behavior is 
observably different.

* Our implementation requires the `std` library. We currently do not support a `#![no_std]` build.
* We can only support a subset of the platforms supported by [`aws-lc-sys`](https://crates.io/crates/aws-lc-sys). We currently support Mac and Linux, both 
x86-64 and aarch64.
* Due to its dependence on AWS-LC, this library does not support generating or parsing PKCS#8 v2. 
Thus, the `Ed25519KeyPair::generate_pkcs8` and `Ed25519KeyPair::from_pkcs8` implementations always returns an error. 
Instead, you can use `Ed25519KeyPair::generate_pkcs8v1` for generating and `Ed25519KeyPair::from_pkcs8_maybe_unchecked`
for parsing PKCS#8 v1.
* When parsing fails, the `KeyRejected` response may differ from *ring*’s response on the same input.
* The implementations for several functions use internally generated pseudo-randomness and 
ignore the provided `SecureRandom` parameter. These functions include: `Ed25519KeyPair::generate_pkcs8`, 
`EcdsaKeyPair::generate_pkcs8`, `EcdsaKeyPair::sign`, and `RsaKeyPair::sign`.


## Questions, Feedback and Contributing

* [Submit an non-security Bug/Issue/Request](https://github.com/awslabs/aws-lc-rust/issues/new/choose)
* [API documentation](https://docs.rs/aws-lc-rust/)
* [Fork our repo](https://github.com/awslabs/aws-lc-rust/fork)

If you have any questions about submitting PR's, opening issues, *aws-lc-rust* API usage or
any similar topic, we have a public chatroom available here to answer your questions
on [Gitter](https://gitter.im/aws/aws-lc).

Otherwise, if you think you might have found a security impacting issue, please instead
follow our *Security Notification Process* below.

## Security Notification Process

If you discover a potential security issue in *AWS-LC* or *aws-lc-rust*, we ask that you notify AWS
Security via our
[vulnerability reporting page](https://aws.amazon.com/security/vulnerability-reporting/).
Please do **not** create a public GitHub issue.

If you package or distribute *aws-lc-rust*, or use *aws-lc-rust* as part of a large multi-user service,
you may be eligible for pre-notification of future *aws-lc-rust* releases.
Please contact aws-lc-pre-notifications@amazon.com.

## License

This library is licensed under the Apache-2.0 or the ISC License.
