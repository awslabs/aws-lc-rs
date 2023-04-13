# AWS Libcrypto for Rust
[*aws-lc-rs*](aws-lc-rs/README.md) is a cryptographic library using [AWS-LC](https://github.com/aws/aws-lc) for its cryptographic operations.
This library strives to be API-compatible with the popular Rust library named 
[ring](https://github.com/briansmith/ring). It uses either the auto-generated [*aws-lc-sys*](aws-lc-sys/README.md) or [*aws-lc-fips-sys*](aws-lc-fips-sys/README.md) Foreign Function Interface (FFI) crates found in this
repository for invoking *AWS-LC*.

## Crates

### [aws-lc-rs](aws-lc-rs/README.md)
A *ring*-compatible crypto library using the cryptographic operations provided by
[*AWS-LC*](https://github.com/awslabs/aws-lc) using either *aws-lc-sys* or *aws-lc-fips-sys*.

### [aws-lc-sys](aws-lc-sys/README.md)
**Autogenerated** Low-level AWS-LC bindings for the Rust programming language.
We do not recommend directly relying on these bindings.

### [aws-lc-fips-sys](aws-lc-fips-sys/README.md)
**Autogenerated** Low-level AWS-LC bindings for the Rust programming language. Providing **experimental** FIPS support.
We do not recommend directly relying on these bindings. This crate uses [AWS-LC](https://github.com/aws/aws-lc/tree/fips-2022-11-02),
which been submitted to an accredited lab for FIPS validation testing, and upon completion will be submitted to NIST
for certification. Once NIST grants a validation certificate to AWS-LC, we will make an announcement to Rust developers
on how to leverage the FIPS mode using [aws-lc-rs](https://crates.io/crates/aws-lc-rs).

# Motivation
As there exists no standard Rust cryptographic API, we chose the Rust cryptographic library ring (v0.16) as our target API to 
build higher-level Rust bindings on top of *AWS-LC*. *ring* is one of the most used cryptographic APIs in the Rust community,
but lacked support for alternate cryptographic implementations. Our desire to build a Rust API on top of AWS-LC is to be able 
to offer a FIPS validated Rust option for our customers. AWS-LC has been validated by an accredited lab,
and was submitted to NIST on 2021-12-23. *aws-lc-rs* adds to the Rust cryptographic landscape with features such as an 
experimental FIPS operation mode, a stable API, and a process for
[vulnerability reporting and disclosure](#security-notification-process).

## Questions, Feedback and Contributing

* [Submit an non-security Bug/Issue/Request](https://github.com/awslabs/aws-lc-rust/issues/new/choose)
* [API documentation](https://docs.rs/aws-lc-rs/)
* [Fork our repo](https://github.com/awslabs/aws-lc-rust/fork)

If you have any questions about submitting PR's, opening issues, *aws-lc-rs* API usage or
any similar topic, we have a public chatroom available here to answer your questions
on [Gitter](https://gitter.im/aws/aws-lc).

Otherwise, if you think you might have found a security impacting issue, please instead
follow our *Security Notification Process* below.

## Security Notification Process

If you discover a potential security issue in *AWS-LC* or *aws-lc-rs*, we ask that you notify AWS
Security via our
[vulnerability reporting page](https://aws.amazon.com/security/vulnerability-reporting/).
Please do **not** create a public GitHub issue.

If you package or distribute *aws-lc-rs*, or use *aws-lc-rs* as part of a large multi-user service,
you may be eligible for pre-notification of future *aws-lc-rs* releases.
Please contact aws-lc-pre-notifications@amazon.com.

## License

This library is licensed under the Apache-2.0 or the ISC License.
