// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

#![cfg(feature = "unstable")]
#![allow(missing_docs)]

//! Unstable aws-lc-rs features.
//!
//! # ⚠️ Warning
//! Features contained within this module, or child modules are subject to changes, relocation,
//! or removal across minor releases, and thus are not subject to semantic versioning policies.
#[deprecated(note = "use  `aws_lc_rs::kdf` instead")]
pub mod kdf;

#[deprecated(note = "use `aws_lc_rs::kem` instead")]
pub mod kem;

#[cfg(not(feature = "fips"))]
pub mod signature;
