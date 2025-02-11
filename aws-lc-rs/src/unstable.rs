// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

#![cfg(feature = "unstable")]
#![allow(missing_docs)]

#[cfg(not(feature = "fips"))]
pub mod signature;
