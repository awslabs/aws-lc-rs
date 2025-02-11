// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

pub use crate::pqdsa::key_pair::PqdsaKeyPair;
pub use crate::pqdsa::signature::{
    PqdsaSigningAlgorithm, PqdsaVerificationAlgorithm, PublicKey as PqdsaPublicKey,
};

use crate::pqdsa::AlgorithmID;
pub static MLDSA_44: PqdsaVerificationAlgorithm = PqdsaVerificationAlgorithm {
    id: &AlgorithmID::MLDSA_44,
};

pub static MLDSA_65: PqdsaVerificationAlgorithm = PqdsaVerificationAlgorithm {
    id: &AlgorithmID::MLDSA_65,
};

pub static MLDSA_87: PqdsaVerificationAlgorithm = PqdsaVerificationAlgorithm {
    id: &AlgorithmID::MLDSA_87,
};

pub static MLDSA_44_SIGNING: PqdsaSigningAlgorithm = PqdsaSigningAlgorithm(&MLDSA_44);

pub static MLDSA_65_SIGNING: PqdsaSigningAlgorithm = PqdsaSigningAlgorithm(&MLDSA_65);

pub static MLDSA_87_SIGNING: PqdsaSigningAlgorithm = PqdsaSigningAlgorithm(&MLDSA_87);
