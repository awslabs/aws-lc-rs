// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

//! Serialization formats

use crate::buffer::Buffer;
use paste::paste;

macro_rules! generated_encodings {
    ($($name:ident),*) => { paste! {
        use core::fmt::{Debug, Error, Formatter};
        use core::ops::Deref;
        mod buffer_type {
            $(
                pub struct [<$name Type>] {
                    _priv: (),
                }
            )*
        }
        $(
            /// Serialized bytes
            pub struct $name<'a>(Buffer<'a, buffer_type::[<$name Type>]>);

            impl<'a> Deref for $name<'a> {
                type Target = Buffer<'a, buffer_type::[<$name Type>]>;

                fn deref(&self) -> &Self::Target {
                    &self.0
                }
            }

            impl $name<'static> {
                #[allow(dead_code)]
                pub(crate) fn new(owned: Vec<u8>) -> Self {
                    Self(Buffer::new(owned))
                }
                #[allow(dead_code)]
                pub(crate) fn take_from_slice(owned: &mut [u8]) -> Self {
                    Self(Buffer::take_from_slice(owned))
                }
            }

            impl Debug for $name<'_> {
                fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), Error> {
                    f.debug_struct(stringify!($name)).finish()
                }
            }

            impl<'a> From<Buffer<'a, buffer_type::[<$name Type>]>> for $name<'a> {
                fn from(value: Buffer<'a, buffer_type::[<$name Type>]>) -> Self {
                    Self(value)
                }
            }
        )*
    }}
}
pub(crate) use generated_encodings;
generated_encodings!(
    EcPrivateKeyBin,
    EcPrivateKeyRfc5915Der,
    EcPublicKeyUncompressedBin,
    EcPublicKeyCompressedBin,
    PublicKeyX509Der,
    Curve25519SeedBin,
    Pkcs8V1Der,
    Pkcs8V2Der,
    PqdsaPrivateKeyBin
);

/// Trait for types that can be serialized into a DER format.
pub trait AsDer<T> {
    /// Serializes into a DER format.
    ///
    /// # Errors
    /// Returns Unspecified if serialization fails.
    fn as_der(&self) -> Result<T, crate::error::Unspecified>;
}

/// Trait for values that can be serialized into a big-endian format
pub trait AsBigEndian<T> {
    /// Serializes into a big-endian format.
    ///
    /// # Errors
    /// Returns Unspecified if serialization fails.
    fn as_be_bytes(&self) -> Result<T, crate::error::Unspecified>;
}

/// Trait for values that can be serialized into a raw format
pub trait AsRawBytes<T> {
    /// Serializes into a raw format.
    ///
    /// # Errors
    /// Returns Unspecified if serialization fails.
    fn as_raw_bytes(&self) -> Result<T, crate::error::Unspecified>;
}
