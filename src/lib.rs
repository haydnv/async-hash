//! Provides traits `Hash`, `HashStream`, and `HashTryStream` for SHA-2 hashing data
//! which must be accessed asynchronously, e.g. a [`Stream`] or database table.
//!
//! `Hash` is implemented for standard Rust types:
//!
//!  - **Primitive types**:
//!    - bool
//!    - i8, i16, i32, i64, i128, isize
//!    - u8, u16, u32, u64, u128, usize
//!    - f32, f64
//!    - &str
//!    - String
//!  - **Common standard library types**:
//!    - Option\<T\>
//!    - PhantomData\<T\>
//!  - **Compound types**:
//!    - \[T; 0\] through \[T; 32\]
//!    - tuples up to size 16
//!  - **Collection types**:
//!    - BTreeMap\<K, V\>
//!    - BTreeSet\<T\>
//!    - BinaryHeap\<T\>
//!    - LinkedList\<T\>
//!    - VecDeque\<T\>
//!    - Vec\<T\>
//!  - **Other types**:
//!    - SmallVec\<V\> (requires the `smallvec` feature flag)
//!
//! **IMPORTANT**: hashing is order-dependent. Do not implement the traits in this crate for
//! any data structure which does not have a consistent order. Consider using the [`collate`] crate
//! if you need to use a type which does not implement [`Ord`].
//!
//! [`collate`]: http://docs.rs/collate

use std::collections::{BTreeMap, BTreeSet, BinaryHeap, LinkedList, VecDeque};

use futures::future::{FutureExt, TryFutureExt};
use futures::stream::{Stream, StreamExt, TryStream, TryStreamExt};

pub use sha2::digest::generic_array;
pub use sha2::digest::{Digest, Output};
pub use sha2::Sha256;

/// Trait to compute a SHA-2 hash using the digest type `D`
pub trait Hash<D: Digest>: Sized {
    /// Compute the SHA-2 hash of this value
    fn hash(self) -> Output<D>;
}

impl<D: Digest> Hash<D> for () {
    fn hash(self) -> Output<D> {
        default_hash::<D>()
    }
}

impl<D: Digest> Hash<D> for bool {
    fn hash(self) -> Output<D> {
        D::digest([self as u8])
    }
}

macro_rules! hash_number {
    ($n:literal, $ty:ty) => {
        impl<D: Digest> Hash<D> for $ty {
            fn hash(self) -> Output<D> {
                D::digest(self.to_be_bytes())
            }
        }
    };
}

hash_number!(4, f32);
hash_number!(8, f64);
hash_number!(1, i8);
hash_number!(2, i16);
hash_number!(4, i32);
hash_number!(8, i64);
hash_number!(16, i128);
hash_number!(1, u8);
hash_number!(2, u16);
hash_number!(4, u32);
hash_number!(8, u64);
hash_number!(16, u128);

impl<D: Digest> Hash<D> for isize {
    fn hash(self) -> Output<D> {
        Hash::<D>::hash(self as i64)
    }
}

impl<D: Digest> Hash<D> for usize {
    fn hash(self) -> Output<D> {
        Hash::<D>::hash(self as u64)
    }
}

impl<'a, D: Digest> Hash<D> for &'a str {
    fn hash(self) -> Output<D> {
        D::digest(self.as_bytes())
    }
}

impl<D: Digest> Hash<D> for String {
    fn hash(self) -> Output<D> {
        Hash::<D>::hash(self.as_str())
    }
}

impl<'a, D: Digest> Hash<D> for &'a String {
    fn hash(self) -> Output<D> {
        Hash::<D>::hash(self.as_str())
    }
}

impl<D: Digest, T: Hash<D>> Hash<D> for Option<T> {
    fn hash(self) -> Output<D> {
        if let Some(value) = self {
            value.hash()
        } else {
            default_hash::<D>()
        }
    }
}

macro_rules! hash_tuple {
    ($($len:expr => ($($n:tt $name:ident)+))+) => {
        $(
            impl<D: Digest, $($name),+> Hash<D> for ($($name,)+)
            where
                $($name: Hash<D>,)+
            {
                fn hash(self) -> Output<D> {
                    let mut hasher = D::new();
                    $(
                        let hash = self.$n.hash();
                        hasher.update(hash);
                    )+
                    hasher.finalize()
                }
            }

            impl<'a, D: Digest, $($name),+> Hash<D> for &'a ($($name,)+)
            where
                $(&'a $name: Hash<D>,)+
            {
                fn hash(self) -> Output<D> {
                    let mut hasher = D::new();
                    $(
                        let hash = self.$n.hash();
                        hasher.update(hash);
                    )+
                    hasher.finalize()
                }
            }
        )+
    }
}

hash_tuple! {
    1 => (0 T0)
    2 => (0 T0 1 T1)
    3 => (0 T0 1 T1 2 T2)
    4 => (0 T0 1 T1 2 T2 3 T3)
    5 => (0 T0 1 T1 2 T2 3 T3 4 T4)
    6 => (0 T0 1 T1 2 T2 3 T3 4 T4 5 T5)
    7 => (0 T0 1 T1 2 T2 3 T3 4 T4 5 T5 6 T6)
    8 => (0 T0 1 T1 2 T2 3 T3 4 T4 5 T5 6 T6 7 T7)
    9 => (0 T0 1 T1 2 T2 3 T3 4 T4 5 T5 6 T6 7 T7 8 T8)
    10 => (0 T0 1 T1 2 T2 3 T3 4 T4 5 T5 6 T6 7 T7 8 T8 9 T9)
    11 => (0 T0 1 T1 2 T2 3 T3 4 T4 5 T5 6 T6 7 T7 8 T8 9 T9 10 T10)
    12 => (0 T0 1 T1 2 T2 3 T3 4 T4 5 T5 6 T6 7 T7 8 T8 9 T9 10 T10 11 T11)
    13 => (0 T0 1 T1 2 T2 3 T3 4 T4 5 T5 6 T6 7 T7 8 T8 9 T9 10 T10 11 T11 12 T12)
    14 => (0 T0 1 T1 2 T2 3 T3 4 T4 5 T5 6 T6 7 T7 8 T8 9 T9 10 T10 11 T11 12 T12 13 T13)
    15 => (0 T0 1 T1 2 T2 3 T3 4 T4 5 T5 6 T6 7 T7 8 T8 9 T9 10 T10 11 T11 12 T12 13 T13 14 T14)
    16 => (0 T0 1 T1 2 T2 3 T3 4 T4 5 T5 6 T6 7 T7 8 T8 9 T9 10 T10 11 T11 12 T12 13 T13 14 T14 15 T15)
}

impl<D: Digest, T: Hash<D>> Hash<D> for [T; 0] {
    fn hash(self) -> Output<D> {
        default_hash::<D>()
    }
}

macro_rules! hash_array {
    ($($len:tt)+) => {
        $(
            impl<D: Digest, T: Hash<D>> Hash<D> for [T; $len] {
                fn hash(self) -> Output<D> {
                    if self.is_empty() {
                        return default_hash::<D>();
                    }

                    let mut hasher = D::new();

                    for item in self {
                        hasher.update(item.hash());
                    }

                    hasher.finalize()
                }
            }
        )+
    }
}

hash_array! {
    01 02 03 04 05 06 07 08 09 10
    11 12 13 14 15 16 17 18 19 20
    21 22 23 24 25 26 27 28 29 30
    31 32
}

macro_rules! hash_seq {
    ($ty:ty) => {
        impl<D: Digest, T: Hash<D>> Hash<D> for $ty {
            fn hash(self) -> Output<D> {
                if self.is_empty() {
                    return default_hash::<D>();
                }

                let mut hasher = D::new();

                for item in self.into_iter() {
                    hasher.update(item.hash());
                }

                hasher.finalize()
            }
        }

        impl<'a, D, T> Hash<D> for &'a $ty
        where
            D: Digest,
            &'a T: Hash<D>,
        {
            fn hash(self) -> Output<D> {
                if self.is_empty() {
                    return default_hash::<D>();
                }

                let mut hasher = D::new();
                for item in self.into_iter() {
                    hasher.update(item.hash());
                }
                hasher.finalize()
            }
        }
    };
}

hash_seq!(BTreeSet<T>);
hash_seq!(BinaryHeap<T>);
hash_seq!(LinkedList<T>);
hash_seq!(Vec<T>);
hash_seq!(VecDeque<T>);

#[cfg(feature = "smallvec")]
impl<const N: usize, D: Digest, T> Hash<D> for smallvec::SmallVec<[T; N]>
where
    [T; N]: smallvec::Array,
    <smallvec::SmallVec<[T; N]> as IntoIterator>::Item: Hash<D>,
{
    fn hash(self) -> Output<D> {
        if self.is_empty() {
            return default_hash::<D>();
        }

        let mut hasher = D::new();

        for item in self.into_iter() {
            hasher.update(item.hash());
        }

        hasher.finalize()
    }
}

#[cfg(feature = "smallvec")]
impl<'a, const N: usize, D: Digest, T> Hash<D> for &'a smallvec::SmallVec<[T; N]>
where
    [T; N]: smallvec::Array,
    <&'a smallvec::SmallVec<[T; N]> as IntoIterator>::Item: Hash<D>,
{
    fn hash(self) -> Output<D> {
        if self.is_empty() {
            return default_hash::<D>();
        }

        let mut hasher = D::new();

        for item in self.into_iter() {
            hasher.update(item.hash());
        }

        hasher.finalize()
    }
}

impl<D: Digest, K: Hash<D>, V: Hash<D>> Hash<D> for BTreeMap<K, V> {
    fn hash(self) -> Output<D> {
        if self.is_empty() {
            return default_hash::<D>();
        }

        let mut hasher = D::new();

        for item in self {
            hasher.update(item.hash());
        }

        hasher.finalize()
    }
}

impl<'a, D, K, V> Hash<D> for &'a BTreeMap<K, V>
where
    D: Digest,
    &'a K: Hash<D>,
    &'a V: Hash<D>,
{
    fn hash(self) -> Output<D> {
        if self.is_empty() {
            return default_hash::<D>();
        }

        let mut hasher = D::new();

        for item in self {
            hasher.update(item.hash());
        }

        hasher.finalize()
    }
}

/// Hash a [`Stream`]
pub async fn hash_stream<D, T, S>(stream: S) -> Output<D>
where
    D: Digest,
    T: Hash<D>,
    S: Stream<Item = T>,
{
    stream
        .map(|item| Hash::<D>::hash(item))
        .fold(D::new(), |mut hasher, hash| {
            hasher.update(hash);
            futures::future::ready(hasher)
        })
        .map(|hasher| hasher.finalize())
        .await
}

/// Hash a [`TryStream`]
pub async fn hash_try_stream<D, T, E, S>(stream: S) -> Result<Output<D>, E>
where
    D: Digest,
    T: Hash<D>,
    E: std::error::Error,
    S: TryStream<Ok = T, Error = E>,
{
    stream
        .map_ok(|item| Hash::<D>::hash(item))
        .try_fold(D::new(), |mut hasher, hash| {
            hasher.update(hash);
            futures::future::ready(Ok(hasher))
        })
        .map_ok(|hasher| hasher.finalize())
        .await
}

/// Construct an empty hash
pub fn default_hash<D: Digest>() -> Output<D> {
    generic_array::GenericArray::default()
}
