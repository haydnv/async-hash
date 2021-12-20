//! Provides traits [`Hash`] and [`HashCollection`] for SHA256 hashing of data that must be
//! accessed asynchronously, e.g. a [`Stream`] or database table.
//!
//! [`Hash`] is implemented for standard Rust types:
//!
//!  - **Primitive types**:
//!    - bool
//!    - i8, i16, i32, i64, i128, isize
//!    - u8, u16, u32, u64, u128, usize
//!    - f32, f64
//!    - str
//!  - **Compound types**:
//!    - \[T; 0\] through \[T; 32\]
//!    - tuples up to size 16
//!  - **Common standard library types**:
//!    - Option\<T\>
//!    - Result\<T, E\>
//!    - PhantomData\<T\>
//!  - **Other common types**:
//!    - Bytes
//!  - **Collection types**:
//!    - BTreeMap\<K, V\>
//!    - BTreeSet\<T\>
//!    - BinaryHeap\<T\>
//!    - LinkedList\<T\>
//!    - VecDeque\<T\>
//!    - Vec\<T\>

use std::collections::{BTreeMap, BTreeSet, BinaryHeap, LinkedList, VecDeque};
use std::convert::Infallible;
use std::marker::PhantomData;
use std::pin::Pin;

use async_trait::async_trait;
use bytes::Bytes;
use futures::future::TryFutureExt;
use futures::stream::{FuturesOrdered, Stream, TryStreamExt};
use futures::try_join;
use sha2::{Digest, Sha256};

/// The hash of an empty value such as `()` or `Option::None`.
pub const NULL_HASH: [u8; 0] = [];

/// A ordered [`Stream`] of the contents of a [`HashCollection`].
pub type Contents<'a, T, E> = Pin<Box<dyn Stream<Item = Result<T, E>> + Send + Unpin + 'a>>;

/// Defines a standard hash for a scalar value.
#[async_trait]
pub trait Hash: Send + Sync + Sized {
    /// Contextual information needed to access the data which this state contains.
    ///
    /// Use `()` if there is no contextual data needed.
    type Context: Send + Sync;

    /// The type of error which may be returned when accessing this state's data.
    ///
    /// Use `Infallible` if there is no error to return.
    type Error: std::error::Error + Send + Sync;

    /// Compute the SHA256 hash of this state.
    async fn hash(&self, cxt: &Self::Context) -> Result<Bytes, Self::Error>;

    /// Consume this state and compute its SHA256 hash.
    async fn hash_owned(self, cxt: &Self::Context) -> Result<Bytes, Self::Error> {
        self.hash(cxt).await
    }

    /// Return the SHA256 hash of this state as a hexadecimal string.
    async fn hash_hex(&self, cxt: &Self::Context) -> Result<String, Self::Error> {
        self.hash(cxt).map_ok(|hash| hex::encode(hash)).await
    }
}

#[async_trait]
impl Hash for () {
    type Context = ();
    type Error = Infallible;

    async fn hash(&self, _: &()) -> Result<Bytes, Self::Error> {
        Ok(Bytes::copy_from_slice(&NULL_HASH))
    }
}

#[async_trait]
impl<T: Hash> Hash for Option<T> {
    type Context = T::Context;
    type Error = T::Error;

    async fn hash(&self, cxt: &Self::Context) -> Result<Bytes, Self::Error> {
        if let Some(value) = self {
            value.hash(cxt).await
        } else {
            Ok(Bytes::copy_from_slice(&NULL_HASH))
        }
    }
}

#[async_trait]
impl<C, T, E> Hash for Result<T, E>
where
    C: Send + Sync,
    T: Hash<Context = C, Error = Infallible>,
    E: Hash<Context = C, Error = Infallible>,
{
    type Context = C;
    type Error = Infallible;

    async fn hash(&self, cxt: &C) -> Result<Bytes, Self::Error> {
        match self {
            Ok(value) => value.hash(cxt).await,
            Err(cause) => cause.hash(cxt).await,
        }
    }
}

#[async_trait]
impl<T: Hash> Hash for PhantomData<T> {
    type Context = ();
    type Error = Infallible;

    async fn hash(&self, _: &()) -> Result<Bytes, Self::Error> {
        Ok(Bytes::copy_from_slice(&NULL_HASH))
    }
}

#[async_trait]
impl Hash for Bytes {
    type Context = ();
    type Error = Infallible;

    async fn hash(&self, _: &()) -> Result<Bytes, Self::Error> {
        let mut hasher = Sha256::default();
        hasher.update(self);
        Ok(hasher.finalize().to_vec().into())
    }
}

#[async_trait]
impl<E, K: Hash<Context = (), Error = E>, V: Hash<Context = (), Error = E>> Hash for BTreeMap<K, V>
where
    E: std::error::Error + Send + Sync,
{
    type Context = ();
    type Error = E;

    async fn hash(&self, cxt: &Self::Context) -> Result<Bytes, Self::Error> {
        let mut hashes: FuturesOrdered<_> = self
            .iter()
            .map(|(k, v)| async move { try_join!(k.hash(cxt), v.hash(cxt)) })
            .collect();

        let mut hasher = Sha256::default();
        while let Some((k_hash, v_hash)) = hashes.try_next().await? {
            hasher.update(&k_hash);
            hasher.update(&v_hash);
        }
        Ok(hasher.finalize().to_vec().into())
    }
}

#[async_trait]
impl<'a> Hash for &'a str {
    type Context = ();
    type Error = Infallible;

    async fn hash(&self, _: &()) -> Result<Bytes, Infallible> {
        let mut hasher = Sha256::default();
        hasher.update(self.as_bytes());
        Ok(hasher.finalize().to_vec().into())
    }
}

macro_rules! hash_seq {
    ($ty:ty) => {
        #[async_trait]
        impl<T: Hash<Context = ()>> Hash for $ty {
            type Context = ();
            type Error = T::Error;

            async fn hash(&self, cxt: &Self::Context) -> Result<Bytes, Self::Error> {
                let hashes: FuturesOrdered<_> = self.iter().map(|item| item.hash(cxt)).collect();
                hash_stream(hashes).await
            }
        }
    };
}

hash_seq!(BinaryHeap<T>);
hash_seq!(BTreeSet<T>);
hash_seq!(LinkedList<T>);
hash_seq!(Vec<T>);
hash_seq!(VecDeque<T>);

#[async_trait]
impl Hash for bool {
    type Context = ();
    type Error = Infallible;

    async fn hash(&self, _: &()) -> Result<Bytes, Infallible> {
        let mut hasher = Sha256::default();
        if *self {
            hasher.update(&[1]);
        } else {
            hasher.update(&[0]);
        }
        Ok(hasher.finalize().to_vec().into())
    }
}

macro_rules! hash_number {
    ($ty:ty) => {
        #[async_trait]
        impl Hash for $ty {
            type Context = ();
            type Error = Infallible;

            async fn hash(&self, _: &()) -> Result<Bytes, Infallible> {
                let mut hasher = Sha256::default();
                hasher.update(self.to_be_bytes());
                Ok(hasher.finalize().to_vec().into())
            }
        }
    };
}

hash_number!(f32);
hash_number!(f64);
hash_number!(u8);
hash_number!(u16);
hash_number!(u32);
hash_number!(u64);
hash_number!(u128);
hash_number!(usize);
hash_number!(i8);
hash_number!(i16);
hash_number!(i32);
hash_number!(i64);
hash_number!(i128);
hash_number!(isize);

#[async_trait]
impl<T: Send + Sync> Hash for [T; 0] {
    type Context = ();
    type Error = Infallible;

    async fn hash(&self, _: &()) -> Result<Bytes, Infallible> {
        Ok(Bytes::copy_from_slice(&NULL_HASH))
    }
}

macro_rules! hash_array {
    ($($len:tt)+) => {
        $(
            #[async_trait]
            impl<T: Hash> Hash for [T; $len] {
                type Context = T::Context;
                type Error = T::Error;

                async fn hash(&self, cxt: &Self::Context) -> Result<Bytes, Self::Error> {
                    let hashes: FuturesOrdered<_> = self.iter().map(|e| e.hash(cxt)).collect();
                    hash_stream(hashes).await
                }
            }
        )+
    }
}

hash_array!(
    01 02 03 04 05 06 07 08 09 10
    11 12 13 14 15 16 17 18 19 20
    21 22 23 24 25 26 27 28 29 30
    31 32);

macro_rules! hash_tuple {
    ($($len:expr => ($($n:tt $name:ident)+))+) => {
        $(
            #[async_trait]
            impl<E, $($name),+> Hash for ($($name,)+)
            where
                E: std::error::Error + Send + Sync,
                $($name: Hash<Context = (), Error = E>,)+
            {
                type Context = ();
                type Error = E;

                async fn hash(&self, cxt: &Self::Context) -> Result<Bytes, E> {
                    let mut hasher = Sha256::default();
                    $(
                        let hash = &self.$n.hash(cxt).await?;
                        hasher.update(hash);
                    )+
                    Ok(hasher.finalize().to_vec().into())
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

/// Defines a standard hash for a mutable collection.
#[async_trait]
pub trait HashCollection: Send + Sync {
    type Item: Hash<Context = ()>;
    type Context: Send + Sync;

    /// Return a stream of hashable items which comprise this collection, in a consistent order.
    async fn hashable<'a>(
        &'a self,
        txn: &'a Self::Context,
    ) -> Result<Contents<'a, Self::Item, <Self::Item as Hash>::Error>, <Self::Item as Hash>::Error>;
}

#[async_trait]
impl<T> Hash for T
where
    T: HashCollection,
{
    type Context = T::Context;
    type Error = <T::Item as Hash>::Error;

    async fn hash(&self, txn: &Self::Context) -> Result<Bytes, Self::Error> {
        let items = self.hashable(txn).await?;
        let item_hashes = items
            .map_ok(|item| item.hash_owned(&()))
            .try_buffered(num_cpus::get());

        hash_stream(item_hashes).await
    }
}

async fn hash_stream<Err, S: Stream<Item = Result<Bytes, Err>> + Unpin>(
    mut items: S,
) -> Result<Bytes, Err> {
    let mut hasher = Sha256::default();
    while let Some(hash) = items.try_next().await? {
        hasher.update(&hash);
    }

    Ok(hasher.finalize().to_vec().into())
}
