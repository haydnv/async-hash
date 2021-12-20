use std::convert::Infallible;
use std::pin::Pin;

use async_trait::async_trait;
use bytes::Bytes;
use futures::future::TryFutureExt;
use futures::stream::{Stream, TryStreamExt};
use sha2::{Digest, Sha256};

pub const NULL_HASH: [u8; 0] = [];

pub type Contents<'a, T, E> = Pin<Box<dyn Stream<Item = Result<T, E>> + Send + Unpin + 'a>>;

/// Defines a standard hash for a scalar value.
#[async_trait]
pub trait Hash: Send + Sync + Sized {
    type Context: Send + Sync;
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

    async fn hash(&self, _: &Self::Context) -> Result<Bytes, Self::Error> {
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
                    let mut hasher = Sha256::default();
                    for e in self {
                        let hash = e.hash(cxt).await?;
                        hasher.update(hash);
                    }
                    Ok(hasher.finalize().to_vec().into())
                }
            }
        )+
    }
}

hash_array!(
    00 01 02 03 04 05 06 07 08 09
    10 11 12 13 14 15 16 17 18 19
    20 21 22 23 24 25 26 27 28 29
    30 31 32);

/// Defines a standard hash for a mutable collection.
#[async_trait]
pub trait HashCollection: Send + Sync {
    type Item: Hash<Context = ()>;
    type Context: Send + Sync;

    /// Return a stream of hashable items which this state comprises, in a consistent order.
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
