#![allow(dead_code)]

//! This example is an implementation of the [Lox] bridge distribution system, by Tulloch and
//! Goldberg, using anonymous credentials to provide Tor bridge information to users in censoring
//! regions while protecting the social graph.
//!
//! This implementation is not intended to be interoperable with the official Lox authority
//! operated by the Tor Project, nor is it intended to be complete. It is intended to provide an
//! example of a more complete application using [rkvc], both for helping others understand how to
//! use the library and to ensure it is complete enough to satisfy a real use case.
//!
//! Some text below is copied directly from the paper by Tulloch and Goldberg.
//!
//! [Lox]: https://uwspace.uwaterloo.ca/handle/10012/18333

use std::collections::HashSet;

use blake2::Blake2b512;
use curve25519_dalek::Scalar;
use hkdf::SimpleHkdf as Hkdf;
use rand::{CryptoRng, Rng};
use rkvc::Attributes;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

#[derive(Attributes, Clone, Debug)]
struct LoxCredential {
    /// A random ID jointly created by the user and the [LoxAuthority].
    ///
    /// This ID is unknown to the server at issuance time, and revealed upon presentation of the
    /// credential. This ID acts as a nullifier / nonce in the [LoxAuthority] will reject
    /// multiple presentations with the same ID.
    pub id: Scalar,

    /// Issuance time of the credential, measured in days since the Unix epoch.
    pub time: Scalar,

    /// Level of trust this user has gained. See [TrustLevel].
    pub trust_level: TrustLevel,

    /// identifier for the bucket this user is assigned to.
    pub bucket_id: BucketId,

    /// Countdown counter is allowing users to issue invitations once they have advanced to L ≥ 2.
    /// The value of a is decremented for each invite issued.
    pub invitations: u8,

    /// The number of times the user has migrated to a new trusted bucket. Open-entry users will
    /// always begin with d = 0. Users who are invited will inherit the d value of their inviter.
    /// Experiencing blockages limits the trust level a user can achieve; 3 and 4 blockages limit
    /// the user to trust levels 3 and 2 respectively, after which they will be be ineligible to
    /// migrate.
    pub blockages: u8,
}

/// Trust level associated with a credential, gained over time interacting with Lox.
///
/// All open-entry users enter Lox with L = 0. All invited users enter Lox with L = 1. Users that
/// can prove to the [LoxAuthority] that a sufficient time period has passed without the bridges in
/// their bucket becoming blocked, can upgrade their trust level through the [LoxAuthority]. If a
/// user continues to hold a credential for an unblocked bucket, they can continue to level up to a
/// maximum of L = 4 with intermittent level up requests to the [LoxAuthority].
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
#[repr(u8)]
enum TrustLevel {
    #[default]
    Untrusted,
    One,
    Two,
    Three,
    Four,
}

/// Token obtained during the first step of the migration process, which can be presented to the
/// [LoxAuthority] to gain new [LoxCredential] with the updated bucket identifer.
#[derive(Attributes, Clone, Debug)]
struct MigrationToken {
    /// A random ID jointly created by the user and the [LoxAuthority], used as a nullifier.
    id: Scalar,
    // TODO(lox): Why do we need bucket_from? It seems like dead-weight here.
    bucket_from: BucketId,
    bucket_to: BucketId,
    reason: MigrationReason,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u8)]
enum MigrationReason {
    TrustPromotion,
    Blockage,
}

/// Token generated by the [LoxAuthority] for each day for every bucket that remains unblocked.
///
/// This token is presented when an action requires the user's bridge remain unblocked (e.g. for
/// the trust promotion request). Tokens are distributed, encrypted with the associated bucket key,
/// with the bucket list.
#[derive(Attributes, Clone, Debug)]
struct BucketReachabilityToken {
    /// Time at which reachability was checked, measured in days since the Unix epoch.
    time: Scalar,
    /// Identifier for the bucket for which the reachability status applies.
    bucket: BucketId,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct BridgeLine {}

/// An numerical index bucket identifier.
///
/// Open-entry buckets are grouped into sets that are merged when the bucket is upgraded to
/// invite-only, if the bridges remain unblocked for the required number of days. All grouped
/// open-entry buckets will have the same identifier expect for the least-significant byte, which
/// is used as an index within the grouping.
#[derive(Copy, Clone, PartialEq, Eq, Debug, Hash, Serialize, Deserialize)]
struct BucketId(pub u64);

impl BucketId {
    pub fn new(index: u64) -> Self {
        Self(index.checked_shl(8).unwrap())
    }

    pub fn open_entry(self, index: u8) -> Self {
        Self(self.0 | index as u64)
    }

    pub fn invite_only(self) -> Self {
        Self(self.0 & (u64::MAX - u8::MAX as u64))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct Bucket {
    id: BucketId,
    bridges: Vec<BridgeLine>,
}

struct LoxAuthority {
    /// Primary key used to derive bucket encryption keys (K_i).
    bucket_encryption_key: Zeroizing<[u8; 16]>,
    seen_credential_ids: HashSet<Scalar>,
}

impl LoxAuthority {
    fn new(mut rng: impl CryptoRng) -> Self {
        Self {
            bucket_encryption_key: Zeroizing::new(rng.random()),
            seen_credential_ids: HashSet::new(),
        }
    }

    fn encrypt_bucket(&self, _bucket: Bucket, _rng: impl CryptoRng) -> ! {
        todo!()
    }

    fn bucket_key(&self, id: BucketId) -> Zeroizing<[u8; 16]> {
        let mut key = Zeroizing::<[u8; 16]>::default();
        Hkdf::<Blake2b512>::new(
            Some(b"LoxAuthority::bucket_key"),
            self.bucket_encryption_key.as_slice(),
        )
        .expand(&id.0.to_be_bytes(), key.as_mut_slice())
        .unwrap();
        key
    }
}

fn main() -> anyhow::Result<()> {
    Ok(())
}
