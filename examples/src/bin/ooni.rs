use core::ops::Mul;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Result};
use blake2::Blake2b512;
use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_TABLE, ristretto::CompressedRistretto, RistrettoPoint, Scalar,
};
use rkvc::{
    cmz::{Key, Mac, PublicParameters},
    range::Bulletproof,
    zkp::{Prover, Transcript, Verifier},
    Attributes, UintEncoder,
};

#[derive(Attributes, Clone, Debug)]
struct OoniAttributes {
    /// A secret key held by the client for the purpose of deriving context-specific pseudonyms.
    /// This value is private during issuance, and used during presentation to derive pseudonyms.
    pub pseudonym_key: Scalar,
    /// An creation time for the credential. Public and chosen by the server during issuance, and
    /// private thereafter. The client must prove during presentation that there credential is at
    /// least a certain age.
    pub created_at: u64,
    /// A count of the number of measurements uploaded by this client. Intialized to zero during
    /// issuance and incremented by one for each provided measurement.
    pub measurement_count: u64,
    /// A bit set to true if the client is a trusted party. Set by the server during presentation,
    /// and can be optionally revealed to bypass other predicate checks if true.
    pub is_trusted: bool,
}

struct Credential {
    pub attributes: OoniAttributes,
    pub mac: Mac<RistrettoPoint, OoniAttributes>,
}

struct CredentialPresentation {
    pub presentation: rkvc::cmz::Presentation<CompressedRistretto, OoniAttributes>,
    pub bulletproof: rkvc::range::Bulletproof<OoniAttributes>,
    pub schnorr_proof: rkvc::zkp::CompactProof,
}

impl Credential {
    /// Present the credential, with current time set to `at`, proving that the time since create
    /// is at least `min_age` and the number of measurements is at least `min_measurement_count`.
    pub fn present(
        &self,
        pp: &PublicParameters<RistrettoPoint, OoniAttributes>,
        at: u64,
        min_age: u64,
        min_measurement_count: u64,
    ) -> Result<CredentialPresentation> {
        let mut transcript =
            Transcript::new(b"rkvc_examples::ooni::Credential::present::transcript");
        let mut prover = Prover::new(
            b"rkvc_examples::ooni::Credential::present::constraints",
            &mut transcript,
        );

        let (presentation, msg_variables) = self.mac.prove_presentation_constraints(
            &mut prover,
            &self
                .attributes
                .attribute_walk(UintEncoder::default())
                .collect(),
            pp,
            rkvc::rand::thread_rng(),
        );
        let (mut bulletproof_commits, mut bulletproof_openings) =
            Bulletproof::prove_range_commit_constaints(
                &mut prover,
                &msg_variables,
                &self.attributes,
            )?;

        let schnorr_proof = prover.prove_compact();

        // Subtract the committed creation timestamp from `at - min_age`. The result will only be
        // in the u64 range if it is less than `at - min_age`.
        // TODO: This relies on fragile implementation details. Provide a more robust way to
        // accomplish this.
        let max_timestamp = at.checked_sub(min_age).unwrap();
        let created_at_commit: RistrettoPoint = bulletproof_commits.created_at().unwrap();
        *bulletproof_commits.created_at_mut().as_mut().unwrap() = RISTRETTO_BASEPOINT_TABLE
            .mul(&Scalar::from(max_timestamp))
            - bulletproof_commits.created_at().as_ref().unwrap();
        let (created_at, created_at_blind) = bulletproof_openings.created_at().unwrap();
        *bulletproof_openings.created_at_mut() =
            Some((Scalar::from(max_timestamp) - created_at, created_at_blind));

        // Prove that the measurement count is at least min_measurement_count.
        let measurement_count_commit: RistrettoPoint =
            bulletproof_commits.measurement_count().unwrap();
        *bulletproof_commits
            .measurement_count_mut()
            .as_mut()
            .unwrap() -= RISTRETTO_BASEPOINT_TABLE.mul(&Scalar::from(min_measurement_count));
        let (measurement_count, measurement_count_blind) =
            bulletproof_openings.measurement_count().unwrap();
        *bulletproof_openings.measurement_count_mut() = Some((
            measurement_count - Scalar::from(min_measurement_count),
            measurement_count_blind,
        ));

        let mut bulletproof = Bulletproof::prove_bulletproof(
            &mut transcript,
            &bulletproof_commits,
            &bulletproof_openings,
        )?;

        // Reset the value in the commit, which will be used for the DLEQ check with CMZ commit.
        *bulletproof.bulletproof_commits.created_at_mut() = Some(created_at_commit.compress());
        *bulletproof.bulletproof_commits.measurement_count_mut() =
            Some(measurement_count_commit.compress());

        Ok(CredentialPresentation {
            presentation,
            bulletproof,
            schnorr_proof,
        })
    }
}

struct Issuer {
    key: Key<Scalar, OoniAttributes>,
}

impl Issuer {
    pub fn new() -> Self {
        Self {
            key: Key::gen(rkvc::rand::thread_rng()),
        }
    }

    pub fn issue(
        &self,
        at: u64,
        is_trusted: bool,
        pseudonym_key_commit: CompressedRistretto,
    ) -> Credential {
        let attributes = OoniAttributes {};
        let mac = self.key.mac(&attributes);
        Credential { attributes, mac }
    }

    pub fn verify_presentation(&self, _at: u64, _pres: &CredentialPresentation) -> Result<()> {
        todo!()
    }

    pub fn public_parameters(&self) -> PublicParameters<RistrettoPoint, OoniAttributes> {
        self.key.public_parameters()
    }
}

// Walks through the mock flow of a client interacting with an issuer.
fn main() -> Result<()> {
    let issuer = Issuer::new();
    let pp = issuer.public_parameters();

    // Client requests a credential that will expire in 30 seconds.
    let now_timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // TODO: This flow is missing the ZKP from the issuer showing the credential was created
    // with the correct key.
    let cred = issuer.issue("alice@dev.null", now_timestamp + 30);
    println!("Issued a credential with attributes: {:?}", cred.attributes);

    // 15 seconds later, they present their credential.
    let later_timestamp = now_timestamp + 15;
    let presentation = cred.present(&pp, later_timestamp)?;
    println!("Created a presentation for the validity of the credential at {later_timestamp}");

    issuer.verify_presentation(later_timestamp, &presentation)?;
    println!("Issuer verified the credential");

    Ok(())
}
