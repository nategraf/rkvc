use core::ops::Mul;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use blake2::Blake2b512;
use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_TABLE, ristretto::CompressedRistretto, RistrettoPoint, Scalar,
};
use rkvc::{
    cmz::{Key, Mac, PublicParameters},
    range::Bulletproof,
    zkp::{Prover, Transcript, Verifier},
    Attributes, EncoderOutput, UintEncoder,
};

#[derive(Attributes, Clone, Debug)]
struct ExpirationAttributes {
    /// A unique identifier for the authenticated user (e.g. an account ID). Public during issuance
    /// and private during presentations.
    pub id: Scalar,
    /// An expiration time for the credential. Public and chosen by the server during issuance, and
    /// private thereafter. The client must prove during presentation that the expiration is
    /// greater than an agreed current timestamp.
    pub expiration: u64,
}

struct Credential {
    pub attributes: ExpirationAttributes,
    pub mac: Mac<RistrettoPoint, ExpirationAttributes>,
}

struct CredentialPresentation {
    pub presentation: rkvc::cmz::Presentation<CompressedRistretto, ExpirationAttributes>,
    pub bulletproof: rkvc::range::Bulletproof<ExpirationAttributes>,
    pub schnorr_proof: rkvc::zkp::CompactProof,
}

impl Credential {
    pub fn present(
        &self,
        pp: &PublicParameters<RistrettoPoint, ExpirationAttributes>,
        at: u64,
    ) -> Result<CredentialPresentation> {
        let mut transcript =
            Transcript::new(b"rkvc_examples::expiration::Credential::present::transcript");
        let mut prover = Prover::new(
            b"rkvc_examples::expiration::Credential::present::constraints",
            &mut transcript,
        );

        let (presentation, msg_variables) = self.mac.prove_presentation_constraints(
            &mut prover,
            &UintEncoder::encode_attributes(&self.attributes).collect(),
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

        // Subtract the current timestamp `at` from the commitmentted value. The result will only
        // be in the u64 range if it is greater than or equal to `at`.
        let expiration_commit: RistrettoPoint = bulletproof_commits.expiration().unwrap();
        *bulletproof_commits.expiration_mut().as_mut().unwrap() -=
            RISTRETTO_BASEPOINT_TABLE.mul(&Scalar::from(at));
        let (expiration, expiration_blind) = bulletproof_openings.expiration().unwrap();
        *bulletproof_openings.expiration_mut() =
            Some((expiration - Scalar::from(at), expiration_blind));

        let mut bulletproof = Bulletproof::prove_bulletproof(
            &mut transcript,
            &bulletproof_commits,
            &bulletproof_openings,
        )?;

        // Reset the value in the commit, which will be used for the DLEQ check with CMZ commit.
        *bulletproof.bulletproof_commits.expiration_mut() = Some(expiration_commit.compress());

        Ok(CredentialPresentation {
            presentation,
            bulletproof,
            schnorr_proof,
        })
    }
}

struct Issuer {
    key: Key<Scalar, ExpirationAttributes>,
}

impl Issuer {
    pub fn new() -> Self {
        Self {
            key: Key::gen(rkvc::rand::thread_rng()),
        }
    }

    pub fn issue(&self, email: &str, expiration: u64) -> Credential {
        // Hash the "email" as an example of an account ID.
        let id = Scalar::hash_from_bytes::<Blake2b512>(email.as_bytes());

        let attributes = ExpirationAttributes { id, expiration };
        let mac = self.key.mac(&attributes);
        Credential { attributes, mac }
    }

    pub fn verify_presentation(&self, at: u64, pres: &CredentialPresentation) -> Result<()> {
        let mut transcript =
            Transcript::new(b"rkvc_examples::expiration::Credential::present::transcript");
        let mut verifier = Verifier::new(
            b"rkvc_examples::expiration::Credential::present::constraints",
            &mut transcript,
        );

        // Constrain the commitments used for the Pederson commitment within CMZ and the
        // commitments used for the (batched) range proof to open to the same values.
        let msg_variables = self
            .key
            .constrain_presentation(&mut verifier, &pres.presentation)?;
        pres.bulletproof
            .constrain_range_commit_opening(&mut verifier, &msg_variables)?;

        verifier.verify_compact(&pres.schnorr_proof)?;

        // Subtract the current timestamp `at` from the commitmentted value. The result will only
        // be in the u64 range if it is greater than or equal to `at`.
        let mut bulletproof = pres.bulletproof.clone();
        let mut expiration_commit = bulletproof
            .bulletproof_commits
            .expiration()
            .unwrap()
            .decompress()
            .context("failed to decompress expiration commit")?;
        expiration_commit -= RISTRETTO_BASEPOINT_TABLE.mul(&Scalar::from(at));
        *bulletproof.bulletproof_commits.expiration_mut() = Some(expiration_commit.compress());

        bulletproof.verify_range_proof(&mut transcript)?;
        Ok(())
    }

    pub fn public_parameters(&self) -> PublicParameters<RistrettoPoint, ExpirationAttributes> {
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
