#![allow(unused, dead_code)] // FIXME
use core::ops::{Add, Mul};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, ensure, Context, Result};
use blake2::Blake2b512;
use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_TABLE, ristretto::CompressedRistretto, RistrettoPoint, Scalar,
};
use rkvc::{
    cmz::{Key, Mac, Presentation as CmzPresentation, PublicParameters},
    pederson::{PedersonCommitment, PedersonGenerators},
    rand,
    range::Bulletproof,
    zkp::{CompactProof as SchnorrProof, Prover, Transcript, Verifier},
    Attributes, UintEncoder,
};

#[derive(Attributes, Clone, Debug)]
struct OoniAttributes {
    /// A secret key held by the client for the purpose of deriving context-specific pseudonyms.
    /// This value is private during issuance, and used during presentation to derive pseudonyms.
    #[rkvc(label = "OoniAttributes::pseudonym_key")]
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

/// Subset of [OoniAttributes] that are committed to as part of the issuance request.
#[derive(Attributes, Clone, Debug)]
struct OoniIssuanceAttributes {
    /// See [OoniAttributes::pseudonym_key].
    #[rkvc(label = "OoniAttributes::pseudonym_key")]
    pub pseudonym_key: Scalar,
}

impl Add<OoniIssuanceAttributes> for OoniAttributes {
    type Output = OoniAttributes;

    fn add(self, rhs: OoniIssuanceAttributes) -> Self::Output {
        OoniAttributes {
            pseudonym_key: self.pseudonym_key + rhs.pseudonym_key,
            ..self
        }
    }
}

impl OoniIssuanceAttributes {
    /// Create [PedersonGenerators] for [OoniIssuanceAttributes] from the given generators for
    /// [OoniAttributes] by taking a subset of the attibute commitment generators plus the blinding
    /// generator.
    fn pederson_generators_from(
        gens: &PedersonGenerators<RistrettoPoint, OoniAttributes>,
    ) -> PedersonGenerators<RistrettoPoint, Self> {
        PedersonGenerators(gens.0, [gens.1.pseudonym_key().clone()].into())
    }
}

struct Credential {
    pub attributes: OoniAttributes,
    pub mac: Mac<RistrettoPoint, OoniAttributes>,
}

struct CredentialPresentation {
    pub presentation: CmzPresentation<CompressedRistretto, OoniAttributes>,
    pub bulletproof: Bulletproof<OoniAttributes>,
    pub schnorr_proof: SchnorrProof,
}

impl Credential {
    /// Present the credential, with current time set to `at`, proving that the time since create
    /// is at least `min_age` and the number of measurements is at least `min_measurement_count`.
    // TODO: Add a statement about the pseudonym.
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
        let mut bulletproof_openings = Bulletproof::prove_range_commit_constaints(
            &mut prover,
            &msg_variables,
            &self.attributes,
        )?;

        let schnorr_proof = prover.prove_compact();

        // Subtract the committed creation timestamp from `at - min_age`. The result will only be
        // in the u64 range if it is less than `at - min_age`.
        let max_timestamp = at.checked_sub(min_age).unwrap();
        let (created_at, created_at_blind) = bulletproof_openings.created_at().unwrap();
        *bulletproof_openings.created_at_mut() =
            Some((Scalar::from(max_timestamp) - created_at, created_at_blind));

        // Prove that the measurement count is at least min_measurement_count.
        let (measurement_count, measurement_count_blind) =
            bulletproof_openings.measurement_count().unwrap();
        *bulletproof_openings.measurement_count_mut() = Some((
            measurement_count - Scalar::from(min_measurement_count),
            measurement_count_blind,
        ));

        let mut bulletproof =
            Bulletproof::prove_bulletproof(&mut transcript, &bulletproof_openings)?;

        // Reset the value in the commit, which will be used for the DLEQ check with CMZ commit.
        // TODO: Find a more elegant way to handle this.
        *bulletproof.bulletproof_commits.created_at_mut() =
            Some(PedersonCommitment::commit_with_blind(&created_at, created_at_blind).compress());
        *bulletproof.bulletproof_commits.measurement_count_mut() = Some(
            PedersonCommitment::commit_with_blind(&measurement_count, measurement_count_blind)
                .compress(),
        );

        Ok(CredentialPresentation {
            presentation,
            bulletproof,
            schnorr_proof,
        })
    }

    pub fn finalize_issuance(
        &mut self,
        issuance_attr: OoniIssuanceAttributes,
        blind: Scalar,
    ) -> anyhow::Result<()> {
        // TODO: Verify a proof from the issuer that they issued the MAC correctly.
        // Add in the issuance_attr (i.e. the pseudonym key).
        ensure!(
            self.attributes.pseudonym_key == Scalar::ZERO,
            "response from issuer has non-zero pseudonym_key"
        );
        self.attributes = self.attributes.clone() + issuance_attr;
        self.mac.remove_blind(blind);
        self.mac.randomize(rand::thread_rng());
        Ok(())
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
        issuance_attr_commit: &PedersonCommitment<CompressedRistretto, OoniIssuanceAttributes>,
        opening_proof: &SchnorrProof,
    ) -> anyhow::Result<Credential> {
        let attributes = OoniAttributes {
            pseudonym_key: Scalar::ZERO,
            is_trusted,
            created_at: at,
            measurement_count: 0,
        };
        // Derive the pederson generators used from the public public parameters.
        let pederson_gens = self.key.public_parameters().into_pederson();
        let issuance_pederson_gens =
            OoniIssuanceAttributes::pederson_generators_from(&pederson_gens);

        let issuance_attr_commit = issuance_attr_commit
            .decompress()
            .context("decompress of pseudonym_key_commit failed")?;

        // Verify that the client knows a valid opening of the issuance attributes (i.e.
        // pseudonym key) message.
        issuance_pederson_gens.verify_opening(&issuance_attr_commit, opening_proof)?;

        // Commit with blinding factor of zero, then add the pseudonym_key committed by the client.
        let attributes_commit =
            pederson_gens.commit_with_blind(&attributes, Scalar::ZERO) + issuance_attr_commit;

        let mac = self.key.blind_mac(&attributes_commit);
        Ok(Credential { attributes, mac })
    }

    // TODO: Show the pseudonym here.
    // TODO: Optionally show the is_trusted bit here.
    pub fn verify_presentation(
        &self,
        at: u64,
        min_age: u64,
        min_measurement_count: u64,
        pres: &CredentialPresentation,
    ) -> Result<()> {
        let mut transcript =
            Transcript::new(b"rkvc_examples::ooni::Credential::present::transcript");
        let mut verifier = Verifier::new(
            b"rkvc_examples::ooni::Credential::present::constraints",
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

        // Subtract the committed creation timestamp from `at - min_age`. The result will only be
        // in the u64 range if it is less than `at - min_age`.
        let max_timestamp = at.checked_sub(min_age).unwrap();
        let mut bulletproof = pres.bulletproof.clone();
        let created_at_commit = bulletproof
            .bulletproof_commits
            .created_at()
            .as_ref()
            .context("created_at commit not included in presentation")?
            .decompress()
            .context("failed to decompress created_at commit")?;
        *bulletproof.bulletproof_commits.created_at_mut() = Some(
            (PedersonCommitment::commit_with_blind(&Scalar::from(max_timestamp), Scalar::ZERO)
                - created_at_commit)
                .compress(),
        );
        let measurement_count_commit = bulletproof
            .bulletproof_commits
            .measurement_count()
            .as_ref()
            .context("measurement_count commit not included in presentation")?
            .decompress()
            .context("failed to decompress measurement_count commit")?;
        *bulletproof.bulletproof_commits.measurement_count_mut() =
            Some((measurement_count_commit - Scalar::from(min_measurement_count)).compress());

        bulletproof.verify_range_proof(&mut transcript)?;
        Ok(())
    }

    // TODO: Show the pseudonym here.
    pub fn increment_measurement_count(
        &self,
        commit: &PedersonCommitment<RistrettoPoint, OoniAttributes>,
        pres: &CmzPresentation<CompressedRistretto, OoniAttributes>,
        proof: &SchnorrProof,
    ) -> Result<Mac<RistrettoPoint, OoniAttributes>> {
        let mut transcript = Transcript::new(
            b"rkvc_examples::ooni::Credential::increment_measurement_count::transcript",
        );
        let mut verifier = Verifier::new(
            b"rkvc_examples::ooni::Credential::increment_measurement_count::constants",
            &mut transcript,
        );
        let pederson_gens = self.key.public_parameters().into_pederson();

        // Verify that the presentation attests to knowledge of a MAC over the message committed to
        // by the given commitment. We do not need to open any of the fields of the MAC under the
        // assumption that the MAC was issued over a valid message.
        let msg_variables = self.key.constrain_presentation(&mut verifier, pres)?;
        pederson_gens.constrain_opening(&mut verifier, commit, &msg_variables)?;
        verifier.verify_compact(proof)?;

        // Increment the hidden measurement count by adding the Pederson generator point associated
        // with the measurement count. This will result in a commitment to a valid message under
        // the assumption that each chain of credentials starts with a measurement count of zero,
        // and is incremented less than than 2^64 times.
        let updated_commit: PedersonCommitment<_, OoniAttributes> =
            PedersonCommitment::from_elem(commit.elem + pederson_gens.1.measurement_count());

        // Issue a new MAC over the updated commit.
        // NOTE: Nothing prevents the client from presentating the original credential, with the
        // unicremented measurement count, again. However, they gain no advantage by doing so,
        Ok(self.key.blind_mac(&updated_commit))
    }

    pub fn public_parameters(&self) -> PublicParameters<RistrettoPoint, OoniAttributes> {
        self.key.public_parameters()
    }
}

// Walks through the mock flow of a client interacting with an issuer.
fn main() -> Result<()> {
    let issuer = Issuer::new();
    let pp = issuer.public_parameters();

    let now_timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // Client picks pseudonym_key to construct the issuance attributes.
    let issuance_attr = OoniIssuanceAttributes {
        pseudonym_key: Scalar::random(&mut rand::thread_rng()),
    };
    let (issuance_attr_commit, issance_blind) = pp
        .into_pederson()
        .commit(&issuance_attr, &mut rand::thread_rng());

    // Client sends their issuance attributes commitment to the issuer, and the issuer creates a
    // credential with the created_at time set to now_timestamp.
    let mut issuance_response =
        issuer.issue(now_timestamp, false, issuance_attr_commit.compress())?;

    // Add the issuance_attr (i.e. the pseudonym_key) into the returned credential to finalize.
    // TODO: Refactor this as a "finalize" step.
    issuance_response.mac.remove_blind(issance_blind);
    issuance_response.mac.randomize(rand::thread_rng());
    issuance_response.attributes = issuance_response.attributes + issuance_attr;
    let cred = issuance_response;

    // TODO: This flow is missing the ZKP from the issuer showing the credential was created
    // with the correct key.
    todo!("create reqeust cred");
    let cred = issuer.issue(now_timestamp, false, todo!());
    todo!("finalize cred");
    println!("Issued a credential with attributes: {:?}", cred.attributes);

    Ok(())
}
