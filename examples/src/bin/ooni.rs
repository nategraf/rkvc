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
    Attributes, EncoderOutput, UintEncoder,
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
        PedersonGenerators(gens.0, [*gens.1.pseudonym_key()].into())
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

struct IncrementMeasurementCountRequest {
    pub commit: PedersonCommitment<CompressedRistretto, OoniAttributes>,
    pub presentation: CmzPresentation<CompressedRistretto, OoniAttributes>,
    pub schnorr_proof: SchnorrProof,
}

struct IncrementMeasurementCountResponse {
    mac: Mac<RistrettoPoint, OoniAttributes>,
}

impl Credential {
    /// Present the credential, with current time set to `at`, proving that the time since create
    /// is at least `min_age` and the number of measurements is at least `min_measurement_count`.
    // TODO: Add a statement about the pseudonym.
    pub fn present_auth(
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

    pub fn request_increment_measurement_count(
        &self,
        pp: &PublicParameters<RistrettoPoint, OoniAttributes>,
    ) -> (IncrementMeasurementCountRequest, Scalar) {
        let mut transcript = Transcript::new(
            b"rkvc_examples::ooni::Credential::increment_measurement_count::transcript",
        );
        let mut prover = Prover::new(
            b"rkvc_examples::ooni::Credential::increment_measurement_count::constraints",
            &mut transcript,
        );
        let pederson_gens = pp.clone().into_pederson();

        let (commit, blind) = pederson_gens.commit(&self.attributes, rand::thread_rng());

        let (presentation, msg_variables) = self.mac.prove_presentation_constraints(
            &mut prover,
            &UintEncoder::encode_attributes(&self.attributes).collect(),
            pp,
            rand::thread_rng(),
        );
        pederson_gens.prove_opening_constraints(&mut prover, &commit, &msg_variables, blind);
        let schnorr_proof = prover.prove_compact();

        (
            IncrementMeasurementCountRequest {
                commit: commit.compress(),
                presentation,
                schnorr_proof,
            },
            blind,
        )
    }
}

impl IncrementMeasurementCountResponse {
    pub fn finalize(
        self,
        pp: &PublicParameters<RistrettoPoint, OoniAttributes>,
        credential: Credential,
        blind: Scalar,
    ) -> anyhow::Result<Credential> {
        // TODO: Verify the MAC was issued correctly.

        let mut attributes = credential.attributes;
        attributes.measurement_count += 1;

        let Self { mut mac } = self;
        mac.remove_blind(blind);
        mac.randomize(rand::thread_rng());

        Ok(Credential { attributes, mac })
    }
}

struct Issuer {
    key: Key<Scalar, OoniAttributes>,
}

/// Response from an issuance request which contains the credential values supplied by the issuer.
struct IssuanceResponse {
    attributes: OoniAttributes,
    mac: Mac<RistrettoPoint, OoniAttributes>,
}

impl IssuanceResponse {
    /// Check that the issuance response is acceptable to the client.
    /// NOTE: This is part of a general pattern: parameters set by the server should be checked by
    /// the client to manipulation that may reduce the anonymity of the client.
    // TODO: Verify a proof from the issuer that they issued the MAC correctly.
    fn validate(&self) -> anyhow::Result<()> {
        ensure!(
            self.attributes.pseudonym_key == Scalar::ZERO,
            "issuance response contains non-zero pseudonym_key"
        );
        Ok(())
    }

    /// Called by the client to finalize issuance an obtain the credential.
    pub fn finalize(
        self,
        issuance_attr: OoniIssuanceAttributes,
        blind: Scalar,
    ) -> anyhow::Result<Credential> {
        self.validate()?;
        let IssuanceResponse {
            mut attributes,
            mut mac,
        } = self;
        attributes = attributes.clone() + issuance_attr;
        mac.remove_blind(blind);
        mac.randomize(rand::thread_rng());
        Ok(Credential { attributes, mac })
    }
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
    ) -> anyhow::Result<IssuanceResponse> {
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
        Ok(IssuanceResponse { attributes, mac })
    }

    // TODO: Show the pseudonym here.
    // TODO: Optionally show the is_trusted bit here.
    pub fn verify_auth_presentation(
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
        req: &IncrementMeasurementCountRequest,
    ) -> Result<IncrementMeasurementCountResponse> {
        let mut transcript = Transcript::new(
            b"rkvc_examples::ooni::Credential::increment_measurement_count::transcript",
        );
        let mut verifier = Verifier::new(
            b"rkvc_examples::ooni::Credential::increment_measurement_count::constraints",
            &mut transcript,
        );
        let pederson_gens = self.key.public_parameters().into_pederson();
        let commit = req
            .commit
            .decompress()
            .ok_or_else(|| anyhow!("decompress of commit failed"))?;

        // Verify that the presentation attests to knowledge of a MAC over the message committed to
        // by the given commitment. We do not need to open any of the fields of the MAC under the
        // assumption that the MAC was issued over a valid message.
        // TODO: This could be optimized by using the commitments that are included in the CMZ
        // presentation rather than constraining equivalence to a second commitment.
        let msg_variables = self
            .key
            .constrain_presentation(&mut verifier, &req.presentation)?;
        pederson_gens.constrain_opening(&mut verifier, &commit, &msg_variables)?;
        verifier.verify_compact(&req.schnorr_proof)?;

        // Increment the hidden measurement count by adding the Pederson generator point associated
        // with the measurement count. This will result in a commitment to a valid message under
        // the assumption that each chain of credentials starts with a measurement count of zero,
        // and is incremented less than than 2^64 times.
        let updated_commit: PedersonCommitment<_, OoniAttributes> =
            PedersonCommitment::from_elem(commit.elem + pederson_gens.1.measurement_count());

        // Issue a new MAC over the updated commit.
        // NOTE: Nothing prevents the client from presenting the original credential, with the
        // unincremented measurement count, again. However, they gain no advantage by doing so,
        // TODO: Prove correct computation of the MAC.
        Ok(IncrementMeasurementCountResponse {
            mac: self.key.blind_mac(&updated_commit),
        })
    }

    pub fn public_parameters(&self) -> PublicParameters<RistrettoPoint, OoniAttributes> {
        self.key.public_parameters()
    }
}

// Walks through the mock flow of a client interacting with an issuer.
fn main() -> Result<()> {
    // Initialize tracing subscriber (using RUST_LOG env var, default to info level)
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let issuer = Issuer::new();
    let pp = issuer.public_parameters();

    let mut now_timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    tracing::info!("Running example OONI flow with starting timestamp {now_timestamp}");

    // Client picks pseudonym_key to construct the issuance attributes.
    let issuance_attr = OoniIssuanceAttributes {
        pseudonym_key: Scalar::random(&mut rand::thread_rng()),
    };

    // Client generates a commitment to their issuance request attributes, and an opening proof.
    let issuance_pederson_gens =
        OoniIssuanceAttributes::pederson_generators_from(&pp.clone().into_pederson());
    let (issuance_attr_commit, issance_blind) =
        issuance_pederson_gens.commit(&issuance_attr, rand::thread_rng());
    let issuance_opening_proof =
        issuance_pederson_gens.prove_opening(&issuance_attr_commit, &issuance_attr, issance_blind);

    tracing::info!("Client sending issuance request with attributes: {issuance_attr:?}");

    // Client sends their issuance attributes commitment to the issuer, and the issuer creates a
    // credential with the created_at time set to now_timestamp.
    let mut issuance_response = issuer.issue(
        now_timestamp,
        false,
        &issuance_attr_commit.compress(),
        &issuance_opening_proof,
    )?;

    tracing::info!("Issuer responded to initial issuance request");

    // Add the issuance_attr (i.e. the pseudonym_key) into the returned credential to finalize.
    let credential = issuance_response.finalize(issuance_attr, issance_blind)?;

    tracing::info!(
        "Client finalized credential with attributes: {:?}",
        credential.attributes
    );

    tracing::info!("Time passes ⌚ +15s");
    now_timestamp += 15;

    tracing::info!("Client requesting updated measurement count");
    let (req, blind) = credential.request_increment_measurement_count(&pp);
    let resp = issuer.increment_measurement_count(&req)?;
    let credential = resp.finalize(&pp, credential, blind)?;
    tracing::info!(
        "Client received new credential with updated measurement_count: {:?}",
        credential.attributes
    );

    tracing::info!("Time passes ⌚ +15s");
    now_timestamp += 15;

    tracing::info!("Client requesting updated measurement count");
    let (req, blind) = credential.request_increment_measurement_count(&pp);
    let resp = issuer.increment_measurement_count(&req)?;
    let credential = resp.finalize(&pp, credential, blind)?;
    tracing::info!(
        "Client received new credential with updated measurement_count: {:?}",
        credential.attributes
    );

    tracing::info!("Time passes ⌚ +15s");
    now_timestamp += 15;

    tracing::info!("Client authenticating with min_age = 30s and min_measurement_count = 1");
    let presentation = credential.present_auth(&pp, now_timestamp, 30, 1)?;
    issuer.verify_auth_presentation(now_timestamp, 30, 1, &presentation)?;
    tracing::info!("Success ✅");

    Ok(())
}
