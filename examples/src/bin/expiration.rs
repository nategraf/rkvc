use anyhow::Result;
use curve25519_dalek::{ristretto::CompressedRistretto, RistrettoPoint, Scalar};
use rkvc::{
    cmz::{Key, Mac, PublicParameters},
    zkp::{Prover, Transcript, Verifier},
    Attributes, UintEncoder,
};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Attributes, Clone, Debug)]
struct ExpirationAttributes {
    #[allow(dead_code)]
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
    // TODO: This is incomplete, since I haven't finished up the part of the range checks that
    // constrains the attributes to a subrange (e.g. less than `at`),
    pub fn present(
        &self,
        pp: &PublicParameters<RistrettoPoint, ExpirationAttributes>,
        _at: u64,
    ) -> Result<CredentialPresentation> {
        let mut transcript =
            Transcript::new(b"rkvc_examples::expiration::Credential::present::transcript");
        let mut prover = Prover::new(
            b"rkvc_examples::expiration::Credential::present::constraints",
            &mut transcript,
        );

        let (presentation, msg_variables) = self.mac.prove_presentation_constraints(
            &mut prover,
            &self
                .attributes
                .attribute_walk(UintEncoder::default())
                .collect(),
            pp,
            &mut rand::thread_rng(),
        );
        let (bulletproof_commits, bulletproof_openings) =
            rkvc::range::PoK::prove_range_commit_constaints(
                &mut prover,
                &msg_variables,
                &self.attributes,
            )?;

        // NOTE: Uses rand::thread_rng internally, in conmbination with witness data.
        let schnorr_proof = prover.prove_compact();
        let bulletproof = rkvc::range::PoK::prove_bulletproof(
            &mut transcript,
            bulletproof_commits,
            bulletproof_openings,
        )?;

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
            key: Key::gen(&mut rand::thread_rng()),
        }
    }

    pub fn issue(&self, expiration: u64) -> Credential {
        let attributes = ExpirationAttributes { expiration };
        let mac = self.key.mac(&attributes);
        Credential { attributes, mac }
    }

    // TODO: This is incomplete, since I haven't finished up the part of the range checks that
    // constrains the attributes to a subrange (e.g. less than `at`),
    pub fn verify_presentation(
        &self,
        _at: u64,
        presentation: &CredentialPresentation,
    ) -> Result<()> {
        let mut transcript =
            Transcript::new(b"rkvc_examples::expiration::Credential::present::transcript");
        let mut verifier = Verifier::new(
            b"rkvc_examples::expiration::Credential::present::constraints",
            &mut transcript,
        );

        let msg_variables = self
            .key
            .constrain_presentation(&mut verifier, &presentation.presentation)?;
        rkvc::range::PoK::constrain_range_commit_opening(
            &mut verifier,
            &presentation.bulletproof,
            &msg_variables,
        )?;

        // NOTE: Uses rand::thread_rng internally, in conmbination with witness data.
        verifier.verify_compact(&presentation.schnorr_proof)?;
        rkvc::range::PoK::verify_bulletproof(&mut transcript, &presentation.bulletproof)?;
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
    let cred = issuer.issue(now_timestamp + 30);
    println!("Issued a credential with attributes: {:?}", cred.attributes);

    // 15 seconds later, they present their credential.
    let later_timestamp = now_timestamp + 15;
    let presentation = cred.present(&pp, later_timestamp)?;
    println!("Created a presentation for the validity of the credential at {later_timestamp}");

    issuer.verify_presentation(later_timestamp, &presentation)?;
    println!("Issuer verified the credential");

    Ok(())
}
