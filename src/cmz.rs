//! An implementaion of the µCMZ algerbraic MAC.

use core::{convert::Infallible, marker::PhantomData, ops::Mul};

use blake2::{Blake2b512, Digest};
use curve25519_dalek::{
    constants::{RISTRETTO_BASEPOINT_POINT, RISTRETTO_BASEPOINT_TABLE},
    ristretto::CompressedRistretto,
    RistrettoPoint, Scalar as RistrettoScalar,
};
use group::{Group, GroupEncoding};
use hybrid_array::Array;
use itertools::zip_eq;
use rand::{CryptoRng, RngCore};
use subtle::ConstantTimeEq;
use typenum::Unsigned;

use crate::{
    attributes::{AttributeArray, AttributeCount, Attributes, IdentityEncoder, UintEncoder},
    pedersen::{PedersenCommitment, PedersenGenerators},
    zkp::{
        AllocPointVar, AllocScalarVar, CompactProof as SchnorrProof, Constraint, Prover, SchnorrCS,
        Transcript, Verifier,
    },
};

// TODO: A weakness exists with the current design that needs to be mitigated with the addition of
// an extra key element. I need to learn the specifics of this weakness and address this.
#[derive(Clone)]
pub struct Key<F, Msg>(F, AttributeArray<F, Msg>)
where
    Msg: AttributeCount;

#[derive(Debug, Clone)]
#[cfg_attr(test, derive(PartialEq, Eq))]
pub struct PublicParameters<G, Msg>(G, AttributeArray<G, Msg>)
where
    Msg: AttributeCount;

#[derive(Debug, Clone)]
pub struct Mac<G, Msg> {
    u: G,
    v: G,
    _phantom_msg: PhantomData<Msg>,
}

#[derive(Clone)]
pub struct Presentation<G, Msg: AttributeCount>
where
    Msg: AttributeCount,
{
    /// The value U from the MAC. Note that the U value is randomized by the client upon receipt.
    pub u: G,
    /// Hiding commitment to the point V from the MAC.
    pub commit_v: G,
    /// An array of Pedersen commitments to the attributes using the generators U and the basepoint
    /// of the group.
    pub commit_msg: AttributeArray<G, Msg>,
}

#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("verification failed")]
    VerificationFailed,
    #[error("decompress of a group element failed")]
    DecompressFailed,
    #[error("schnorr proof verification error: {0:?}")]
    ZkpError(crate::zkp::ProofError),
}

impl From<crate::zkp::ProofError> for Error {
    fn from(value: crate::zkp::ProofError) -> Self {
        Error::ZkpError(value)
    }
}

// TODO: Add methods that yield both a mac and a ZKP.
impl<Msg> Key<RistrettoScalar, Msg>
where
    Msg: AttributeCount,
{
    pub fn gen(mut rng: impl CryptoRng + RngCore) -> Self {
        Self(
            RistrettoScalar::random(&mut rng),
            (0..Msg::N::USIZE)
                .map(|_| RistrettoScalar::random(&mut rng))
                .collect(),
        )
    }

    pub fn public_parameters(&self) -> PublicParameters<RistrettoPoint, Msg> {
        PublicParameters(
            PublicParameters::<RistrettoPoint, Msg>::h().mul(self.0),
            self.1
                .iter()
                .map(|x| RISTRETTO_BASEPOINT_TABLE.mul(x))
                .collect(),
        )
    }

    pub fn mac(&self, msg: &Msg) -> Mac<RistrettoPoint, Msg>
    where
        Msg: Attributes<UintEncoder<RistrettoScalar>>,
    {
        // Use a hasher to generate the secret dlog of U from a combination of the secret key and
        // the message attributes. Ensures that two messages will not be mac'd with the same U.
        // TODO: This is fine when used with Blake2, but using HKDF or simmilar may be better.
        let mut hasher = Blake2b512::new();
        hasher.update("rkvc::cmz::Key::mac");
        hasher.update(self.0.as_bytes());
        for m in msg.encode_attributes() {
            hasher.update(m.as_bytes());
        }
        let u_scalar = RistrettoScalar::from_hash(hasher);
        let v_scalar: RistrettoScalar = (&u_scalar).mul(
            self.0
                + zip_eq(msg.encode_attributes(), self.1.iter())
                    .map(|(m, x)| m * x)
                    .sum::<RistrettoScalar>(),
        );
        Mac {
            u: (&u_scalar).mul(RISTRETTO_BASEPOINT_TABLE),
            v: (&v_scalar).mul(RISTRETTO_BASEPOINT_TABLE),
            _phantom_msg: PhantomData,
        }
    }

    pub fn verify(&self, msg: &Msg, mac: &Mac<RistrettoPoint, Msg>) -> Result<(), Error>
    where
        Msg: Attributes<UintEncoder<RistrettoScalar>>,
    {
        let invalid_u = mac.u.is_identity();
        let v = mac.u.mul(
            self.0
                + zip_eq(msg.encode_attributes(), self.1.iter())
                    .map(|(m, x)| m * x)
                    .sum::<RistrettoScalar>(),
        );
        let invalid_v = !mac.v.ct_eq(&v);
        match (invalid_u | invalid_v).into() {
            true => Err(Error::VerificationFailed),
            false => Ok(()),
        }
    }

    pub fn blind_mac(
        &self,
        commit: &PedersenCommitment<RistrettoPoint, Msg>,
    ) -> Mac<RistrettoPoint, Msg> {
        // Use a hasher to generate the secret dlog of U from a combination of the secret key and
        // the commitment. Ensures that two messages will not be mac'd with the same U. Note that
        // the commitment must be binding here.
        let mut hasher = Blake2b512::new();
        hasher.update("rkvc::cmz::Key::blind_mac");
        hasher.update(self.0.as_bytes());
        hasher.update(commit.elem.to_bytes());
        let u_scalar = RistrettoScalar::from_hash(hasher);
        let v = u_scalar.mul((&self.0).mul(RISTRETTO_BASEPOINT_TABLE) + commit.elem);
        Mac {
            u: (&u_scalar).mul(RISTRETTO_BASEPOINT_TABLE),
            v,
            _phantom_msg: PhantomData,
        }
    }

    // NOTE: Requiring the message to be encodable with the Identity encoder restricts to messages
    // that only contain the group scalar field elements (and not e.g. u64), which is important for
    // the soundness of the semantics (i.e. ensuring the sender knows a valid MAC'd message).
    //
    // TODO: If the issuer ensures they only ever MAC messages that are valid (e.g. they check a
    // range proof on issuance) this requirement could be lifted to an extent. One way to
    // accommodate this is to require a range proof be attached here (or in another method). A
    // range proof is not required if the message is encodable with Identity. In real applications,
    // range proofs are only strictly required when the issuer wants to run (non-field) arithmetic
    // on a secret value (e.g. subtracting 1 from a quota). Fields that are not modified can be
    // assumed to be in range by the fact that they were checked at issuance, either with a range
    // proof of because the fields were set by the issuer.
    //
    // Perhaps I should return a commitment here, as an indication that they should be checking
    // this commitment. Main issue with this is that the presentation includes a SchnorrProof and
    // already, and doing anything useful with the commit would require further binding it.
    pub fn verify_presentation(
        &self,
        pres: &Presentation<CompressedRistretto, Msg>,
        proof: &SchnorrProof,
    ) -> Result<(), Error>
    where
        Msg: Attributes<IdentityEncoder<RistrettoScalar>>,
    {
        let mut transcript = Transcript::new(b"rkvc::cmz::Mac::presentation::transcript");
        let mut verifier = Verifier::new(
            b"rkvc::cmz::Mac::presentation::constraints",
            &mut transcript,
        );
        self.constrain_presentation(&mut verifier, pres)?;
        verifier.verify_compact(proof)?;
        Ok(())
    }

    // NOTE: This function exists as a partial answer to the comments above on the Identity
    // trait bound for Msg. TODO: Should it be moved as a member of the presentation.
    pub fn constrain_presentation<'a>(
        &self,
        verifier: &mut Verifier<'a>,
        pres: &Presentation<CompressedRistretto, Msg>,
    ) -> Result<AttributeArray<<Verifier<'a> as SchnorrCS>::ScalarVar, Msg>, Error> {
        let u = pres.u.decompress().ok_or(Error::DecompressFailed)?;
        // NOTE: Unwrapping the CtChoice is ok here because U is non-private.
        if u.is_identity().into() {
            return Err(Error::VerificationFailed);
        }
        let commit_v = pres.commit_v.decompress().ok_or(Error::DecompressFailed)?;

        // Calculate Z = x_0 * U + \Sigma_i x_i * C_i - C_v
        let z = u.mul(self.0) - commit_v
            + zip_eq(self.1.as_slice(), pres.commit_msg.as_slice())
                .map(|(x_i, c_i)| {
                    c_i.decompress()
                        .ok_or(Error::DecompressFailed)
                        .map(|c_i| c_i.mul(x_i))
                })
                .collect::<Result<Array<_, Msg::N>, _>>()?
                .into_iter()
                .sum::<RistrettoPoint>();

        let m_vars = constrain_presentation(
            verifier,
            pres.u,
            z,
            &self.public_parameters().compress(),
            &pres.commit_msg,
        )?;
        Ok(m_vars)
    }
}

impl<G, Msg> PublicParameters<G, Msg>
where
    Msg: AttributeCount,
    G: Group,
{
    /// Converts the public public public parameters into [PedersenGenerators] for use in
    /// committing a message than can then be used as input for a blind MAC.
    ///
    /// Uses the group generator here as the blind generator as a requirement to then be
    /// able to remove the blinding from the final MAC. Without this, the blinding factor for a
    /// commit would need to be carried as part of the MAC.
    pub fn into_pedersen(self) -> PedersenGenerators<G, Msg> {
        PedersenGenerators(G::generator(), self.1)
    }
}

impl<Msg> PublicParameters<RistrettoPoint, Msg>
where
    Msg: AttributeCount,
{
    /// H is used as the base point to commit to the first scalar in the key, x_0.
    ///
    /// It is critical that it not have a known discrete log relative to G, the base point used to
    /// commit to other key values.
    pub fn h() -> RistrettoPoint {
        RistrettoPoint::hash_from_bytes::<Blake2b512>(b"rvkc::cmz::Key::public_parameters::h")
    }

    pub fn compress(&self) -> PublicParameters<CompressedRistretto, Msg> {
        PublicParameters(
            self.0.compress(),
            self.1.iter().map(|pp_i| pp_i.compress()).collect(),
        )
    }
}

impl<Msg> PublicParameters<CompressedRistretto, Msg>
where
    Msg: AttributeCount,
{
    pub fn decompress(&self) -> Option<PublicParameters<RistrettoPoint, Msg>> {
        Some(PublicParameters(
            self.0.decompress()?,
            self.1
                .iter()
                .map(|pp_i| pp_i.decompress())
                .collect::<Option<AttributeArray<_, _>>>()?,
        ))
    }
}

impl<Msg> Mac<RistrettoPoint, Msg> {
    /// Upon receiving the MAC, the blinding factor used to hide the message from the issuer can
    /// and should be removed. This is done by setting V = V - sU.
    pub fn remove_blind(&mut self, blind: RistrettoScalar) {
        self.v -= self.u.mul(blind);
    }

    /// Randomize the MAC such that revealing the newly randomized U value cannot result in linkage
    /// to the original issued U value. This should be done when receiving the MAC, and before any
    /// presentation.
    pub fn randomize(&mut self, mut rng: impl CryptoRng + RngCore) -> RistrettoScalar {
        let r = RistrettoScalar::random(&mut rng);
        self.u = self.u.mul(r);
        self.v = self.v.mul(r);
        r
    }

    /// Creates a hiding (i.e. zero-knowledge) presentation of the MAC that can be verified by the
    /// issuer to ensure that the presenter has knowledge of a valid MAC, without learning anything
    /// about the underlying message.
    ///
    /// Internally randomizes the MAC before generating the presentation.
    pub fn present(
        &mut self,
        msg: &Msg,
        pp: &PublicParameters<RistrettoPoint, Msg>,
        mut rng: impl CryptoRng + RngCore,
    ) -> (Presentation<CompressedRistretto, Msg>, SchnorrProof)
    where
        Msg: Attributes<IdentityEncoder<RistrettoScalar>>,
    {
        // Randomize the RNG before presentation to ensure that the sent U value cannot be linked
        // to the one that was issued, or shown in any previous presentation of the same MAC.
        self.randomize(&mut rng);

        // Produce a ZKP attesting to the knowledge of an opening for the committed values.
        // NOTE: Unwrap will never panic, prove_presentation is infallible.
        let mut transcript = Transcript::new(b"rkvc::cmz::Mac::presentation::transcript");
        let mut prover = Prover::new(
            b"rkvc::cmz::Mac::presentation::constraints",
            &mut transcript,
        );
        let (presentation, _) = self.prove_presentation_constraints(
            &mut prover,
            &msg.encode_attributes().collect(),
            pp,
            &mut rng,
        );
        let proof = prover.prove_compact();

        (presentation, proof)
    }

    /// Adds the constraints for the presentation to an existing prover, in order to compose with
    /// other statements being proven.
    ///
    /// Does not randomize the MAC; [Mac::randomize] should be called seperately.
    pub fn prove_presentation_constraints<'a>(
        &self,
        prover: &mut Prover<'a>,
        msg_encoded: &Array<RistrettoScalar, Msg::N>,
        pp: &PublicParameters<RistrettoPoint, Msg>,
        mut rng: impl RngCore + CryptoRng,
    ) -> (
        Presentation<CompressedRistretto, Msg>,
        AttributeArray<<Prover<'a> as SchnorrCS>::ScalarVar, Msg>,
    )
    where
        Msg: AttributeCount,
    {
        let r_v = RistrettoScalar::random(&mut rng);
        let commit_v_blind_point = PublicParameters::<RistrettoPoint, Msg>::h().mul(r_v);
        let commit_v = self.v + commit_v_blind_point;

        let r: AttributeArray<RistrettoScalar, Msg> = (0..Msg::N::USIZE)
            .map(|_| RistrettoScalar::random(&mut rng))
            .collect();
        let commit_msg = zip_eq(msg_encoded.as_slice(), r.as_slice())
            .map(|(m_i, r_i)| self.u.mul(m_i) + RISTRETTO_BASEPOINT_TABLE.mul(r_i))
            .collect::<AttributeArray<RistrettoPoint, Msg>>();
        let z = zip_eq(r.as_slice(), pp.1.as_slice())
            .map(|(r_i, pp_i)| pp_i.mul(r_i))
            .sum::<RistrettoPoint>()
            - commit_v_blind_point;

        // Add constraints to the prover for the correctness of the presentation.
        // NOTE: Unwrap will never panic, prove_presentation_constraints is infallible.
        let m_vars = prove_presentation_constraints(
            prover,
            self.u,
            r_v,
            z,
            &r,
            msg_encoded,
            pp,
            &commit_msg,
        )
        .unwrap();

        (
            Presentation {
                u: self.u.compress(),
                commit_v: commit_v.compress(),
                commit_msg: commit_msg.iter().map(|c| c.compress()).collect(),
            },
            m_vars,
        )
    }
}

// TODO: Is it better to take the scalar vars as an argument, or return them as is done here? The
// API is not consistent across the board.
fn constrain_presentation<'a, Msg: AttributeCount>(
    verifier: &mut Verifier<'a>,
    u: CompressedRistretto,
    z: RistrettoPoint,
    pp: &PublicParameters<CompressedRistretto, Msg>,
    commit_msg: &Array<CompressedRistretto, Msg::N>,
) -> Result<AttributeArray<<Verifier<'a> as SchnorrCS>::ScalarVar, Msg>, crate::zkp::ProofError> {
    // A small macro to construct the labels for variables that get added to the transcript.
    macro_rules! label {
        ($s:literal) => {
            concat!("rkvc::cmz::Mac::presentation::", $s)
        };
    }
    // Allocate variables used in multiple constraint declarations.
    let g_var = verifier.alloc_point((label!("g"), RISTRETTO_BASEPOINT_POINT))?;
    let u_var = verifier.alloc_point((label!("u"), u))?;
    let r_vars: AttributeArray<_, Msg> =
        verifier.alloc_scalars((0..Msg::N::USIZE).map(|_| label!("r_i")))?;

    // Constrain Z = \Sigma^n_i r_i * X_i - r_v * H
    let mut constraint_z = Constraint::new();
    constraint_z.sum(
        verifier,
        r_vars.iter().copied(),
        pp.1.iter().map(|pp_i| (label!("pp_i"), *pp_i)),
    )?;
    constraint_z.add(
        verifier,
        label!("-r_v"),
        (
            label!("h"),
            PublicParameters::<RistrettoPoint, Msg>::h().compress(),
        ),
    )?;
    constraint_z.eq(verifier, (label!("z"), z))?;

    // Constrain each C_i = m_i * U + r_i * G
    let m_vars: AttributeArray<_, Msg> =
        verifier.alloc_scalars((0..Msg::N::USIZE).map(|_| label!("m_i")))?;
    for (r_i_var, (m_var, c_i)) in zip_eq(
        r_vars.as_slice(),
        zip_eq(m_vars.iter(), commit_msg.as_slice()),
    ) {
        let mut constraint_c_i = Constraint::new();
        constraint_c_i.add(verifier, *m_var, u_var)?;
        constraint_c_i.add(verifier, *r_i_var, g_var)?;
        constraint_c_i.eq(verifier, (label!("c_i"), *c_i))?;
    }

    // Return the m variables to use in further constraints.
    Ok(m_vars)
}

#[allow(clippy::too_many_arguments)]
fn prove_presentation_constraints<'a, Msg>(
    prover: &mut Prover<'a>,
    u: RistrettoPoint,
    r_v: RistrettoScalar,
    z: RistrettoPoint,
    r: &Array<RistrettoScalar, Msg::N>,
    msg: &Array<RistrettoScalar, Msg::N>,
    pp: &PublicParameters<RistrettoPoint, Msg>,
    commit_msg: &Array<RistrettoPoint, Msg::N>,
) -> Result<AttributeArray<<Prover<'a> as SchnorrCS>::ScalarVar, Msg>, Infallible>
where
    Msg: AttributeCount,
{
    // A small macro to construct the labels for variables that get added to the transcript.
    macro_rules! label {
        ($s:literal) => {
            concat!("rkvc::cmz::Mac::presentation::", $s)
        };
    }

    // Allocate variables used in multiple constraint declarations.
    let g_var = prover.alloc_point((label!("g"), RISTRETTO_BASEPOINT_POINT))?;
    let u_var = prover.alloc_point((label!("u"), u))?;
    let r_vars: AttributeArray<_, Msg> =
        prover.alloc_scalars(r.iter().map(|r_i| (label!("r_i"), *r_i)))?;

    // Constrain Z = \Sigma^n_i r_i * X_i - r_v * H
    let mut constraint_z = Constraint::new();
    constraint_z.sum(
        prover,
        r_vars.iter().copied(),
        pp.1.iter().map(|pp_i| (label!("pp_i"), *pp_i)),
    )?;
    constraint_z.add(
        prover,
        (label!("-r_v"), -r_v),
        (label!("h"), PublicParameters::<RistrettoPoint, Msg>::h()),
    )?;
    constraint_z.eq(prover, (label!("z"), z))?;

    // Constrain each C_i = m_i * U + r_i * G
    let m_vars: AttributeArray<_, Msg> =
        prover.alloc_scalars(msg.iter().map(|m_i| (label!("m_i"), *m_i)))?;
    let iter = zip_eq(
        zip_eq(m_vars.as_slice(), r_vars.as_slice()),
        commit_msg.as_slice(),
    );
    for ((m_i, r_i_var), c_i) in iter {
        let mut constraint_c_i = Constraint::new();
        constraint_c_i.add(prover, *m_i, u_var)?;
        constraint_c_i.add(prover, *r_i_var, g_var)?;
        constraint_c_i.eq(prover, (label!("c_i"), *c_i))?;
    }

    Ok(m_vars)
}

#[cfg(test)]
mod test {
    use curve25519_dalek::Scalar as RistrettoScalar;
    use rkvc_derive::Attributes;

    use super::{Error, Key};

    #[derive(Attributes, Clone, Debug, PartialEq, Eq)]
    struct ExampleA {
        a: u64,
        b: RistrettoScalar,
    }

    // Example B only has Scalars, which is required to provide a PoK without range check.
    #[derive(Attributes, Clone, Debug, PartialEq, Eq)]
    struct ExampleB {
        a: RistrettoScalar,
        b: RistrettoScalar,
    }

    #[test]
    fn basic_mac_success() {
        let example = ExampleA {
            a: 5,
            b: 7u64.into(),
        };

        let key = Key::<RistrettoScalar, ExampleA>::gen(&mut rand::thread_rng());
        let mac = key.mac(&example);
        key.verify(&example, &mac).unwrap();
    }

    #[test]
    fn basic_mac_fail() {
        let example = ExampleA {
            a: 5,
            b: 7u64.into(),
        };

        let key = Key::<RistrettoScalar, ExampleA>::gen(&mut rand::thread_rng());
        let mac = key.mac(&example);

        let bad_example = ExampleA {
            a: 6,
            b: 7u64.into(),
        };
        let Err(Error::VerificationFailed) = key.verify(&bad_example, &mac) else {
            panic!("mac verify of the wrong message succeeded");
        };
    }

    #[test]
    fn basic_blind_mac_success() {
        let example = ExampleB {
            a: 5u64.into(),
            b: 7u64.into(),
        };

        let key = Key::<RistrettoScalar, ExampleB>::gen(&mut rand::thread_rng());
        let pp = key.public_parameters();

        // Client creates a commitment, has the MAC generated over it, then removes the blind from
        // the MAC. This should generate a MAC that is the same (except U) as a plaintext.
        let (commit, blind) = pp
            .clone()
            .into_pedersen()
            .commit(&example, rand::thread_rng());
        let mut mac = key.blind_mac(&commit);
        mac.remove_blind(blind);
        mac.randomize(&mut rand::thread_rng());

        // Ensure that the MAC verifies when given the plaintext message.
        key.verify(&example, &mac).unwrap();
        // Ensure that the MAC verifies when given a presentation.
        let (presentation, proof) = mac.present(&example, &pp, &mut rand::thread_rng());

        key.verify_presentation(&presentation, &proof).unwrap();
    }

    #[test]
    fn basic_blind_mac_fail() {
        let example = ExampleB {
            a: 5u64.into(),
            b: 7u64.into(),
        };

        let key = Key::<RistrettoScalar, ExampleB>::gen(&mut rand::thread_rng());
        let pp = key.public_parameters();

        let (commit, blind) = pp
            .clone()
            .into_pedersen()
            .commit(&example, rand::thread_rng());
        let mut mac = key.blind_mac(&commit);
        mac.remove_blind(blind);
        mac.randomize(&mut rand::thread_rng());

        // Ensure that the MAC fails to verify with a different message or key.
        let bad_example = ExampleB {
            a: 6u64.into(),
            b: 7u64.into(),
        };
        let other_key = Key::<RistrettoScalar, ExampleB>::gen(&mut rand::thread_rng());
        let Err(Error::VerificationFailed) = key.verify(&bad_example, &mac) else {
            panic!("mac verify of the wrong message succeeded");
        };
        let Err(Error::VerificationFailed) = other_key.verify(&example, &mac) else {
            panic!("mac verify with the wrong key succeeded");
        };

        // Ensure that the MAC presentation fails to verify with a different key.
        let (presentation, proof) = mac.present(&example, &pp, &mut rand::thread_rng());
        let Err(Error::VerificationFailed | Error::ZkpError(_)) =
            other_key.verify_presentation(&presentation, &proof)
        else {
            panic!("mac presentation verify with the wrong key succeeded");
        };
    }

    #[test]
    fn public_parameters_compress_decompress() {
        let key = Key::<RistrettoScalar, ExampleA>::gen(&mut rand::thread_rng());
        let pp = key.public_parameters();
        assert_eq!(pp, pp.compress().decompress().unwrap());
    }
}
