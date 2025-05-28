//! An implementaion of the µCMZ algerbraic MAC.

use core::{marker::PhantomData, ops::Mul};

use blake2::{Blake2b512, Digest};
use curve25519_dalek::{
    constants::{RISTRETTO_BASEPOINT_POINT, RISTRETTO_BASEPOINT_TABLE},
    ristretto::CompressedRistretto,
    RistrettoPoint, Scalar as RistrettoScalar,
};
use group::{Group, GroupEncoding};
use itertools::zip_eq;
use rand::{CryptoRng, RngCore};
use subtle::ConstantTimeEq;
use typenum::Unsigned;

use crate::{
    attributes::{AttributeArray, AttributeCount, Attributes, IdentityEncoder, UintEncoder},
    pedersen::{PedersenCommitment, PedersenGenerators},
    predicate::{
        Error as PredicateError, Instance, LinearCombination, PointVar, Relation, ScalarVar,
        Witness,
    },
    zkp::CompactProof as SchnorrProof,
};

// TODO: A weakness exists with the current design that needs to be mitigated with the addition of
// an extra key element. I need to learn the specifics of this weakness and address this.
#[derive(Clone)]
pub struct Key<F, Msg>(F, AttributeArray<F, Msg>)
where
    Msg: AttributeCount;

#[derive(Debug)]
#[cfg_attr(test, derive(PartialEq, Eq))]
pub struct PublicParameters<G, Msg>(G, AttributeArray<G, Msg>)
where
    Msg: AttributeCount;

impl<G, Msg> Clone for PublicParameters<G, Msg>
where
    G: Clone,
    Msg: AttributeCount,
{
    fn clone(&self) -> Self {
        Self(self.0.clone(), self.1.clone())
    }
}

#[derive(Debug)]
pub struct Mac<G, Msg> {
    u: G,
    v: G,
    _phantom_msg: PhantomData<Msg>,
}

impl<G: Clone, Msg> Clone for Mac<G, Msg> {
    fn clone(&self) -> Self {
        Self {
            u: self.u.clone(),
            v: self.v.clone(),
            _phantom_msg: PhantomData,
        }
    }
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

impl<Msg: AttributeCount> Presentation<RistrettoPoint, Msg> {
    pub fn compress(&self) -> Presentation<CompressedRistretto, Msg> {
        Presentation {
            u: self.u.compress(),
            commit_v: self.commit_v.compress(),
            commit_msg: self.commit_msg.iter().map(|p| p.compress()).collect(),
        }
    }
}

impl<Msg: AttributeCount> Presentation<CompressedRistretto, Msg> {
    pub fn decompress(&self) -> Option<Presentation<RistrettoPoint, Msg>> {
        Some(Presentation {
            u: self.u.decompress()?,
            commit_v: self.commit_v.decompress()?,
            commit_msg: self
                .commit_msg
                .iter()
                .map(|p| p.decompress())
                .collect::<Option<_>>()?,
        })
    }
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
    // this commitment.
    pub fn verify_presentation(
        &self,
        pres: &Presentation<CompressedRistretto, Msg>,
        proof: &SchnorrProof,
    ) -> Result<(), Error>
    where
        Msg: Attributes<IdentityEncoder<RistrettoScalar>>,
    {
        let pres = pres.decompress().ok_or(Error::DecompressFailed)?;
        let statement = CmzPresentationStatement {
            u: pres.u,
            pp: self.public_parameters(),
        };
        let mut relation = Relation::default();
        let vars = statement.constrain(&mut relation);

        // Calculate Z = x_0 * U + \Sigma_i x_i * C_i - C_v
        // NOTE: This is computed here because the verifier and prover use different methods to
        // calculate the z point.
        let z = pres.u.mul(self.0)
            + zip_eq(self.1.as_slice(), pres.commit_msg.as_slice())
                .map(|(x_i, c_i)| c_i.mul(x_i))
                .sum::<RistrettoPoint>()
            - pres.commit_v;

        let mut instance = Instance::default();
        statement.assign_instance(
            &vars,
            &mut instance,
            &CmzPresentationInstance {
                z,
                commit_msg: pres.commit_msg.clone(),
            },
        );

        // TODO: Use a better error type.
        relation
            .verify(&instance, proof)
            .map_err(|_| Error::VerificationFailed)?;
        Ok(())
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
        let statement = CmzPresentationStatement {
            u: self.u,
            pp: pp.clone(),
        };
        let mut relation = Relation::default();
        let vars = statement.constrain(&mut relation);
        let r_v = RistrettoScalar::random(&mut rng);
        let mut witness = Witness::default();
        statement.assign_witness(
            &vars,
            &mut witness,
            &CmzPresentationWitness {
                msg: msg.encode_attributes().collect(),
                r_v,
                r_msg: AttributeArray::random(&mut rng),
            },
        );
        let (instance, proof) = relation.prove(&witness).unwrap();
        let cmz_instance = statement.extract_instance(&vars, &instance).unwrap();

        let presentation = Presentation {
            commit_msg: cmz_instance.commit_msg,
            u: self.u,
            // NOTE: r_v * H gets computed twice here since there is no notion of a secret point
            // variable in the system right now.
            commit_v: self.v + r_v * PublicParameters::<RistrettoPoint, Msg>::h(),
        };
        (presentation.compress(), proof)
    }
}

trait ConstraintSystem {
    type Relation;
    type Instance;
    type Witness;
    type Proof;
    type Error;
}

struct SchnorrConstaintSystem;

impl ConstraintSystem for SchnorrConstaintSystem {
    type Relation = Relation;
    type Instance = Instance;
    type Witness = Witness;
    type Proof = SchnorrProof;
    type Error = PredicateError;
}

trait Statement<CS: ConstraintSystem> {
    type Vars;
    type Instance;
    type Witness;

    fn constrain(&self, cs: &mut CS::Relation) -> Self::Vars;

    fn assign_witness(&self, vars: &Self::Vars, cs: &mut CS::Witness, witness: &Self::Witness);

    fn assign_instance(
        &self,
        vars: &Self::Vars,
        cs_instance: &mut CS::Instance,
        instance: &Self::Instance,
    );

    fn extract_instance(
        &self,
        vars: &Self::Vars,
        instance: &CS::Instance,
    ) -> Result<Self::Instance, CS::Error>;
}

// Have a notion of a constraint system, which exposes an API to define contraints.

struct CmzPresentationStatement<Msg: AttributeCount> {
    u: RistrettoPoint,
    pp: PublicParameters<RistrettoPoint, Msg>,
}

struct CmzPresentationVars<Msg: AttributeCount> {
    z: PointVar,
    commit_msg: AttributeArray<PointVar, Msg>,
    r_v: ScalarVar,
    r_msg: AttributeArray<ScalarVar, Msg>,
    msg: AttributeArray<ScalarVar, Msg>,
}

struct CmzPresentationInstance<Msg: AttributeCount> {
    z: RistrettoPoint,
    commit_msg: AttributeArray<RistrettoPoint, Msg>,
}

struct CmzPresentationWitness<Msg: AttributeCount> {
    r_v: RistrettoScalar,
    r_msg: AttributeArray<RistrettoScalar, Msg>,
    msg: AttributeArray<RistrettoScalar, Msg>,
}

impl<Msg: AttributeCount> Statement<SchnorrConstaintSystem> for CmzPresentationStatement<Msg> {
    type Vars = CmzPresentationVars<Msg>;
    type Witness = CmzPresentationWitness<Msg>;
    type Instance = CmzPresentationInstance<Msg>;

    fn constrain(&self, rel: &mut Relation) -> Self::Vars {
        let g = RISTRETTO_BASEPOINT_POINT;
        let r_msg: AttributeArray<ScalarVar, Msg> = rel.alloc_scalars(Msg::N::USIZE).collect();
        let r_v = rel.alloc_scalar();

        // Constrain Z = \Sigma^n_i r_i * X_i - r_v * H
        let mut z_constraint = LinearCombination::default();
        for (r_i, pp_i) in zip_eq(r_msg.iter().copied(), self.pp.1.iter().copied()) {
            z_constraint = z_constraint + r_i * pp_i;
        }
        z_constraint = z_constraint - r_v * PublicParameters::<RistrettoPoint, Msg>::h();
        let z = rel.alloc_eq(z_constraint);

        // Constrain each C_i = m_i * U + r_i * G
        let msg: AttributeArray<ScalarVar, Msg> = rel.alloc_scalars(Msg::N::USIZE).collect();
        let commit_msg: AttributeArray<PointVar, Msg> = zip_eq(r_msg.as_slice(), msg.as_slice())
            .map(|(r_i, m_i)| rel.alloc_eq(*m_i * self.u + *r_i * g))
            .collect();

        Self::Vars {
            z,
            commit_msg,
            r_v,
            r_msg,
            msg,
        }
    }

    fn assign_witness(&self, vars: &Self::Vars, cs_witness: &mut Witness, witness: &Self::Witness) {
        cs_witness.assign_scalar(vars.r_v, witness.r_v);
        cs_witness.assign_scalars(zip_eq(
            vars.msg.iter().copied(),
            witness.msg.iter().copied(),
        ));
        cs_witness.assign_scalars(zip_eq(
            vars.r_msg.iter().copied(),
            witness.r_msg.iter().copied(),
        ));
    }

    fn assign_instance(
        &self,
        vars: &Self::Vars,
        cs_instance: &mut Instance,
        instance: &Self::Instance,
    ) {
        cs_instance.assign_point(vars.z, instance.z);
        cs_instance.assign_points(zip_eq(
            vars.commit_msg.0.clone(),
            instance.commit_msg.0.clone(),
        ));
    }

    fn extract_instance(
        &self,
        vars: &Self::Vars,
        cs_instance: &Instance,
    ) -> Result<Self::Instance, PredicateError> {
        Ok(Self::Instance {
            z: cs_instance.point_val(vars.z),
            commit_msg: cs_instance
                .point_vals(vars.commit_msg.iter().copied())
                .collect(),
        })
    }
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
