use core::{convert::Infallible, marker::PhantomData, ops::Mul};

use blake2::{Blake2b512, Digest};
use curve25519_dalek::{
    constants::{RISTRETTO_BASEPOINT_POINT, RISTRETTO_BASEPOINT_TABLE},
    ristretto::CompressedRistretto,
    RistrettoPoint, Scalar as RistrettoScalar,
};
use generic_array::GenericArray;
use group::{Group, GroupEncoding};
use itertools::zip_eq;
use rand_core::CryptoRngCore;
use subtle::ConstantTimeEq;
use typenum::Unsigned;

use crate::{
    attributes::{AttributeCount, Attributes, Identity, UintEncoder},
    pederson::{PedersonCommitment, PedersonGenerators},
    zkp::{
        AllocPointVar, AllocScalarVar, CompactProof as SchnorrProof, Constraint, Prover,
        Transcript, Verifier,
    },
};

#[derive(Clone)]
pub struct Key<F, Msg>(F, GenericArray<F, Msg::N>)
where
    Msg: AttributeCount;

#[derive(Debug, Clone)]
#[cfg_attr(test, derive(PartialEq, Eq))]
pub struct PublicParameters<G, Msg>(G, GenericArray<G, Msg::N>)
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
    u: G,
    commit_v: G,
    commit_msg: GenericArray<G, Msg::N>,
    proof: SchnorrProof,
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

impl<Msg> Key<RistrettoScalar, Msg>
where
    Msg: AttributeCount,
{
    pub fn blind_mac(
        &self,
        commit: &PedersonCommitment<RistrettoPoint, Msg>,
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

    pub fn public_parameters(&self) -> PublicParameters<RistrettoPoint, Msg> {
        PublicParameters(
            PublicParameters::<RistrettoPoint, Msg>::h().mul(self.0),
            self.1
                .iter()
                .map(|x| RISTRETTO_BASEPOINT_TABLE.mul(x))
                .collect(),
        )
    }
}

impl<Msg> Key<RistrettoScalar, Msg>
where
    Msg: AttributeCount,
{
    pub fn gen<R>(rng: &mut R) -> Self
    where
        R: CryptoRngCore + ?Sized,
    {
        Self(
            RistrettoScalar::random(rng),
            (0..Msg::N::USIZE)
                .map(|_| RistrettoScalar::random(rng))
                .collect(),
        )
    }
}

// TODO: Add methods that yield both a mac and a ZKP.
impl<Msg> Key<RistrettoScalar, Msg>
where
    Msg: Attributes<UintEncoder<RistrettoScalar>>,
{
    pub fn mac(&self, msg: &Msg) -> Mac<RistrettoPoint, Msg> {
        // Use a hasher to generate the secret dlog of U from a combination of the secret key and
        // the message attributes. Ensures that two messages will not be mac'd with the same U.
        // TODO: This is fine when used with Blake2, but using HKDF or simmilar may be better.
        let mut hasher = Blake2b512::new();
        hasher.update("rkvc::cmz::Key::mac");
        hasher.update(self.0.as_bytes());
        for m in UintEncoder::encode(msg) {
            hasher.update(m.as_bytes());
        }
        let u_scalar = RistrettoScalar::from_hash(hasher);
        let v_scalar: RistrettoScalar = (&u_scalar).mul(
            self.0
                + zip_eq(UintEncoder::encode(msg), self.1.iter())
                    .map(|(m, x)| m * x)
                    .sum::<RistrettoScalar>(),
        );
        Mac {
            u: (&u_scalar).mul(RISTRETTO_BASEPOINT_TABLE),
            v: (&v_scalar).mul(RISTRETTO_BASEPOINT_TABLE),
            _phantom_msg: PhantomData,
        }
    }

    pub fn verify(&self, msg: &Msg, mac: &Mac<RistrettoPoint, Msg>) -> Result<(), Error> {
        let invalid_u = mac.u.is_identity();
        let v = mac.u.mul(
            self.0
                + zip_eq(UintEncoder::encode(msg), self.1.iter())
                    .map(|(m, x)| m * x)
                    .sum::<RistrettoScalar>(),
        );
        let invalid_v = !mac.v.ct_eq(&v);
        match (invalid_u | invalid_v).into() {
            true => Err(Error::VerificationFailed),
            false => Ok(()),
        }
    }
}

impl<Msg> Key<RistrettoScalar, Msg>
where
    Msg: Attributes<Identity<RistrettoScalar>>,
{
    pub fn verify_presentation(
        &self,
        pres: &Presentation<CompressedRistretto, Msg>,
    ) -> Result<(), Error> {
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
                .collect::<Result<GenericArray<_, Msg::N>, _>>()?
                .into_iter()
                .sum::<RistrettoPoint>();

        verify_presentation(
            &pres.proof,
            pres.u,
            z,
            &self.public_parameters().compress(),
            &pres.commit_msg,
        )?;
        Ok(())
    }
}

impl<Msg> PublicParameters<RistrettoPoint, Msg>
where
    Msg: AttributeCount,
{
    /// H is used as the base point to commit to the first scalar in the key, x_0. It is
    /// critical that it not have a known discreet log relative to G, the base point used to
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
                .collect::<Option<GenericArray<_, _>>>()?,
        ))
    }
}

impl<G, Msg> From<PublicParameters<G, Msg>> for PedersonGenerators<G, Msg::N>
where
    Msg: AttributeCount,
    G: Group,
{
    fn from(value: PublicParameters<G, Msg>) -> Self {
        // NOTE: We use the group generator here as the blind generator as a requirement to then be
        // able to remove the blinding from the final MAC. Without this, the blinding factor for a
        // commit would need to be carried as part of the MAC.
        Self(G::generator(), value.1)
    }
}

impl<Msg> Mac<RistrettoPoint, Msg>
where
    Msg: AttributeCount,
{
    /// Upon receiving the MAC, the blinding factor used to hide the message from the issuer can
    /// and should be removed. This is done by setting V = V - sU.
    pub fn remove_blind(&mut self, blind: RistrettoScalar) {
        self.v -= self.u.mul(blind);
    }

    /// Randomize the MAC such that revealing the newly randomized U value cannot result in linkage
    /// to the original issued U value. This should be done when receiving the MAC, and before any
    /// presentation.
    pub fn randomize<R>(&mut self, rng: &mut R) -> RistrettoScalar
    where
        R: CryptoRngCore + ?Sized,
    {
        let r = RistrettoScalar::random(rng);
        self.u = self.u.mul(r);
        self.v = self.v.mul(r);
        r
    }
}

impl<Msg> Mac<RistrettoPoint, Msg>
where
    Msg: Attributes<Identity<RistrettoScalar>>,
{
    /// Creates a hiding (i.e. zero-knowledge) presentation of the MAC that can be verified by the
    /// issuer to ensure that the presenter has knowledge of a valid MAC, without learning anything
    /// about the underlying message.
    ///
    /// Internally randomizes the MAC before generating the presentation.
    pub fn present<R>(
        &mut self,
        msg: &Msg,
        pp: &PublicParameters<RistrettoPoint, Msg>,
        rng: &mut R,
    ) -> Presentation<CompressedRistretto, Msg>
    where
        R: CryptoRngCore + ?Sized,
    {
        // Randomize the RNG before presentation to ensure that the sent U value cannot be linked
        // to the one that was issued, or shown in any previous presentation of the same MAC.
        self.randomize(rng);

        let r_v = RistrettoScalar::random(rng);
        let commit_v_blind_point = PublicParameters::<RistrettoPoint, Msg>::h().mul(r_v);
        let commit_v = self.v + commit_v_blind_point;

        let r: GenericArray<RistrettoScalar, Msg::N> = (0..Msg::N::USIZE)
            .map(|_| RistrettoScalar::random(rng))
            .collect();
        let commit_msg = zip_eq(Identity::elem_iter(msg), r.as_slice())
            .map(|(m_i, r_i)| self.u.mul(m_i) + RISTRETTO_BASEPOINT_TABLE.mul(r_i))
            .collect::<GenericArray<RistrettoPoint, Msg::N>>();
        let z = zip_eq(r.as_slice(), pp.1.as_slice())
            .map(|(r_i, pp_i)| pp_i.mul(r_i))
            .sum::<RistrettoPoint>()
            - commit_v_blind_point;

        // Produce a ZKP attesting to the knowledge of an opening for the committed values.
        // NOTE: Unwrap will never panic, prove_presentation is infallible.
        let proof = prove_presentation(self.u, r_v, z, r, msg, pp, &commit_msg).unwrap();

        Presentation {
            u: self.u.compress(),
            commit_v: commit_v.compress(),
            commit_msg: commit_msg.iter().map(|c| c.compress()).collect(),
            proof,
        }
    }
}

fn verify_presentation<Msg: AttributeCount>(
    proof: &SchnorrProof,
    u: CompressedRistretto,
    z: RistrettoPoint,
    pp: &PublicParameters<CompressedRistretto, Msg>,
    commit_msg: &GenericArray<CompressedRistretto, Msg::N>,
) -> Result<(), crate::zkp::ProofError> {
    // A small macro to construct the labels for variables that get added to the transcript.
    macro_rules! label {
        ($s:literal) => {
            concat!("rkvc::cmz::Mac::presentation::", $s)
        };
    }
    let mut transcript = Transcript::new(label!("transcript").as_bytes());
    let mut verifier = Verifier::new(label!("constraints").as_bytes(), &mut transcript);

    // Allocate variables used in multiple constraint declarations.
    let g_var = verifier.alloc_point((label!("g"), RISTRETTO_BASEPOINT_POINT))?;
    let u_var = verifier.alloc_point((label!("u"), u))?;
    let r_vars: GenericArray<_, Msg::N> =
        verifier.alloc_scalars((0..Msg::N::USIZE).map(|_| label!("r_i")))?;

    // Constrain Z = \Sigma^n_i r_i * X_i - r_v * H
    let mut constraint_z = Constraint::new();
    constraint_z.sum(
        &mut verifier,
        r_vars.iter().copied(),
        pp.1.iter().map(|pp_i| (label!("pp_i"), *pp_i)),
    )?;
    constraint_z.add(
        &mut verifier,
        label!("-r_v"),
        (
            label!("h"),
            PublicParameters::<RistrettoPoint, Msg>::h().compress(),
        ),
    )?;
    constraint_z.eq(&mut verifier, (label!("z"), z))?;

    // Constrain each C_i = m_i * U + r_i * G
    for (r_i_var, c_i) in zip_eq(r_vars.as_slice(), commit_msg.as_slice()) {
        let mut constraint_c_i = Constraint::new();
        constraint_c_i.add(&mut verifier, label!("m_i"), u_var)?;
        constraint_c_i.add(&mut verifier, *r_i_var, g_var)?;
        constraint_c_i.eq(&mut verifier, (label!("c_i"), *c_i))?;
    }

    verifier.verify_compact(proof)
}

fn prove_presentation<Msg>(
    u: RistrettoPoint,
    r_v: RistrettoScalar,
    z: RistrettoPoint,
    r: GenericArray<RistrettoScalar, Msg::N>,
    msg: &Msg,
    pp: &PublicParameters<RistrettoPoint, Msg>,
    commit_msg: &GenericArray<RistrettoPoint, Msg::N>,
) -> Result<SchnorrProof, Infallible>
where
    Msg: Attributes<Identity<RistrettoScalar>>,
{
    // A small macro to construct the labels for variables that get added to the transcript.
    macro_rules! label {
        ($s:literal) => {
            concat!("rkvc::cmz::Mac::presentation::", $s)
        };
    }
    let mut transcript = Transcript::new(label!("transcript").as_bytes());
    let mut prover = Prover::new(label!("constraints").as_bytes(), &mut transcript);

    // Allocate variables used in multiple constraint declarations.
    let g_var = prover.alloc_point((label!("g"), RISTRETTO_BASEPOINT_POINT))?;
    let u_var = prover.alloc_point((label!("u"), u))?;
    let r_vars: GenericArray<_, Msg::N> =
        prover.alloc_scalars(r.iter().map(|r_i| (label!("r_i"), *r_i)))?;

    // Constrain Z = \Sigma^n_i r_i * X_i - r_v * H
    let mut constraint_z = Constraint::new();
    constraint_z.sum(
        &mut prover,
        r_vars.iter().copied(),
        pp.1.iter().map(|pp_i| (label!("pp_i"), *pp_i)),
    )?;
    constraint_z.add(
        &mut prover,
        (label!("-r_v"), -r_v),
        (label!("h"), PublicParameters::<RistrettoPoint, Msg>::h()),
    )?;
    constraint_z.eq(&mut prover, (label!("z"), z))?;

    // Constrain each C_i = m_i * U + r_i * G
    let iter = zip_eq(
        zip_eq(Identity::elem_iter(msg), r_vars.as_slice()),
        commit_msg.as_slice(),
    );
    for ((m_i, r_i_var), c_i) in iter {
        let mut constraint_c_i = Constraint::new();
        constraint_c_i.add(&mut prover, (label!("m_i"), m_i), u_var)?;
        constraint_c_i.add(&mut prover, *r_i_var, g_var)?;
        constraint_c_i.eq(&mut prover, (label!("c_i"), *c_i))?;
    }

    Ok(prover.prove_compact())
}

#[cfg(test)]
mod test {
    use curve25519_dalek::Scalar as RistrettoScalar;
    use rkvc_derive::Attributes;

    use super::{Error, Key};
    use crate::pederson::PedersonGenerators;

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
        // TODO: This needs to commit using the public_parameters.
        let (commit, blind) =
            PedersonGenerators::from(pp.clone()).commit(&example, &mut rand::thread_rng());
        let mut mac = key.blind_mac(&commit);
        mac.remove_blind(blind);
        mac.randomize(&mut rand::thread_rng());

        // Ensure that the MAC verifies when given the plaintext message.
        key.verify(&example, &mac).unwrap();
        // Ensure that the MAC verifies when given a presentation.
        let presentation = mac.present(&example, &key.public_parameters(), &mut rand::thread_rng());
        key.verify_presentation(&presentation).unwrap();
    }

    #[test]
    fn basic_blind_mac_fail() {
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
    fn public_parameters_compress_decompress() {
        let key = Key::<RistrettoScalar, ExampleA>::gen(&mut rand::thread_rng());
        let pp = key.public_parameters();
        assert_eq!(pp, pp.compress().decompress().unwrap());
    }
}
