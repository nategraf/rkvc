use core::{convert::Infallible, marker::PhantomData, ops::Mul};

use blake2::{Blake2b512, Digest};
use curve25519_dalek::{
    constants::{RISTRETTO_BASEPOINT_POINT, RISTRETTO_BASEPOINT_TABLE},
    ristretto::CompressedRistretto,
    RistrettoPoint, Scalar as RistrettoScalar,
};
use generic_array::GenericArray;
use group::{Group, GroupEncoding};
use rand_core::CryptoRngCore;
use subtle::ConstantTimeEq;
use typenum::Unsigned;

use crate::{
    attributes::{AttributeCount, Attributes, UintEncoder},
    pederson::PedersonCommitment,
    zkp::{CompactProof as SchnorrProof, Constraint, Prover, Transcript},
};

pub struct Key<F, Msg>(F, GenericArray<F, Msg::N>)
where
    Msg: AttributeCount;

pub struct PublicParameters<G, Msg>(G, GenericArray<G, Msg::N>)
where
    Msg: AttributeCount;

pub struct Mac<G, Msg> {
    u: G,
    v: G,
    _phantom_msg: PhantomData<Msg>,
}

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
    VerificationError,
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
        // H is used as the base point to commit to the first scalar in the key, x_0. It is
        // critical that it not have a known discreet log relative to G, the base point used to
        // commit to other key values.
        let h =
            RistrettoPoint::hash_from_bytes::<Blake2b512>(b"rvkc::cmz::Key::public_parameters::h");
        PublicParameters(
            h.mul(self.0),
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
                + itertools::zip_eq(UintEncoder::encode(msg), self.1.iter())
                    .map(|(m, x)| m * x)
                    .sum::<RistrettoScalar>(),
        );
        Mac {
            u: (&u_scalar).mul(RISTRETTO_BASEPOINT_TABLE),
            v: (&v_scalar).mul(RISTRETTO_BASEPOINT_TABLE),
            _phantom_msg: PhantomData,
        }
    }

    pub fn verify(&self, msg: &Msg, mac: Mac<RistrettoPoint, Msg>) -> Result<(), Error> {
        let invalid_u = mac.u.is_identity();
        let v = mac.u.mul(
            self.0
                + itertools::zip_eq(UintEncoder::encode(msg), self.1.iter())
                    .map(|(m, x)| m * x)
                    .sum::<RistrettoScalar>(),
        );
        let invalid_v = mac.v.ct_eq(&v);
        match (invalid_u | invalid_v).into() {
            true => Err(Error::VerificationError),
            false => Ok(()),
        }
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
    Msg: Attributes<UintEncoder<RistrettoScalar>>,
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
        self.randomize(rng);
        let r_v = RistrettoScalar::random(rng);
        let commit_v = self.v + pp.0.mul(r_v);

        let r: GenericArray<RistrettoScalar, Msg::N> = (0..Msg::N::USIZE)
            .map(|_| RistrettoScalar::random(rng))
            .collect();
        let commit_msg = itertools::zip_eq(UintEncoder::encode(msg), r.as_slice())
            .map(|(m, r_i)| self.u.mul(m) + RISTRETTO_BASEPOINT_TABLE.mul(r_i))
            .collect::<GenericArray<RistrettoPoint, Msg::N>>();
        let z = itertools::zip_eq(r.as_slice(), pp.1.as_slice())
            .map(|(r_i, x_i)| x_i.mul(r_i))
            .sum::<RistrettoPoint>()
            - RISTRETTO_BASEPOINT_TABLE.mul(&r_v);

        // Produce a ZKP attesting to the knowledge of an opening for the committed values.
        // NOTE: Unwrap will never panic, prove_presentation is infallible.
        let proof = self
            .prove_presentation(r_v, z, r, msg, pp, &commit_msg)
            .unwrap();

        Presentation {
            u: self.u.compress(),
            commit_v: commit_v.compress(),
            commit_msg: commit_msg.iter().map(|c| c.compress()).collect(),
            proof,
        }
    }

    fn prove_presentation(
        &self,
        r_v: RistrettoScalar,
        z: RistrettoPoint,
        r: GenericArray<RistrettoScalar, Msg::N>,
        msg: &Msg,
        pp: &PublicParameters<RistrettoPoint, Msg>,
        commit_msg: &GenericArray<RistrettoPoint, Msg::N>,
    ) -> Result<SchnorrProof, Infallible> {
        let mut transcript = Transcript::new(b"rkvc::cmz::Mac::presentation::transcript");
        let mut prover = Prover::new(b"rkvc::cmz::Mac::presentation::prover", &mut transcript);
        let mut constraint_z = Constraint::new();
        let g_var = prover
            .allocate_point(
                b"rkvc::cmz::Mac::presentation::g",
                RISTRETTO_BASEPOINT_POINT,
            )
            .0;
        let u_var = prover
            .allocate_point(b"rkvc::cmz::Mac::presentation::u", self.u)
            .0;
        let iter = itertools::zip_eq(
            itertools::zip_eq(UintEncoder::encode(msg), r.as_slice()),
            itertools::zip_eq(commit_msg.as_slice(), pp.1.as_slice()),
        );
        for ((m_i, r_i), (c_i, x_i)) in iter {
            // TODO: Differentiate labels across loop iterations.
            let r_i_var = prover.allocate_scalar(b"rkvc::cmz::Mac::presentation::r_i", *r_i);
            constraint_z.add(
                &mut prover,
                r_i_var,
                ("rkvc::cmz::Mac::presentation::x_i", *x_i),
            )?;

            let mut constraint_c_i = Constraint::new();
            constraint_c_i.add(
                &mut prover,
                ("rkvc::cmz::Mac::presentation::m_i", m_i),
                u_var,
            )?;
            constraint_c_i.add(&mut prover, r_i_var, g_var)?;
            constraint_c_i.eq(&mut prover, ("rkvc::cmz::Mac::presentation::c_i", *c_i))?;
        }
        constraint_z.add(
            &mut prover,
            ("rkvc::cmz::Mac::presentation::r_v", -r_v),
            ("rkvc::cmz::Mac::presentation::h", pp.0),
        )?;
        constraint_z.eq(&mut prover, ("rkvc::cmz::Mac::presentation::z", z))?;
        Ok(prover.prove_compact())
    }
}
