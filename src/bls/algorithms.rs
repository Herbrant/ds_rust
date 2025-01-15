use blstrs::{pairing, G1Affine, G1Projective, G2Affine, Scalar};
use ff::Field;
use group::Curve;
use group::{prime::PrimeCurveAffine, GroupEncoding};
use rand_core::OsRng;

use crate::traits::ds::DigitalSignature;

use super::keys::{BLSPublicKey, BLSSecretKey};

// Ref: https://datatracker.ietf.org/doc/html/rfc9380
const CSUITE: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";

pub struct BLS;

impl DigitalSignature<BLSSecretKey, BLSPublicKey> for BLS {
    fn keygen(sec_level: u64) -> Result<(BLSSecretKey, BLSPublicKey), &'static str> {
        if sec_level != 100 {
            return Err("The implementation supports only the BLS12_381 curve, which supports approximately 100-bit security.");
        }

        let x = Scalar::random(OsRng);
        let pk = (G2Affine::generator() * x).to_affine();

        let sk = BLSSecretKey { x };
        let pk = BLSPublicKey { pk };

        Ok((sk, pk))
    }

    fn sign(sk: &BLSSecretKey, message: &[u8]) -> Result<Vec<u8>, &'static str> {
        let h = G1Projective::hash_to_curve(message, CSUITE, &[]);
        let sigma = h * sk.x;

        let sigma_bytes = sigma.to_bytes().as_ref().to_vec();

        Ok(sigma_bytes)
    }

    fn verify(pk: &BLSPublicKey, signature: &[u8], message: &[u8]) -> Result<bool, &'static str> {
        if signature.len() != 48 {
            return Err("Invalid signature size.");
        }

        let sigma: [u8; 48] = signature.try_into().unwrap(); // TO-FIX
        let sigma = G1Affine::from_compressed(&sigma).unwrap(); // TO-FIX

        let h = G1Projective::hash_to_curve(&message, CSUITE, &[]).to_affine();

        let term1 = pairing(&sigma, &G2Affine::generator());
        let term2 = pairing(&h, &pk.pk);

        if term1 == term2 {
            return Ok(true);
        } else {
            return Ok(false);
        }
    }
}

#[cfg(test)]
mod test {
    use crate::traits::ds::DigitalSignature;

    use super::BLS;


    #[test]
    fn bls_gen_failes_on_wrong_sec_level() {
        let bls = BLS::keygen(192);
        assert!(bls.is_err());
    }

    #[test]
    fn scheme_works_as_expected() {
        let m = ("test\0").as_bytes();
        let (sk, pk) = BLS::keygen(100).unwrap();
        let s = BLS::sign(&sk, m).unwrap();
        let b = BLS::verify(&pk, &s, m).unwrap();
        assert!(b);
    }

    #[test]
    #[should_panic]
    fn scheme_should_fail() {
        let m1 = ("testA\0").as_bytes();
        let m2 = ("testB\0").as_bytes();
        let (sk, pk) = BLS::keygen(100).unwrap();
        let s = BLS::sign(&sk, m1).unwrap();
        let b = BLS::verify(&pk, &s, m2).unwrap();
        assert!(b);
    }

}
