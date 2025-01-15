use blstrs::{G2Affine, Scalar};

// Represents the BLS's public key
#[derive(Debug)]
pub struct BLSPublicKey {
    pub pk: G2Affine,
}

// Represents the BLS's secret key
#[derive(Debug)]
pub struct BLSSecretKey {
    pub x: Scalar,
}

impl BLSPublicKey {
    pub fn new(pk: G2Affine) -> Self {
        Self { pk }
    }
}

impl BLSSecretKey {
    pub fn new(x: Scalar) -> Self {
        Self { x }
    }
}
