pub trait DigitalSignature {
    type SecretKey;
    type PublicKey;

    // keygen algorithm
    fn keygen(sec_level: u64) -> Result<(Self::SecretKey, Self::PublicKey), &'static str>;

    // sign algorithm
    fn sign(pk: &Self::SecretKey, message: &[u8]) -> Result<Vec<u8>, &'static str>;

    // verify algorithm
    fn verify(pk: &Self::PublicKey, signature: &[u8], message: &[u8])
        -> Result<bool, &'static str>;
}
