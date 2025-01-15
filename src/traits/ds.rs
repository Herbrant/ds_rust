pub trait DigitalSignature<SecretKey, PublicKey> {
    // keygen algorithm
    fn keygen(sec_level: u64) -> Result<(SecretKey, PublicKey), &'static str>;

    // sign algorithm
    fn sign(pk: &SecretKey, message: &[u8]) -> Result<Vec<u8>, &'static str>;

    // verify algorithm
    fn verify(pk: &PublicKey, signature: &[u8], message: &[u8]) -> Result<bool, &'static str>;
}
