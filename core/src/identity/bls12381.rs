use super::error::{DecodingError};
use blst::min_sig as blst_impl;
use core::cmp;
use core::hash;
use rand::Rng;
use zeroize::Zeroize;

pub const DST: &[u8] = b"BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_POP_";
const DST_POP: &[u8] = b"BLS_POP_BLS12381G1_XMD:SHA-256_SSWU_RO_POP_";

#[derive(Clone, Debug)]
pub struct Keypair {
    secret: SecretKey,
    public: PublicKey,
}

impl Keypair {
    /// Generate a new BLS12-381 keypair.
    pub fn generate() -> Keypair {
        Keypair::from(SecretKey::generate())
    }

    /// Sign a message using the private key of this keypair.
    pub fn sign(&self, msg: &[u8]) -> Vec<u8> {
        self.secret.sign(msg)
    }

    /// Get the public key of this keypair.
    pub fn public(&self) -> &PublicKey {
        &self.public
    }

    /// Get the secret key of this keypair.
    pub fn secret(&self) -> &SecretKey {
        &self.secret
    }
}

impl From<SecretKey> for Keypair {
    fn from(secret: SecretKey) -> Keypair {
        let sk = &secret.0;
        let public = PublicKey(sk.sk_to_pk());
        Keypair { secret, public }
    }
}

#[derive(Clone, Debug)]
pub struct SecretKey(blst_impl::SecretKey);

impl SecretKey {
    pub fn generate() -> SecretKey {
        let ikm = rand::thread_rng().gen::<[u8; 32]>();
        SecretKey(blst_impl::SecretKey::key_gen(&ikm, &[]).expect("key_gen failed"))
    }

    pub fn sign(&self, msg: &[u8]) -> Vec<u8> {
        let signature = self.0.sign(msg, &DST, &[]);
        signature.to_bytes().to_vec()
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    pub fn from_bytes(mut sk: impl AsMut<[u8]>) -> Result<SecretKey, DecodingError> {
        let sk_bytes = sk.as_mut();
        let secret = blst_impl::SecretKey::from_bytes(&*sk_bytes)
            .map_err(|e| DecodingError::new(format!("bls12381 public key: {:?}", &e)))?;
        sk_bytes.zeroize();
        Ok(SecretKey(secret))
    }
}

#[derive(Clone, Eq, PartialEq, Debug)]
pub struct PublicKey(blst_impl::PublicKey);

impl PublicKey {
    pub fn verify(&self, msg: &[u8], sig: &[u8]) -> bool {
        let signature = blst_impl::Signature::from_bytes(sig).expect("signature from_bytes failed");
        signature.verify(false, msg, &DST, &[], &self.0, false) == blst::BLST_ERROR::BLST_SUCCESS
    }

    pub fn encode(&self) -> [u8; 96] {
        self.0.to_bytes()
    }

    pub fn decode(k: &[u8]) -> Result<PublicKey, DecodingError> {
        blst_impl::PublicKey::from_bytes(k)
            .map_err(|e| DecodingError::new(format!("bls12381 public key: {:?}", &e)))
            .map(PublicKey)
    }
}

impl hash::Hash for PublicKey {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        self.encode().hash(state);
    }
}

impl cmp::PartialOrd for PublicKey {
    fn partial_cmp(&self, other: &Self) -> Option<cmp::Ordering> {
        self.encode().partial_cmp(&other.encode())
    }
}

impl cmp::Ord for PublicKey {
    fn cmp(&self, other: &Self) -> cmp::Ordering {
        self.encode().cmp(&other.encode())
    }
}
