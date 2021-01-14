use crate::config::Committee;
use crate::messages::Payload;
use crypto::Hash as _;
use crypto::{generate_keypair, PublicKey, SecretKey, Signature};
use rand::rngs::StdRng;
use rand::SeedableRng as _;

// Fixture.
pub fn keys() -> Vec<(PublicKey, SecretKey)> {
    let mut rng = StdRng::from_seed([0; 32]);
    (0..4).map(|_| generate_keypair(&mut rng)).collect()
}

// Fixture.
pub fn committee() -> Committee {
    let authorities: Vec<_> = keys().into_iter().map(|(name, _)| name).collect();
    Committee::new(&authorities, /* epoch */ 1)
}

// Fixture.
pub fn payload() -> Payload {
    let (author, secret) = keys().pop().unwrap();
    let payload = Payload {
        transactions: vec![vec![1u8]],
        author,
        signature: Signature::default(),
    };
    let signature = Signature::new(&payload.digest(), &secret);
    Payload {
        signature,
        ..payload
    }
}