mod error;
mod dalek;
mod sodium;

use std::convert::{From, Into};

impl From<dalek::KeyPair> for sodium::KeyPair {
    fn from(k: dalek::KeyPair) -> Self {
        sodium::KeyPair {
            private: k.private().to_bytes(),
            public: k.public().to_bytes(),
        }
    }
}

impl From<sodium::KeyPair> for dalek::KeyPair {
    fn from(k: sodium::KeyPair) -> Self {
        let private = dalek::PrivateKey::from_bytes(&k.private).unwrap();
        let public = dalek::PublicKey::from_bytes(&k.public).unwrap();

        dalek::KeyPair {
            private: private.0,
            public: public.0,
        }
    }
}

impl From<dalek::TokenSignature> for sodium::TokenSignature {
    fn from(s: dalek::TokenSignature) -> Self {
        let parameters = s.parameters.iter()
            .map(|k| k.compress().to_bytes()).collect();

        sodium::TokenSignature {
            parameters,
            z: s.z.to_bytes(),
        }
    }
}

impl From<sodium::TokenSignature> for dalek::TokenSignature {
    fn from(s: sodium::TokenSignature) -> Self {
        let parameters = s.parameters.iter()
            .map(|k| curve25519_dalek::ristretto::CompressedRistretto::from_slice(k).decompress().unwrap()).collect();

        dalek::TokenSignature {
            parameters,
            z: curve25519_dalek::scalar::Scalar::from_canonical_bytes(s.z).unwrap(),
        }
    }
}

impl From<dalek::Token> for sodium::Token {
    fn from(t: dalek::Token) -> Self {
        sodium::Token {
            messages: t.messages,
            keys: t.keys.iter()
                .map(|k| k.0.compress().to_bytes()).collect(),
            signature: t.signature.into(),
        }
    }
}

impl From<sodium::Token> for dalek::Token {
    fn from(t: sodium::Token) -> Self {

        dalek::Token {
            messages: t.messages,
            keys: t.keys.iter()
                .map(|k| curve25519_dalek::ristretto::CompressedRistretto::from_slice(k).decompress().unwrap())
                .map(dalek::PublicKey)
                .collect(),
            signature: t.signature.into(),
        }
    }
}
#[cfg(test)]
mod tests {
    use crate::{dalek, sodium};

    #[test]
    fn three_messages() {
        let message1 = b"hello";
        let keypair1_d = dalek::KeyPair::new();

        let token1_d = dalek::Token::new(&mut rand::rngs::OsRng, &keypair1_d, &message1.to_vec());

        assert_eq!(token1_d.verify(), Ok(()), "cannot verify first token (dalek)");

        let token1_s: sodium::Token = token1_d.into();
        assert_eq!(token1_s.verify(), Ok(()), "cannot verify first token (sodium)");

        println!("will derive a second token");

        let message2 = b"world";
        let keypair2_s = sodium::KeyPair::new();

        let token2_s = token1_s.append(&keypair2_s, message2.to_vec());

        assert_eq!(token2_s.verify(), Ok(()), "cannot verify second token (sodium)");

        let token2_d: dalek::Token = token2_s.into();
        assert_eq!(token2_d.verify(), Ok(()), "cannot verify second token (dalek)");

        println!("will derive a third token");

        let message3 = b"!!!";
        let keypair3_d = dalek::KeyPair::new();

        let token3_d = token2_d.append(&mut rand::rngs::OsRng, &keypair3_d, message3);

        assert_eq!(token3_d.verify(), Ok(()), "cannot verify third token (dalek)");

        let token3_s: sodium::Token = token3_d.into();
        assert_eq!(token3_s.verify(), Ok(()), "cannot verify third token (sodium)");
        panic!();
    }
}
