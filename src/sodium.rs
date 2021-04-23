use super::error;
use libsodium_sys::*;
use std::fmt;

pub type Scalar = [u8; crypto_core_ristretto255_SCALARBYTES as usize];
pub type Point = [u8; crypto_core_ristretto255_BYTES as usize];
pub type Sha512Hash = [u8; crypto_hash_sha512_BYTES as usize];

pub struct KeyPair {
    pub private: Scalar,
    pub public: Point,
}

impl KeyPair {
    pub fn new() -> Self {
        // calling FFI functions require the unsafe indicator
        unsafe {
            let mut private = [0u8; crypto_core_ristretto255_SCALARBYTES as usize];
            //FIXME: test return values
            crypto_core_ristretto255_scalar_random(private.as_mut_ptr());

            let mut public = [0u8; crypto_core_ristretto255_BYTES as usize];
            // generate a point in the Ristretto group from the scalar and the generator
            crypto_scalarmult_ristretto255_base(public.as_mut_ptr(), private.as_ptr());

            KeyPair { private, public }
        }
    }
}

impl fmt::Display for KeyPair {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
      write!(f, "({}, {})", hex::encode(self.private), hex::encode(self.public))
  }
}

// overwrite the memory of the private key when deleting it
impl Drop for KeyPair {
  fn drop(&mut self) {
      unsafe {
          sodium_memzero(self.private.as_mut_ptr() as *mut _, crypto_core_ristretto255_SCALARBYTES as usize);
      }
  }
}

pub type PublicKey = Point;

pub struct Token {
    pub messages: Vec<Vec<u8>>,
    pub keys: Vec<PublicKey>,
    pub signature: TokenSignature,
}

pub struct TokenSignature {
    pub parameters: Vec<Point>,
    pub z: Scalar,
}

impl Token {
    pub fn new(root_key_pair: &KeyPair, message: Vec<u8>) -> Self {
        let signature = TokenSignature::sign_one_message(root_key_pair, &message);

        println!("first z: {}", hex::encode(signature.z));
        Token {
            messages: vec![message],
            keys: vec![root_key_pair.public],
            signature,
        }
    }

    pub fn append(&self, key_pair: &KeyPair, message: Vec<u8>) -> Self {
        let new_signature = TokenSignature::sign_one_message(key_pair, &message);
        let aggregated_signature = TokenSignature::aggregate(&self.signature, &new_signature);

        println!("new z: {}, aggregated: {}",
                 hex::encode(new_signature.z),
                 hex::encode(aggregated_signature.z),
                 );
        let mut new_token = Token {
            messages: self.messages.clone(),
            keys: self.keys.clone(),
            signature: aggregated_signature,
        };

        new_token.messages.push(message);
        new_token.keys.push(key_pair.public);

        new_token
    }

    pub fn verify(&self) -> Result<(), error::Signature> {
        self.signature.verify(&self.keys, &self.messages)
    }
}

impl TokenSignature {
    pub fn sign_one_message(key_pair: &KeyPair, message: &[u8]) -> Self {
        unsafe {
            // r <- random scalar
            let mut r = [0u8; crypto_core_ristretto255_SCALARBYTES as usize];
            crypto_core_ristretto255_scalar_random(r.as_mut_ptr());

            // A = r * BASEPOINT
            let mut A = [0u8; crypto_core_ristretto255_BYTES as usize];
            crypto_scalarmult_ristretto255_base(A.as_mut_ptr(), r.as_ptr());

            let d = hash_points(&[A]);
            let e = hash_message(key_pair.public, &message);

            // let z = r * d - e * keypair.private;
            let mut r_d = [0u8; crypto_core_ristretto255_SCALARBYTES as usize];
            crypto_core_ristretto255_scalar_mul(r_d.as_mut_ptr(), r.as_ptr(), d.as_ptr());
            let mut e_privatekey = [0u8; crypto_core_ristretto255_SCALARBYTES as usize];
            crypto_core_ristretto255_scalar_mul(e_privatekey.as_mut_ptr(), e.as_ptr(), key_pair.private.as_ptr());
            let mut z = [0u8; crypto_core_ristretto255_SCALARBYTES as usize];
            crypto_core_ristretto255_scalar_sub(z.as_mut_ptr(), r_d.as_ptr(), e_privatekey.as_ptr());

            TokenSignature {
                parameters: vec![A],
                z
            }
        }
    }

    pub fn aggregate(first: &TokenSignature, second: &TokenSignature) -> Self {
        let mut parameters = first.parameters.clone();
        parameters.extend(second.parameters.iter().cloned());

        unsafe {
            // z = first.z + second.z
            let mut z = [0u8; crypto_core_ristretto255_SCALARBYTES as usize];
            crypto_core_ristretto255_scalar_add(
                z.as_mut_ptr(),
                first.z.as_ptr(),
                second.z.as_ptr());

            TokenSignature {
                parameters,
                z
            }
        }
    }

    pub fn verify(&self, public_keys: &[PublicKey], messages: &[Vec<u8>]) -> Result<(), error::Signature> {
        if !(public_keys.len() == messages.len() && public_keys.len() == self.parameters.len()) {
            println!("invalid data");
            return Err(error::Signature::InvalidFormat);
        }

        if public_keys.len() == 0 {
            println!("invalid data");
            return Err(error::Signature::InvalidFormat);
        }

        unsafe {
            // zP = z * BASEPOINT
            let mut zP = [0u8; crypto_core_ristretto255_BYTES as usize];
            crypto_scalarmult_ristretto255_base(zP.as_mut_ptr(), self.z.as_ptr());

            // ei = hash_message(public_keys[i], messages[i]);
            // eiXi_res = sum(ei * public_keys[i]) for i from 0 to public_keys.len()
            // a buffer full of zeroes is the identity point
            let mut eiXi_res = [0u8; crypto_core_ristretto255_BYTES as usize];

            for i in 0..public_keys.len() {
                let mut eiXi = [0u8; crypto_core_ristretto255_BYTES as usize];

                let mut ei = hash_message(public_keys[i], &messages[i]);
                crypto_scalarmult_ristretto255(
                    eiXi.as_mut_ptr(),
                    ei.as_ptr(),
                    public_keys[i].as_ptr()
                );

                let mut eiXi_res_tmp = [0u8; crypto_core_ristretto255_BYTES as usize];
                crypto_core_ristretto255_add(
                    eiXi_res_tmp.as_mut_ptr(),
                    eiXi_res.as_ptr(),
                    eiXi.as_ptr());
                eiXi_res = eiXi_res_tmp;
            }

            // ei = hash_message(public_keys[i], messages[i]);
            // diAi_res = sum(hash_points([Ai]) * Ai) for i from 0 to public_keys.len()
            let mut diAi_res = [0u8; crypto_core_ristretto255_BYTES as usize];

            for i in 0..public_keys.len() {
                let mut diAi = [0u8; crypto_core_ristretto255_BYTES as usize];

                let mut di = hash_points(&[self.parameters[i]]);

                crypto_scalarmult_ristretto255(
                    diAi.as_mut_ptr(),
                    di.as_ptr(),
                    self.parameters[i].as_ptr()
                );

                let mut diAi_res_tmp = [0u8; crypto_core_ristretto255_BYTES as usize];
                crypto_core_ristretto255_add(
                    diAi_res_tmp.as_mut_ptr(),
                    diAi_res.as_ptr(),
                    diAi.as_ptr());

                diAi_res = diAi_res_tmp;
            }


            // let res = zP + eiXi_res - diAi_res;
            let mut res_tmp = [0u8; crypto_core_ristretto255_BYTES as usize];
            crypto_core_ristretto255_add(
                res_tmp.as_mut_ptr(),
                zP.as_ptr(),
                eiXi_res.as_ptr());

            let mut res = [0u8; crypto_core_ristretto255_BYTES as usize];
            crypto_core_ristretto255_sub(
                res.as_mut_ptr(),
                res_tmp.as_ptr(),
                diAi_res.as_ptr());

            // res should be the identity point
            let mut res2 = [0u8; crypto_core_ristretto255_BYTES as usize];
            crypto_core_ristretto255_sub(
                res2.as_mut_ptr(),
                res.as_ptr(),
                res.as_ptr());

            println!("identity test: res = {}, res2 = {}",
                     hex::encode(res), hex::encode(res2));
            if res == res2 {
                Ok(())
            } else {
                Err(error::Signature::InvalidSignature)
            }
        }
    }
}

fn hash_points(points: &[Point]) -> Scalar {
    // the crypto_hash_sha512_state_malloc could be used here
    let mut hasher = crypto_hash_sha512_state {
        state: [0u64; 8],
        count: [0u64; 2],
        buf: [0u8; 128],
    };

    unsafe {
        let _res = crypto_hash_sha512_init((&mut hasher) as *mut _);

        for point in points.iter() {
            let _res = crypto_hash_sha512_update(
                (&mut hasher) as *mut _,
                point.as_ptr(),
                crypto_core_ristretto255_BYTES as u64,
            );
        }

        // write the hash in this array
        let mut hash = [0u8; crypto_hash_sha512_BYTES as usize];
        let _res = crypto_hash_sha512_final(
            (&mut hasher) as *mut _,
            hash.as_mut_ptr() as *mut _);

        let mut scalar = [0u8; crypto_core_ristretto255_SCALARBYTES as usize];
        let _res = crypto_core_ristretto255_scalar_reduce(
            scalar.as_mut_ptr() as *mut _,
            hash.as_ptr() as *const _);

        scalar
    }
}

fn hash_message(point: Point, message: &[u8]) -> Scalar {
    // the crypto_hash_sha512_state_malloc could be used here
    let mut hasher = crypto_hash_sha512_state {
        state: [0u64; 8],
        count: [0u64; 2],
        buf: [0u8; 128],
    };

    unsafe {
        let _res = crypto_hash_sha512_init((&mut hasher) as *mut _);

        let _res = crypto_hash_sha512_update(
            (&mut hasher) as *mut _,
            point.as_ptr(),
            crypto_core_ristretto255_BYTES as u64,
            );

        let _res = crypto_hash_sha512_update(
            (&mut hasher) as *mut _,
            message.as_ptr(),
            message.len() as u64,
            );

        // write the hash in this array
        let mut hash = [0u8; crypto_hash_sha512_BYTES as usize];
        let _res = crypto_hash_sha512_final(
            (&mut hasher) as *mut _,
            hash.as_mut_ptr() as *mut _);

        let mut scalar = [0u8; crypto_core_ristretto255_SCALARBYTES as usize];
        let _res = crypto_core_ristretto255_scalar_reduce(
            scalar.as_mut_ptr() as *mut _,
            hash.as_ptr() as *const _);

        scalar
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use libsodium_sys::*;

    #[test]
    fn three_messages() {
        let message1 = b"hello";
        let keypair1 = KeyPair::new();

        let token1 = Token::new(&keypair1, message1.to_vec());

        assert_eq!(token1.verify(), Ok(()), "cannot verify first token");

        println!("will derive a second token");

        let message2 = b"world";
        let keypair2 = KeyPair::new();

        let token2 = token1.append(&keypair2, message2.to_vec());

        assert_eq!(token2.verify(), Ok(()), "cannot verify second token");

        println!("will derive a third token");

        let message3 = b"!!!";
        let keypair3 = KeyPair::new();

        let token3 = token2.append(&keypair3, message3.to_vec());

        assert_eq!(token3.verify(), Ok(()), "cannot verify third token");
    }
}

