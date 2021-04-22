
mod sodium {
    use libsodium_sys::*;

    #[test]
    fn test() {
        let mut priv_key = [0u8; crypto_core_ristretto255_SCALARBYTES as usize];
        unsafe {
            crypto_core_ristretto255_scalar_random(priv_key.as_mut_ptr());
        }
        let mut pub_key = [0u8; crypto_core_ristretto255_BYTES as usize];
        unsafe {
            crypto_scalarmult_ristretto255_base(pub_key.as_mut_ptr(), priv_key.as_ptr());
        }


        // sign
        let mut r = [0u8; crypto_core_ristretto255_SCALARBYTES as usize];
        unsafe {
            crypto_core_ristretto255_scalar_random(r.as_mut_ptr());
        }
        let mut A = [0u8; crypto_core_ristretto255_BYTES as usize];
        unsafe {
            crypto_scalarmult_ristretto255_base(A.as_mut_ptr(), r.as_ptr());
        }

        // compress must use ristretto255_p3_tobytes
        /*
         unsigned char r[crypto_core_ristretto255_SCALARBYTES];
unsigned char gr[crypto_core_ristretto255_BYTES];
unsigned char a[crypto_core_ristretto255_BYTES];
crypto_core_ristretto255_scalar_random(r);
crypto_scalarmult_ristretto255_base(gr, r);
crypto_core_ristretto255_add(a, px, gr);

        */

    }
}

