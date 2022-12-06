extern crate core;



mod ch3 {
    use des::cipher::{BlockEncrypt, KeyInit};
    use des::cipher::generic_array::GenericArray;
    use openssl::symm::{encrypt, decrypt, Cipher};
    use des::Des;
    use generic_array::typenum::consts::{U8, U16, U256};

    pub fn des2_recover_key() {
        unimplemented!()
    }

    pub fn decrypt_cipher(cipher: &[u8], key: &[u8]) -> Vec<u8> {
        decrypt(Cipher::aes_256_cbc(), key, None, cipher).unwrap()
    }

    pub fn encrypt_plaintext(plaintext: &[u8], key: &[u8]) -> Vec<u8> {
        encrypt(Cipher::aes_256_cbc(), key, None, plaintext).unwrap()
    }

    pub fn des(k: Vec<u8>, p: Vec<u8>) -> Vec<u8> {
        let k_arr: GenericArray<u8, U8> = GenericArray::clone_from_slice(&*k);
        let p_arr: GenericArray<u8, U8> = GenericArray::clone_from_slice(&*p);

        let des = Des::new_from_slice(&k_arr).unwrap();

        let mut c = [0u8; 8];
        let mut c = GenericArray::from_mut_slice(&mut c);
        des.encrypt_block_b2b(&p_arr, c);
        c.to_vec()
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn decrypt_basic() {
            let ciphertext = b"\x53\x9B\x33\x3B\x39\x70\x6D\x14\x90\x28\xCF\xE1\xD9\xD4\xA4\x07";
            let key = b"\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01";
            let plaintext = decrypt_cipher(ciphertext, key);

            assert_eq!(
                ciphertext,
                encrypt(Cipher::aes_256_cbc(), key, None, &*plaintext).unwrap().as_slice()
            );
        }

        #[test]
        fn encrypt_basic() {
            let plaintext = b"\x29\x6C\x93\xFD\xF4\x99\xAA\xEB\x41\x94\xBA\xBC\x2E\x63\x56\x1D";
            let key = b"\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01";
            let ciphertext = encrypt_plaintext(plaintext, key);

            assert_eq!(
                plaintext,
                decrypt(Cipher::aes_256_cbc(), key, None,&*ciphertext).unwrap().as_slice()
            );
        }

        #[test]
        fn des_complementation() {
            // encrypting the complement of the plaintext with the complement of the key
            // should yield the complement of the encryption of plaintext with the key
            let plaintext = "12345678".as_bytes().to_vec();
            let key = "87654321".as_bytes().to_vec();

            let plaintext_complement = plaintext.iter().cloned().map(|b| !b).collect();
            let key_complement = key.iter().cloned().map(|b| !b).collect();

            let ciphertext = des(key, plaintext);
            let ciphertext_from_complements = des(key_complement, plaintext_complement);

            let ciphertext_complement: Vec<u8> = ciphertext.into_iter().map(|b| !b).collect();

            assert_eq!(
                ciphertext_complement,
                ciphertext_from_complements
            );
        }
    }
}

mod ch4 {
    use des::cipher::{BlockEncrypt, KeyInit};
    use des::cipher::generic_array::GenericArray;
    use openssl::symm::{encrypt, decrypt, Cipher, Mode, Crypter};
    use des::Des;
    use generic_array::typenum::consts::{U8, U16, U256};

    pub fn decrypt_aes_256_random_iv(c: &[u8], key: &[u8]) -> Vec<u8> {

        println!("decrypting {:?} (len {:?})", c, c.len());
        // random iv is included at the beginning of c
        let iv = &c[0..16];
        println!("IV (len {:?}): {:?}", iv.len(), iv);
        let cipher = &c[16..];
        println!("cipher (len {:?}): {:?}", cipher.len(), cipher);
        decrypt(Cipher::aes_256_cbc(), &*key, Some(&iv), &cipher).unwrap()
    }

    pub fn pkcs_7_padding(m: &[u8]) -> Vec<u8> {
        // if length < 255, pad the message with 255-m
        let unpadded_length: u8 = 255 - m.len() as u8;
        let mut padded_m = Vec::with_capacity(255);
        // clone existing m
        padded_m.extend_from_slice(m);
        for i in 1..unpadded_length {
            padded_m.push(unpadded_length);
        }
        padded_m
    }

    pub fn pkcs_7_validate_padding(m: &[u8]) -> bool {

        let padding_length: Vec<&u8> = m.iter().rev().take(1).collect();
        let padding_length: u8 = **padding_length.get(0).unwrap();

        let mut message = Vec::with_capacity(255);
        message.extend_from_slice(m);

        let mut valid = true;
        for i in padding_length..254 {
            if message.get(i as usize) != Some(&padding_length) {
                valid = false;
            }
        }
        valid
    }

    #[cfg(test)]
    mod tests {
        use openssl::symm::{Cipher, decrypt};
        use crate::ch4::{decrypt_aes_256_random_iv, pkcs_7_padding, pkcs_7_validate_padding};

        #[test]
        fn test_aes_256_random_iv() {
            let key = b"\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01";
            let cipher = b"\x87\xF3\x48\xFF\x79\xB8\x11\xAF\x38\x57\xD6\x71\x8E\x5F\x0F\x91\x7C\x3D\x26\xF7\x73\x77\x63\x5A\x5E\x43\xE9\xB5\xCC\x5D\x05\x92\x6E\x26\xFF\xC5\x22\x0D\xC7\xD4\x05\xF1\x70\x86\x70\xE6\xE0\x17";

            let plaintext = decrypt_aes_256_random_iv(cipher, key);
        }

        #[test]
        fn test_pkcs_7_padding() {
            let m = b"\x29\x6C\x93\xFD\xF4\x99\xAA\xEB\x41\x94\xBA\xBC\x2E\x63\x56\x1D";
            let padded_m = pkcs_7_padding(m);
            println!("{:?}", m);
            println!("{:?}", padded_m);
        }

        #[test]
        fn test_validate_pkcs_7_padding() {
            let m = b"\x29\x6C\x93\xFD\xF4\x99\xAA\xEB\x41\x94\xBA\xBC\x2E\x63\x56\x1D";
            let padded_m = pkcs_7_padding(m);

            assert!(pkcs_7_validate_padding(padded_m.as_slice()));
        }
    }
}
