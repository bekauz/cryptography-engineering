extern crate core;

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
