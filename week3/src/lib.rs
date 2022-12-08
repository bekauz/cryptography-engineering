mod ch3 {
    use sha2::{Sha256, Sha512, Digest};
    use hex_literal::hex;
    use std::collections::HashSet;

    pub fn sha_512_n(m: &[u8], n: usize) -> Vec<u8> {
        let mut hasher = Sha512::new();
        hasher.update(m);
        let hash = hasher.finalize();
        let result = hash[0..n].to_vec();
        result
    }

    pub fn birthday_attack_sha_512_n(input: Vec<u8>, n: usize) {

        let mut found = false;
        while !found {
            // let data = ...
            // let sha_512_n_hash = sha_512_n(data.as_slice(), n);
            // if input == sha_512_n_hash {
            //     found = true;
            //     println!("COLLISION WITH {:?}", data);
            // }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn find_sha_512_n() {
            let bytes = b"hello hello";
            let n = 8;
            println!("{:?}", sha_512_n(bytes, n));

        }

        #[test]
        fn bday_attack_sha_512_n() {
            let bytes = b"hello hello";
            let n = 8;
            let sha_n_bytes = sha_512_n(bytes, n);

            birthday_attack_sha_512_n(sha_n_bytes, n);
        }
    }
}
