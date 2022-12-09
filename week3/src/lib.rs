mod ch3 {
    use sha2::{Sha512, Digest};
    use std::collections::{HashMap};

    pub fn sha_512_n(m: &[u8], n: usize) -> Vec<u8> {
        let mut hasher = Sha512::new();
        hasher.update(m);
        let hash = hasher.finalize();
        let take_bytes: usize = n / 8;
        let result = hash.iter().take(take_bytes).copied();
        result.collect()
    }

    pub fn birthday_attack_sha_512_n(n: usize) {
        // map of hash value -> int
        let mut previous = HashMap::new();
        for i in 1usize .. 100_000 {
            let hash = sha_512_n(&i.to_be_bytes(), n);
            let resp = previous.insert(hash.clone(), i);
            match resp {
                None => {}
                Some(val) => {
                    println!("collision: {:?} and {:?} both map to {:?}",
                             i,
                             val,
                             &hash
                    );
                    break;
                }
            }
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
            let n = 24;
            birthday_attack_sha_512_n(n);
        }
    }
}
