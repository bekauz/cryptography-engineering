mod ch5 {
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

    pub fn find_sha_512_16_message_attempts(hash_hex: &[u8; 2], offset: usize) -> usize {
        let mut i = offset;
        loop {
            let hash = sha_512_n(&i.to_be_bytes(), 16);
            if hash == hash_hex.to_vec() {
                println!("collision with msg: {:?} @ i:{:?}", &i.to_be_bytes(), i);
                break;
            }
            i += 1;
        }
        i - offset
    }

    pub fn average_sha_512_16_attempts(hash_hex: &[u8; 2]) -> usize {
        let offsets: Vec<usize> = vec![1597, 28657, 514229, 433494437, 2971215073];
        let total_ops: usize = offsets.iter()
            .map(|offset| find_sha_512_16_message_attempts(hash_hex, offset.clone()))
            .sum();
        total_ops / offsets.len()
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

        #[test]
        fn find_message_by_hash() {
            // hex value to find
            let s: [u8; 2] = [0x3D, 0x4B];
            let avg = average_sha_512_16_attempts(&s);
            println!("average attempts: {:?}", avg);
        }
    }
}
