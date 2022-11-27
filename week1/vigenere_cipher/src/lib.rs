fn get_keystream(m: &str, key: &str) -> String {
    let mut keystream = key.repeat(m.len() / key.len());
    let excess = key.get(0..(m.len() % key.len())).unwrap();
    keystream.push_str(excess);
    keystream
}

pub fn vigenere_encrypt(m: &str, key: &str) -> String {

    let keystream  = get_keystream(m, key);
    let keystream_bytes = keystream.as_bytes();
    let m_bytes = m.as_bytes();

    let mut ciphertext: String = "".to_string();
    for i in 0..m.len() {
        // 'a' in ASCII = 97, 'z' = 122, 26 chars
        // - 2 * 97 to shift both key and msg character left
        // % 26 to make sure no non-ascii ciphers
        let cyper_ascii_code = (keystream_bytes[i] + m_bytes[i] - 2 * 97) % 26;
        ciphertext.push((cyper_ascii_code + 97) as char);
    }

    return ciphertext;
}

pub fn vigenere_decrypt(ciphertext: &str, key: &str) -> String {

    let keystream  = get_keystream(ciphertext, key);
    let keystream_bytes = keystream.as_bytes();
    let c_bytes = ciphertext.as_bytes();

    let mut message: String = "".to_string();
    for i in 0..ciphertext.len() {
        let c_index = c_bytes[i] - 97;
        let k_index = keystream_bytes[i] - 97;

        let abs_diff = c_index.abs_diff(k_index);
        let diff = if c_index < k_index {
            // if k_index is bigger, avoid overflow
            26 - abs_diff
        } else {
            abs_diff
        };

        let decrypted_char_index = 97 + (diff);
        message.push(decrypted_char_index as char);
    }

    message
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_encrypt() {
        let plaintext = "attackatdawn";
        let key = "lemon";

        let ciphertext = vigenere_encrypt(plaintext, key);

        assert_eq!(ciphertext, "lxfopvefrnhr");
    }

    #[test]
    fn basic_decrypt() {
        let ciphertext = "lxfopvefrnhr";
        let key = "lemon";

        let message = vigenere_decrypt(ciphertext, key);

        assert_eq!(message, "attackatdawn");
    }
}
