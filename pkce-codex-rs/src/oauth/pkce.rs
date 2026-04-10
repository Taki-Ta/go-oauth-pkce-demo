use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use rand::random;
use sha2::{Digest, Sha256};

pub fn random_string(size: usize) -> String {
    let buf: Vec<u8> = (0..size).map(|_| random::<u8>()).collect();
    URL_SAFE_NO_PAD.encode(buf)
}

pub fn new_state() -> String {
    random_string(24)
}

pub fn new_pkce() -> (String, String) {
    let verifier = random_string(32);
    let challenge = pkce_challenge(&verifier);
    (verifier, challenge)
}

pub fn pkce_challenge(verifier: &str) -> String {
    let digest = Sha256::digest(verifier.as_bytes());
    URL_SAFE_NO_PAD.encode(digest)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn random_string_changes_between_calls() {
        let s1 = random_string(32);
        let s2 = random_string(32);

        assert_eq!(s1.len(), 43);
        assert_eq!(s2.len(), 43);
        assert_ne!(s1, s2);
    }

    #[test]
    fn state_uses_expected_entropy() {
        assert_eq!(new_state().len(), 32);
    }

    #[test]
    fn pkce_pair_is_consistent() {
        let (verifier, challenge) = new_pkce();

        assert_eq!(verifier.len(), 43);
        assert_eq!(challenge, pkce_challenge(&verifier));
    }
}
