use aes_gcm::{Aes256Gcm, KeyInit};
use argon2::Argon2;

const ARGON_SALT: &str = "shiny-donut";

/// Uses Argon2 as a key derivation function to derive a 258-bit AES key from a password
pub fn generate_aes_key(password: &str) -> Aes256Gcm {
    let mut out = [0u8; 32];
    Argon2::default()
        .hash_password_into(password.as_bytes(), ARGON_SALT.as_bytes(), &mut out)
        .unwrap();

    Aes256Gcm::new_from_slice(&out).unwrap()
}
