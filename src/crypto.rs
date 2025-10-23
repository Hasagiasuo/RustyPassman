use aes_gcm::{AeadCore, Aes256Gcm, KeyInit, aead::Aead};
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier, password_hash::SaltString};
use base64::{decode, encode};
use rand_core::OsRng;
use std::fs::{OpenOptions, read_to_string};
use std::io::{Read, Write};

pub fn hashing_password(password: &str) -> String {
    let salt = SaltString::generate(OsRng);
    let argon = Argon2::default();

    argon
        .hash_password(password.as_bytes(), &salt)
        .expect("Cannot hash password")
        .to_string()
}

pub fn compare_password(current_password: &str, old_password: &str) -> bool {
    let argon = Argon2::default();
    let password_hash =
        PasswordHash::new(old_password).expect("Cannot create password hash from old password");
    argon
        .verify_password(current_password.as_bytes(), &password_hash)
        .is_ok()
}

pub fn read_key() -> Vec<u8> {
    let pass_path = std::env::var("pass_path").expect("Cannot get var about password path");
    read_to_string(pass_path.clone())
        .expect("Cannot read password")
        .trim()
        .as_bytes()
        .to_vec()
}

pub fn get_nonce() -> Vec<u8> {
    let data = read_to_string("./.config/nonce").expect("Cannot read nonce from file");
    decode(data).expect("Cannot decode nonce from file")
}

pub fn gen_nonce() {
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng).to_vec();
    let mut file = OpenOptions::new()
        .create(true)
        .write(true)
        .read(true)
        .open("./.config/nonce")
        .expect("Cannot open file nonce");
    let mut file_value = "".to_string();
    file.read_to_string(&mut file_value)
        .expect("Cannot read file nonce");
    if file_value.len() > 0 {
        return;
    }
    let nonce_64 = encode(nonce);
    file.write(nonce_64.as_bytes()).expect("Cannot write nonce");
}

pub fn encode_password(message: &str, nonce: Vec<u8>) -> String {
    let key = read_key();
    let cipher = Aes256Gcm::new(key.as_slice().into());
    let encoded_text = cipher
        .encrypt(nonce.as_slice().into(), message.as_bytes())
        .expect("Cannot encrypt password");
    encode(encoded_text)
}

pub fn decode_password(message64: String, nonce: Vec<u8>) -> Vec<u8> {
    let key = read_key();
    let cipher = Aes256Gcm::new(key.as_slice().into());
    let text = decode(message64).expect("Cannot decode message");
    let result = cipher
        .decrypt(nonce.as_slice().into(), text.as_ref())
        .expect("Cannot decrypt password");
    result
}
