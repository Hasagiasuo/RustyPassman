use aes_gcm::{AeadCore, Aes256Gcm, KeyInit, aead::Aead};
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier, password_hash::SaltString};
use base64::{decode, encode};
use rand_core::{OsRng, RngCore};
use std::fs::{OpenOptions, read_to_string};
use std::io::{Read, Write};

fn get_salt() -> SaltString {
    let path_to_salt = std::env::var("salt").expect("Cannot get salt path");
    let salt: SaltString;
    if std::fs::exists(&path_to_salt).expect("Cannot get information about file existsing") {
        let salt_data = read_to_string(path_to_salt).expect("Cannot read salt from file");
        salt = SaltString::from_b64(salt_data.as_str())
            .expect("Cannot parse SaltString from string in salt file");
    } else {
        salt = SaltString::generate(OsRng);
        let mut file = OpenOptions::new()
            .create(true)
            .write(true)
            .read(true)
            .open(&path_to_salt)
            .expect("Cannot open file with sault");
        file.write(salt.to_string().as_bytes())
            .expect("Cannot write sault in file");
    }
    salt
}

pub fn hashing_password(password: &str) -> String {
    let salt = get_salt();
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
    let key_path = std::env::var("key").expect("Cannot get path to key");
    let mut file = OpenOptions::new()
        .read(true)
        .open(key_path)
        .expect("Cannot open key file");
    let mut key = Vec::new();
    file.read_to_end(&mut key).expect("Cannot read key file");
    if key.len() != 32 {
        panic!(
            "Key length is invalid: expected 32 bytes, got {}",
            key.len()
        );
    }
    key
}

pub fn get_nonce() -> Vec<u8> {
    let nonce_path = std::env::var("nonce").expect("Cannot get path to nonce");
    let data = read_to_string(nonce_path).expect("Cannot read nonce from file");
    decode(data).expect("Cannot decode nonce from file")
}

pub fn gen_key() {
    if !std::fs::exists(".config").expect("Cannot get information about exists folder .config") {
        std::fs::create_dir(".config").expect("Cannot create directory");
    }
    let mut buffer = [0u8; 32];
    OsRng.fill_bytes(&mut buffer);
    let key_path = std::env::var("key").expect("Cannot get path to key");
    if std::fs::exists(&key_path).expect("Cannot get information about exists file key") {
        return;
    }
    let mut file = OpenOptions::new()
        .create(true)
        .write(true)
        .read(true)
        .open(key_path)
        .expect("Cannot open key file");
    file.write(&buffer).expect("Cannot write file");
}

pub fn gen_nonce() {
    let nonce_path = std::env::var("nonce").expect("Cannot get path to nonce");
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng).to_vec();
    let mut file = OpenOptions::new()
        .create(true)
        .write(true)
        .read(true)
        .open(nonce_path)
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
