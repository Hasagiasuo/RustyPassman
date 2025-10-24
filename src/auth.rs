use base64::{decode, encode};

use super::crypto::{compare_password, hashing_password};
use std::{
    fs::OpenOptions,
    io::{Read, Write},
};

fn read_password() -> String {
    let password_path = std::env::var("password").expect("Cannot get password path");
    let mut passw_file = OpenOptions::new()
        .create(true)
        .write(true)
        .read(true)
        .open(password_path)
        .expect("Cannot open file with password");
    let mut result = "".to_string();
    passw_file
        .read_to_string(&mut result)
        .expect("Cannot read password from file");
    String::from_utf8(decode(result).expect("Cannot decode password"))
        .expect("Cannot decode password to string")
}

fn write_password(password: &str) {
    let password_path = std::env::var("password").expect("Cannot get password path");
    let mut file = OpenOptions::new()
        .create(true)
        .write(true)
        .read(true)
        .open(&password_path)
        .expect("Cannot create open option with parameters");
    let hashed_password = hashing_password(password);
    let password_64 = encode(hashed_password);
    file.write(password_64.as_bytes())
        .expect("Cannot write hash password in file");
}

fn compare_passw(target: &str) -> bool {
    let old_password = read_password();
    if compare_password(target, &old_password) {
        return true;
    }
    false
}

pub fn login() -> bool {
    let entered = rpassword::prompt_password("Password: ").expect("Cannot get password");
    if compare_passw(entered.trim()) {
        return true;
    }
    println!("Password incorrect");
    false
}

pub fn is_authed() -> bool {
    let password = read_password();
    if password.len() > 0 {
        return true;
    }
    false
}

pub fn signup(password: &str) {
    write_password(password);
}

pub fn change_password(entryed_password: &str, new_password: &str) -> bool {
    if compare_passw(entryed_password) {
        write_password(new_password);
        return true;
    }
    println!("Password uncorrect!");
    false
}
