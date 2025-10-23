use super::crypto::{hashing_password, compare_password};
use std::{
    fs::{OpenOptions, read_to_string},
    io::Write,
};

fn write_password(password: &str) {
    let password_path = std::env::var("pass_path").expect("Cannot get password path");
    let mut file = OpenOptions::new()
        .create(true)
        .write(true)
        .read(true)
        .open(&password_path)
        .expect("Cannot create open option with parameters");
    let hashed_password = hashing_password(password);
    file.write(hashed_password.as_bytes())
        .expect("Cannot write hash password in .env file");
}

pub fn read_password() -> String {
    let password_path = std::env::var("pass_path").expect("Cannot get password path");
    read_to_string(&password_path).expect("Cannot read from password file")
}

pub fn signup(password: &str) {
    write_password(password);
}

pub fn change_password(entryed_password: &str, new_password: &str) -> bool {
    let old_password = std::env::var("pass").expect("Cannot get password from .env");
    if compare_password(entryed_password, &old_password) {
        write_password(new_password);
        return true;
    } 
    println!("Password uncorrect!");
    false
}
