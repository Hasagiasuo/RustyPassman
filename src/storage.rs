use super::crypto;
use super::entry::PasswordEntry;
use std::io::{Read, Write};

pub struct Vault {
    pub path: String,
    pub nonce: Vec<u8>,
    pub entries: Vec<PasswordEntry>,
}

impl Vault {
    pub fn upload() -> Self {
        let path_to_file = std::env::var("path").expect("Cannot get var path from .env");
        let nonce = crypto::get_nonce();
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .open(path_to_file.clone())
            .expect("Cannot open data file");
        let mut data_from_file = "".to_string();
        file.read_to_string(&mut data_from_file)
            .expect("Cannot read from data file");
        let lines: Vec<String> = data_from_file.split('\n').map(|e| e.to_string()).collect();
        let mut entries = Vec::<PasswordEntry>::with_capacity(lines.len());
        for line in lines {
            let tmp: Vec<String> = line.split(':').map(|e| e.to_string()).collect();
            if tmp.len() < 3 {
                continue;
            }
            let password = crypto::decode_password(tmp[2].clone(), nonce.clone());
            let pass_str = String::from_utf8(password).expect("Cannot parse string from bytes");
            entries.push(PasswordEntry {
                password: pass_str,
                username: tmp[1].clone(),
                service: tmp[0].clone(),
            });
        }
        Self {
            entries,
            nonce,
            path: path_to_file,
        }
    }
    pub fn update(&self) {
        let mut value_to_write = "".to_string();
        for passetr in &self.entries {
            let encrypted_password =
                crypto::encode_password(passetr.password.as_str(), self.nonce.clone());
            value_to_write.push_str(&format!(
                "{}:{}:{}\n",
                passetr.service.clone(),
                passetr.username.clone(),
                encrypted_password
            ));
        }
        std::fs::write(self.path.as_str(), value_to_write).expect("Cannot write in data file");
    }
    pub fn add_entry(&mut self, service: &str, username: &str, password: &str) {
        self.entries.push(PasswordEntry {
            password: password.to_string(),
            username: username.to_string(),
            service: service.to_string(),
        });
    }
    pub fn get_entry(&self, service: &str) -> Option<PasswordEntry> {
        if let Some(index) = self.entries.iter().position(|e| (*e).service == service) {
            return Some(self.entries[index].clone());
        }
        None
    }
    pub fn delete_entry(&mut self, service: &str) {
        if let Some(index) = self
            .entries
            .iter()
            .position(|e| (*e).service.as_str() == service)
        {
            self.entries.swap_remove(index);
        }
    }
}
