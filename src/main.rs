use crate::storage::Vault;
use dotenv::dotenv;
use std::env;

mod auth;
mod crypto;
mod entry;
mod storage;

fn main() {
    dotenv().expect("Cannot load .env space");
    crypto::gen_nonce();
    let mut vault = Vault::upload();
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        println!(
            "Use format: {} [cmd] params\n\tCommands: add, del, get\n\t~ add service_name username password\n\t~ del service_name\n\t~ get service_name",
            args[0].clone()
        );
        return;
    }
    match args[1].as_str() {
        "add" => {
            vault.add_entry(args[2].as_str(), args[3].as_str(), args[4].as_str());
        }
        "del" => {
            vault.delete_entry(args[2].as_str());
        }
        "get" => {
            if let Some(entr) = vault.get_entry(args[2].as_str()) {
                entr.draw();
            } else {
                println!("Element {} not found", args[2].as_str());
            }
        }
        _ => {
            println!(
                "Use format: {} [cmd] params\n\tCommands: add, del, get\n\t~ add service_name username password\n\t~ del service_name\n\t~ get service_name",
                args[0].clone()
            );
            return;
        }
    }
    vault.update();
}
