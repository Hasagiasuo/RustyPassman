use crate::storage::Vault;
use dotenv::dotenv;
use std::env;

mod auth;
mod crypto;
mod entry;
mod storage;

fn main() {
    dotenv().expect("Cannot load .env space");
    crypto::gen_key();
    crypto::gen_nonce();
    let mut vault = Vault::upload();
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        println!(
            "Use format: {} [cmd] params\n\tCommands: add, del, get\n\t~ add [service_name] [username] [password]\n\t~ del [service_name]\n\t~ get [service_name]\n\t~ list\n\t~ auth [password]\n\t~ change [old_password] [new_password]",
            args[0].clone()
        );
        return;
    }
    if args[1].as_str() == "auth" {
        auth::signup(args[2].as_str());
        return;
    }
    if !auth::is_authed() {
        println!("Login first\n\t{} auth [password]", args[0].clone());
        return;
    }
    match args[1].as_str() {
        "list" => {
            if vault.entries.len() == 0 {
                println!("There is no service");
                return;
            }
            println!("All services:");
            for serv in &vault.entries {
                println!("\t> {}", serv.service);
            }
        }
        "change" => {
            if auth::change_password(args[2].as_str(), args[3].as_str()) {
                println!("Success changed password");
            } else {
                println!("Password not change");
            }
        }
        "add" => {
            vault.add_entry(args[2].as_str(), args[3].as_str(), args[4].as_str());
        }
        "del" => {
            vault.delete_entry(args[2].as_str());
        }
        "get" => {
            if !auth::login() {
                return;
            }
            if let Some(entr) = vault.get_entry(args[2].as_str()) {
                entr.draw();
            } else {
                println!("Element [{}] not found", args[2].as_str());
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
