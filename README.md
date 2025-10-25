# RustyPassman — Password Manager for Services

**RustyPassman** is a command-line application written in **Rust** that securely stores user credentials (usernames and passwords for various services).
The project uses password hashing for user identification and AES encryption to protect stored service passwords.

---

## Overview

When launched, the program initializes configuration files and checks whether the user is authenticated.
To access or modify stored passwords, the user must first authenticate with their master password.
The user's password is never stored in plain text — it is hashed and verified upon login.
Service passwords are encrypted using AES with a 256-bit key.

---

## Commands

| Command    | Format                                     | Description                                                      |
| ---------- | ------------------------------------------ | ---------------------------------------------------------------- |
| **auth**   | `auth [password]`                          | Registers or authenticates a user using the given password       |
| **add**    | `add [service_name] [username] [password]` | Adds a new service with its login and password                   |
| **del**    | `del [service_name]`                       | Deletes a service entry                                          |
| **get**    | `get [service_name]`                       | Displays stored credentials for a service (after authentication) |
| **list**   | `list`                                     | Lists all stored services                                        |
| **change** | `change [old_password] [new_password]`     | Changes the user's master password                               |

---

## Security

- All user and service passwords are stored only in encrypted form.
- Each session generates a unique `nonce` to prevent replay attacks.
- Authentication uses a hashed password — even if files are compromised, the original password cannot be recovered.

---

## License

This project is distributed under the MIT License.
