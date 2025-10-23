#[derive(Clone)]
pub struct PasswordEntry {
    pub password: String,
    pub username: String,
    pub service: String,
}

impl PasswordEntry {
    pub fn new(service: &str, username: &str, password: &str) -> Self {
        Self {
            service: String::from(service),
            username: String::from(username),
            password: String::from(password),
        }
    }
    pub fn draw(&self) {
        println!(
            "-> {}:\n\t> {}\n\t> {}",
            self.service, self.username, self.password
        );
    }
}
