#[derive(Clone)]
pub struct PasswordEntry {
    pub password: String,
    pub username: String,
    pub service: String,
}

impl PasswordEntry {
    pub fn draw(&self) {
        println!(
            "-> {}:\n\t> {}\n\t> {}",
            self.service, self.username, self.password
        );
    }
}
