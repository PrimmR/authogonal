// Structs used throughout the application

use serde::{Deserialize, Serialize};

// Structs used for the whole library
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Key {
    pub secret: String,
    pub name: String,
    pub options: CodeOptions,
    pub time: i64,
}

impl Key {
    pub fn new(secret: String, name: String, options: CodeOptions) -> Self {
        let time = chrono::Utc::now().timestamp();
        Self {
            secret,
            name,
            options,
            time,
        }
    }

    pub fn validate(&self) -> Result<(), String> {
        // Make sure name not empty
        if self.name.len() == 0 {
            return Err(String::from("Name cannot be empty"));
        }

        let secret = &self.secret;

        // Make sure secret at least 2 characters
        if secret.len() <= 1 {
            return Err(String::from("Invalid secret length"));
        }

        let secret = secret.to_ascii_uppercase();
        Self::validate_char(&secret)?;
        Self::validate_len(&secret)?;

        Ok(())
    }

    // Validate that chars in Base-32 set
    fn validate_char(secret: &String) -> Result<(), String> {
        let base32chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

        if secret.chars().any(|c| !base32chars.contains(c)) {
            return Err(String::from("Invalid character in secret"));
        }
        Ok(())
    }

    // Validate any overflow when converting to b32 just contains 0s
    fn validate_len(secret: &String) -> Result<(), String> {
        let base32chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

        let mut backwards = secret.chars().rev();
        let last = backwards.next().unwrap();
        let penultimate = backwards.next().unwrap();
        let ending_binary = format!(
            "{:05b}{:05b}",
            base32chars.find(penultimate).unwrap(),
            base32chars.find(last).unwrap()
        );

        // The right index to start the check from
        let bit_len = secret.len() * 5;
        let rem_i = bit_len - bit_len / 8 * 8;

        let bits: Vec<char> = ending_binary.chars().collect();
        // Len is always 10, so gives left index
        if bits[10 - rem_i..].iter().any(|b| *b == '1') {
            return Err(String::from("Invalid secret"));
        }
        Ok(())
    }

    pub fn increment(&mut self, e_key: &encrypt::EncryptionKey) {
        crate::file::keys::save_increment(&self, e_key);
        self.options.method.increment_counter();
    }
}

impl std::default::Default for Key {
    fn default() -> Self {
        Self {
            secret: String::from(""),
            name: String::from(""),
            options: CodeOptions::default(),
            time: chrono::Utc::now().timestamp(),
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(remote = "hash::HashFn")]
enum HashFnDef {
    SHA1,
    SHA256,
    SHA512,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct CodeOptions {
    pub method: crate::otp::OTPMethod,
    #[serde(with = "HashFnDef")]
    pub hash: hash::HashFn,
    pub length: u8,
    pub interval: u32,
}

impl CodeOptions {
    pub fn new(
        method: crate::otp::OTPMethod,
        hash: hash::HashFn,
        length: u8,
        interval: u32,
    ) -> Self {
        Self {
            method,
            hash,
            length,
            interval,
        }
    }

    pub fn new_or_default(
        method: Option<crate::otp::OTPMethod>,
        hash: Option<hash::HashFn>,
        length: Option<u8>,
        interval: Option<u32>,
    ) -> Self {
        Self::new(
            method.unwrap_or(crate::otp::OTPMethod::TOTP),
            hash.unwrap_or(hash::HashFn::SHA1),
            length.unwrap_or(6),
            interval.unwrap_or(30),
        )
    }
}

impl std::default::Default for CodeOptions {
    fn default() -> Self {
        Self::new_or_default(None, None, None, None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_validate_empty() {
        Key::new(String::from(""), String::new(), Default::default())
            .validate()
            .unwrap_err();
    }

    #[test]
    fn secret_validate_non_empty() {
        Key::new(String::from("7A"), String::new(), Default::default())
            .validate()
            .unwrap();
    }

    #[test]
    fn secret_validate_invalid_char() {
        Key::validate_char(&String::from("2082")).unwrap_err();
    }

    #[test]
    fn secret_validate_valid_char() {
        Key::validate_char(&String::from("manonam")).unwrap();
    }

    #[test]
    fn secret_validate_invalid_len() {
        // 00000000_1000000
        // ACA
        Key::validate_len(&String::from("ACA")).unwrap_err();
    }

    #[test]
    fn secret_validate_valid_len() {
        // 01111100_01010000_11000110_0
        // Primm
        Key::validate_len(&String::from("PRIMM")).unwrap();
    }

    #[test]
    fn secret_validate_exact_len() {
        // 10010001_11011101_01101000_10111001_11001100
        // Showroom
        Key::validate_len(&String::from("SHOWROOM")).unwrap();
    }
}
