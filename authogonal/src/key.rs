// Structs used for the whole library

use serde::{Deserialize, Serialize};

/// Stores all data relevant to creating a OTP code
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)] // Doesn't derive Copy, as contains Strings
pub struct Key {
    pub secret: String,
    pub name: String,
    pub options: CodeOptions,
    pub time: i64,
}

impl Key {
    /// Constructor for a [Key]
    /// The time attribute will always be initialised as the current time
    pub fn new(secret: String, name: String, options: CodeOptions) -> Self {
        let time = chrono::Utc::now().timestamp();
        Self {
            secret,
            name,
            options,
            time,
        }
    }

    /// Validates that the key can be used to create valid OTP codes
    /// On error, returns an Err variant containing an error message as a string
    pub fn validate(&self) -> Result<(), String> {
        // Validate name not empty
        if self.name.len() == 0 {
            return Err(String::from("Name cannot be empty"));
        }

        let secret = &self.secret;

        // Validate secret at least 2 characters
        if secret.len() <= 1 {
            return Err(String::from("Invalid secret length"));
        }

        let secret = secret.to_ascii_uppercase();
        // ? operator propegates the error through this function
        Self::validate_char(&secret)?;
        Self::validate_len(&secret)?;

        Ok(())
    }

    /// Validate that chars in Base-32 set
    fn validate_char(secret: &String) -> Result<(), String> {
        // All characters in base 32 character set
        let base32chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

        // Iterates through all characters, if one isn't in the &str above, the secret must be invalid
        if secret.chars().any(|c| !base32chars.contains(c)) {
            return Err(String::from("Invalid character in secret"));
        }
        Ok(())
    }

    // Validate any overflow when converting to b32 just contains 0s
    fn validate_len(secret: &String) -> Result<(), String> {
        // All characters in base 32 character set
        let base32chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

        // Reverse, so calling next will return final item, in order to take only the last 2 chars of the secret
        let mut backwards = secret.chars().rev();
        // Unwrap can be used safely, as validation that secret is at least 2 chars has already been performed
        let last = backwards.next().unwrap();
        let penultimate = backwards.next().unwrap();
        // Creates a String representation of the final 10 bits of the secret when converted to base 32
        // The find method will return the index location of a character, which is the base 32 representation, as base32chars variable stores characters in index order
        let ending_binary = format!(
            "{:05b}{:05b}",
            base32chars.find(penultimate).unwrap(),
            base32chars.find(last).unwrap()
        );

        // The right index to start the check from
        let bit_len = secret.len() * 5;
        // The number of 'trailing bits' (bits after the final full byte)
        let rem_i = bit_len - bit_len / 8 * 8;

        let bits: Vec<char> = ending_binary.chars().collect();
        // Len is always 10, so 10 - rem_i gives left index
        // If any of the 'trailing bits' are a 1, the secret is invalid
        if bits[10 - rem_i..].iter().any(|b| *b == '1') {
            return Err(String::from("Invalid secret"));
        }
        Ok(())
    }

    // This is a method to allow for modification of the struct within Rust's concurrency checker
    /// Increments the contained HOTP counter by 1
    /// This additionally saves the change to file
    pub fn increment(&mut self, e_key: &encrypt::EncryptionKey) {
        crate::file::keys::save_increment(&self, e_key);
        self.options.method.increment_counter();
    }
}

impl std::default::Default for Key {
    fn default() -> Self {
        Self {
            secret: String::new(),
            name: String::new(),
            options: CodeOptions::default(),
            time: chrono::Utc::now().timestamp(),
        }
    }
}

// As Serialize & Deserialize cannot be implemented on a type outside this scope, a duplicate enum is used here to create a link to HashFn, allowing it to be used with serde
#[derive(Serialize, Deserialize)]
#[serde(remote = "hash::HashFn")]
enum HashFnDef {
    SHA1,
    SHA256,
    SHA512,
}

/// Stores several attributes that apply to [Key]
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct CodeOptions {
    pub method: crate::otp::OTPMethod,
    #[serde(with = "HashFnDef")]
    // Defines the link with HashFnDef in order to implement serde traits on hash::HashFn
    pub hash: hash::HashFn,
    pub length: u8,
    pub interval: u32,
}

impl CodeOptions {
    /// Constructor for [CodeOptions] that requires all attributes as parameters
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

    /// Constructor for [CodeOptions] that allows for the default value to be used if None is passed in to a parameter
    pub fn new_or_default(
        method: Option<crate::otp::OTPMethod>,
        hash: Option<hash::HashFn>,
        length: Option<u8>,
        interval: Option<u32>,
    ) -> Self {
        // unwrap_or will return the specified default if the value is None
        Self::new(
            method.unwrap_or(crate::otp::OTPMethod::TOTP),
            hash.unwrap_or(hash::HashFn::SHA1),
            length.unwrap_or(6),
            interval.unwrap_or(30),
        )
    }
}

impl std::default::Default for CodeOptions {
    // Default function calls new_or_default with all arguments as None, meaning all are the default
    fn default() -> Self {
        Self::new_or_default(None, None, None, None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_validate_empty() {
        Key::new(String::new(), String::new(), Default::default())
            .validate()
            .unwrap_err();
    }

    #[test]
    fn secret_validate_non_empty() {
        Key::new(String::from("7A"), String::from("test"), Default::default())
            .validate()
            .unwrap();
    }

    #[test]
    fn secret_validate_invalid_char() {
        Key::validate_char(&String::from("2082")).unwrap_err();
    }

    #[test]
    fn secret_validate_valid_char() {
        Key::validate_char(&String::from("MANONAM")).unwrap();
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
