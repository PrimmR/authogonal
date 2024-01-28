// Crate that will save data encrypted using a password

use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Key,
};

use hash::Hashable;
use std::path::Path;
use std::{
    fs::File,
    io::{Read, Write},
};

// Password hash stored separately for verification

pub fn save(
    path: &Path,
    key: &EncryptionKey,
    message: String,
) -> Result<(), Box<dyn std::error::Error>> {
    let key = Key::<Aes256Gcm>::from_slice(key);
    let cipher = Aes256Gcm::new(&key);
    // 96-bits, unique per message, stored plain next to encryption
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    // Encrypts using AES256GCM
    let ciphertext = match cipher.encrypt(&nonce, message.as_bytes().as_ref()) {
        Ok(v) => v,
        Err(_) => return Err(Box::new(Error::WriteError)),
    };

    // Writes nonce to file then cipher
    let mut file = File::create(path)?;
    file.write_all(&nonce)?;
    file.write_all(&ciphertext)?;

    Ok(())
}

pub fn load(path: &Path, key: &EncryptionKey) -> Result<String, Box<dyn std::error::Error>> {
    let key = Key::<Aes256Gcm>::from_slice(key);
    let cipher = Aes256Gcm::new(&key);

    if let Ok(mut f) = File::open(path) {
        // Read exactly 12 bytes to get the nonce
        let mut nonce = [0; 12];
        f.read_exact(&mut nonce)?;

        // Read the rest for the cipher
        let mut ciphertext = Vec::new();
        f.read_to_end(&mut ciphertext)?;

        // Decrypt and return
        // Validation done by crate
        let plaintext = match cipher.decrypt(&(nonce).into(), ciphertext.as_ref()) {
            Ok(v) => v,
            Err(_) => return Err(Box::new(Error::ReadError)),
        };

        Ok(String::from_utf8(plaintext)?)
    } else {
        File::create(path).unwrap();
        Ok(String::new())
    }
}

// Type alias for improved readability
pub type EncryptionKey = [u8; 32];

// Generates numerical key from string using hash algorithm
pub fn password_to_key(password: &impl Hashable) -> EncryptionKey {
    // Note that you can get byte array from slice using the `TryInto` trait:
    hash::HashFn::SHA256
        .digest(&password.to_message())
        .try_into()
        .unwrap()
}

#[derive(Debug)]
pub enum Error {
    ReadError, // ReadError signifies incorrect password
    WriteError,
}

impl std::error::Error for Error {}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn integrity() {
        let path = Path::new("test_integrity");
        let plaintext = String::from("manonam");
        let password = password_to_key(&String::from("2082"));
        save(path, &password, plaintext.clone()).unwrap();
        assert_eq!(load(path, &password).unwrap(), plaintext);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    #[should_panic]
    fn empty() {
        let path = Path::new("test_empty");
        let plaintext = String::from("");
        save(
            path,
            &password_to_key(&String::from("a")),
            plaintext.clone(),
        )
        .unwrap();
        let load = load(path, &password_to_key(&String::from("b")));
        let _ = std::fs::remove_file(path);
        load.unwrap();
    }
}
