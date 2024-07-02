// Handles interface with reading and writing keys to encrypted files

use std::fs::File;
use std::path::Path;

/// Filename for key file
pub const KEYPATH: &str = "keys";
/// Filename for settings file
pub const SETTINGSPATH: &str = "settings.json";

pub fn get_dir() -> std::path::PathBuf {
    let exe_path = std::env::current_exe().unwrap();
    exe_path.parent().unwrap().to_path_buf()
}

/// Handles operations with the key file
/// Data stored in the key file is encrypted, so all functions require an [EncryptionKey]
pub mod keys {
    use super::*;
    use crate::key::Key;
    use encrypt::EncryptionKey;

    /// Appends a key to the key file, returning an error String if key is invalid, or a key with the same name attribute already exists
    pub fn add(key: &Key, e_key: &EncryptionKey) -> Result<(), String> {
        // Check that key to add is valid
        key.validate()?;

        // Load already existing keys to check for name matches, and to allow append to the end using vector methods
        let mut load = load(e_key);

        // Validation, returning an error if key with name already exists (as needs to be unique to index into HashMap)
        // Operation is performed here as all keys are accessible to be checked
        if let None = load.iter().find(|k| *k.name == key.name) {
            // Add to end of vector and save again
            load.push(key.clone());
            save(&load, e_key);
            Ok(())
        } else {
            Err(String::from("A key with that name already exists"))
        }
    }

    /// Removes key with a given name from the key file
    pub fn remove(key_name: &String, e_key: &EncryptionKey) {
        let mut load = load(e_key);
        // Removes specified key from loaded list and saves it back to file
        load.remove(
            load.iter()
                .position(|k| &k.name == key_name)
                .expect("Key not found"), // Panics if key name invalid
        );
        save(&load, e_key);
    }

    /// Save function to write a vec of keys to file
    fn save(keys: &Vec<Key>, e_key: &EncryptionKey) {
        // Create path from key path constant
        let path = get_dir().join(Path::new(KEYPATH));
        // Convert keys to JSON format
        let message = serde_json::to_string(&keys).unwrap();
        // Save using encrypt external module
        encrypt::save(&path, e_key, message).unwrap()
    }

    /// Load data from key file
    pub fn load(e_key: &EncryptionKey) -> Vec<Key> {
        let path = get_dir().join(Path::new(KEYPATH));
        if let Ok(m) = encrypt::load(&path, e_key) {
            if let Ok(v) = serde_json::from_str(&m) {
                // If decryption succeeds and data is valid JSON, return
                return v;
            }
        }

        // If couldn't retrieve data, return an empty vector
        Vec::new()
    }

    /// Increment a specified key's HOTP counter by 1 and save to key file
    pub fn save_increment(key: &Key, e_key: &EncryptionKey) {
        let mut keys = load(e_key);
        // Find key in file to increment
        if let Some(k) = keys.iter_mut().find(|k| *k == key) {
            // Deref and increment counter value, then save
            (*k).options.method.increment_counter();
            save(&keys, e_key)
        }
    }

    /// Replaces the current key file with an empty one
    pub fn new_file(e_key: &EncryptionKey) {
        // Writes an empty vec to the file, overwriting existing data
        save(&Vec::new(), e_key)
    }
}

/// Handles operations with the settings (options) file
/// Data is stored in plaintext JSON
pub mod options {
    use super::*;
    use crate::ui::main::AppOptions;

    /// Save [AppOptions] to settings file
    pub fn save(options: &AppOptions) {
        // Create path from settings path constant
        let path = get_dir().join(Path::new(SETTINGSPATH));
        // Create file in path location
        let file = File::create(path).unwrap();
        // Convert AppOptions to pretty JSON and write to file
        serde_json::to_writer_pretty(file, &options).unwrap();
    }

    /// Load [AppOptions] from settings file
    pub fn load() -> AppOptions {
        let path = get_dir().join(Path::new(SETTINGSPATH));

        if let Ok(f) = File::open(&path) {
            if let Ok(v) = serde_json::from_reader(f) {
                // If file could be read and contains valid JSON, return read data
                return v;
            }
        }
        // If data invalid, overwrite it with valid default settings, and return defaults
        save(&Default::default());
        Default::default()
    }
}
