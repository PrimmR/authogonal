// Handles interface with reading and writing keys to encrypted files

use std::fs::File;
use std::path::Path;

pub const KEYPATH: &str = "keys";
pub const SETTINGSPATH: &str = "settings.json";

pub mod keys {
    use super::*;
    use crate::key::Key;
    use encrypt::{self, EncryptionKey};

    // Fails if key with name already exists
    pub fn add(key: &Key, e_key: &EncryptionKey) -> Result<(), String> {
        key.validate()?;
        let mut load = load(e_key);

        // Validation
        if let None = load.iter_mut().find(|k| *k.name == key.name) {
            load.push(key.clone());
            save(&load, e_key);
            Ok(())
        } else {
            Err(String::from("A key with that name already exists"))
        }
    }

    // Removes key with name
    pub fn remove(key_name: &String, e_key: &EncryptionKey) {
        let mut load = load(e_key);
        load.remove(
            load.iter()
                .position(|k| &k.name == key_name)
                .expect("Key not found"),
        );
        save(&load, e_key);
    }

    fn save(keys: &Vec<Key>, e_key: &EncryptionKey) {
        let path = Path::new(KEYPATH);
        let message = serde_json::to_string_pretty(&keys).unwrap();
        encrypt::save(path, e_key, message).unwrap()
    }

    pub fn load(e_key: &EncryptionKey) -> Vec<Key> {
        let path = Path::new(KEYPATH);
        if let Ok(m) = encrypt::load(path, e_key) {
            if let Ok(v) = serde_json::from_str(&m) {
                return v;
            }
        }

        Vec::new()
    }

    pub fn save_increment(key: &Key, e_key: &EncryptionKey) {
        let mut keys = load(e_key);
        if let Some(k) = keys.iter_mut().find(|k| *k == key) {
            (*k).options.method.increment_counter();
            save(&keys, e_key)
        }
    }

    pub fn delete_all(e_key: &EncryptionKey) {
        save(&Vec::new(), e_key)
    }
}

pub mod options {
    use super::*;
    use crate::ui::main::AppOptions;

    pub fn save(options: &AppOptions) {
        let path = Path::new(SETTINGSPATH);
        let file = File::create(path).unwrap();
        serde_json::to_writer_pretty(file, &options).unwrap();
    }

    pub fn load() -> AppOptions {
        if let Ok(f) = File::open(SETTINGSPATH) {
            if let Ok(v) = serde_json::from_reader(f) {
                return v;
            }
        }
        save(&Default::default());
        Default::default()
    }
}
