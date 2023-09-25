extern crate chrono;
extern crate serde;
extern crate sha1;

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Key {
    pub key: String,
    pub name: String,
}

impl Key {
    pub fn new(key: String, name: String) -> Self {
        Self { key, name }
    }
}

mod hash {
    pub fn sha1(key: &[u8]) -> Vec<u8> {
        use sha1::{Digest, Sha1};

        let mut hasher = Sha1::new();
        hasher.update(key);
        let result = hasher.finalize();

        result[..].to_vec()
    }
}

pub mod hmac {
    use crate::hash;
    const IPAD: u8 = 0x36;
    const OPAD: u8 = 0x5c;

    pub fn generate(key: &[u8], message: &[u8]) -> Vec<u8> {
        let block_size = 64;
        // let output_size = 40;

        let block_sized_key = compute_block_sized_key(key, block_size);

        let input_key_pad: Vec<u8> = block_sized_key.iter().map(|x| x ^ IPAD).collect();
        let output_key_pad: Vec<u8> = block_sized_key.iter().map(|x| x ^ OPAD).collect();

        let digest: Vec<u8> = hash::sha1(&concat(input_key_pad, message.to_vec()));
        hash::sha1(&concat(output_key_pad, digest))
    }

    fn compute_block_sized_key(key: &[u8], block_size: usize) -> Vec<u8> {
        if key.len() > block_size {
            hash::sha1(&key)
        } else if key.len() < block_size {
            pad(key, block_size)
        } else {
            key[..].to_vec()
        }
    }

    fn pad(key: &[u8], block_size: usize) -> Vec<u8> {
        // Panics if too large
        let mut pad = key[..].to_vec();
        // Pads to right
        pad.resize(block_size, 0);
        // pad.splice(..0, std::iter::repeat(0).take(block_size - pad.len())); // Pads to left
        pad
    }

    fn concat(a: Vec<u8>, b: Vec<u8>) -> Vec<u8> {
        vec![a, b].concat()
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        extern crate hex;

        #[test]
        fn regular_hmac() {
            let mac = generate(b"key", b"Primm");
            assert_eq!(
                mac,
                hex::decode("cb32bca866c267d57a2143984bb7e3590095a1d7").unwrap()
            )
        }

        #[test]
        fn empty_hmac() {
            let mac = generate(b"", b"");
            assert_eq!(
                mac,
                hex::decode("fbdb1d1b18aa6c08324b7d64b71fb76370690e1d").unwrap()
            )
        }

        #[test]
        fn padding_key() {
            assert_eq!(pad(&[20, 82], 8), vec![20, 82, 0, 0, 0, 0, 0, 0]);
        }

        #[test]
        fn padding_key_shrink() {
            assert_eq!(pad(&[20, 82], 1), vec![20]);
        }
    }
}

mod totp {
    use std::convert::TryInto;
    use std::str;

    use chrono::Utc;
    use hmac;
    // use sha1::Sha1;

    fn truncate(mac: &Vec<u8>) -> u32 {
        // Truncation first takes the 4 least significant bits of the MAC and uses them as a byte offset i:
        let lsb = mac[mac.len() - 1] & 0b00001111;
        let extracted = extract31(mac, lsb.into());

        u32::from_be_bytes(extracted)
    }

    fn extract31(mac: &Vec<u8>, i: usize) -> [u8; 4] {
        let mut extract: [u8; 4] = mac[i..i + 4].try_into().unwrap();
        extract[0] &= 0x7F;
        extract
    }

    pub fn validate(string: &str, character: char) -> Result<(), char> {
        if !string.contains(character) {
            Err(character)
        } else {
            Ok(())
        }
    }

    fn to_b32(key: &str) -> Result<Vec<u8>, char> {
        let base32chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        let upper = key.to_ascii_uppercase();

        upper
            .chars()
            .map(|c| validate(base32chars, c))
            .collect::<Result<(), char>>()?;

        let i = upper.chars().fold(String::new(), |acc, x| {
            acc + format!("{:05b}", base32chars.find(x).unwrap()).as_str()
        });

        let bytes = i.into_bytes();

        Ok(bytes
            .chunks(8)
            .map(|x| {
                u8::from_str_radix(String::from_utf8(x.to_vec()).unwrap().as_str(), 2).unwrap()
            })
            .collect::<Vec<u8>>())
    }

    pub fn generate(key: &str) -> u32 {
        let b32key = to_b32(key).expect("Key contains invalid characters");

        let now = Utc::now();
        let timestep = now.timestamp() / 30;

        let mac = hmac::generate(&b32key[..], &timestep.to_be_bytes());

        let totp = truncate(&mac) % 10_u32.pow(6);

        totp
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn truncation() {
            let mac: Vec<_> = vec![
                239, 175, 55, 150, 38, 85, 24, 149, 68, 234, 249, 243, 110, 126, 48, 57, 73, 119,
                39, 232,
            ];
            assert_eq!(truncate(&mac), 1156250099);
        }

        #[test]
        fn extract_high_unset() {
            let mac: Vec<_> = vec![
                239, 175, 55, 150, 38, 85, 24, 149, 68, 234, 249, 243, 110, 126, 48, 57, 73, 119,
                39, 232,
            ];
            assert_eq!(extract31(&mac, 2), [55, 150, 38, 85]);
        }

        #[test]
        fn extract_high_set() {
            let mac: Vec<_> = vec![
                239, 175, 55, 150, 38, 85, 24, 149, 68, 234, 249, 243, 110, 126, 48, 57, 73, 119,
                39, 232,
            ];
            assert_eq!(extract31(&mac, 10), [121, 243, 110, 126]);
        }

        #[test]
        fn regular_to_b32() {
            let key = "Primm";
            let expect = vec![0x7c, 0x50, 0xc6, 0x00];
            assert_eq!(to_b32(key).unwrap(), expect)
        }

        #[test]
        fn empty_to_b32() {
            let expect: Vec<u8> = Vec::new();
            assert_eq!(to_b32("").unwrap(), expect);
        }

        #[test]
        fn invalid_to_b32() {
            assert_eq!(to_b32("&"), Err('&'));
        }
    }
}

pub mod display {
    use chrono::Timelike;
    use chrono::Utc;

    use std::sync::mpsc;
    use std::sync::mpsc::Receiver;
    // use std::sync::mpsc::TryRecvError;
    use std::io;
    use std::thread;
    use std::time::Duration;

    use totp::generate;

    use crate::Key;

    pub enum OTPMessage {
        Code(u32),
    }

    pub fn display_key(key: &Key) {
        let otp_channel = spawn_thread(key);

        loop {
            match otp_channel.recv().unwrap() {
                OTPMessage::Code(c) => println!("{:0>6}", c),
            }
        }
    }

    fn spawn_thread(key: &Key) -> Receiver<OTPMessage> {
        let (tx, rx) = mpsc::channel::<OTPMessage>();
        let key_string = key.key.clone();

        let code = generate(key_string.as_str());
        tx.send(OTPMessage::Code(code)).unwrap();

        thread::spawn(move || loop {
            let now = Utc::now();

            if now.second() == 0 || now.second() == 30 {
                let code = generate(key_string.as_str());

                tx.send(OTPMessage::Code(code)).unwrap();

                thread::sleep(Duration::from_secs(2));
            } else {
                thread::sleep(Duration::from_millis(50));
            }
        });
        rx
    }

    pub fn display_choice(keys: &Vec<Key>) -> &Key {
        loop {
            let listing = keys
                .iter()
                .map(|k| format!("{}\n", k.name))
                .collect::<String>();
            println!("Codes:\n{}", listing);

            let mut buffer = String::new();
            io::stdin().read_line(&mut buffer).unwrap();
            let n = buffer.trim();

            if let Some(k) = keys.iter().find(|k| k.name == n) {
                return k;
            } else {
                println!("\nPlease input a valid name\n")
            }
        }
    }
}

pub mod file {
    use crate::Key;
    use std::fs::File;
    use std::path::Path;

    pub fn save(keys: Vec<Key>) {
        let path = Path::new("keys.txt");
        let file = File::create(path).unwrap();
        serde_json::to_writer_pretty(file, &keys).unwrap();
    }

    pub fn load() -> Vec<Key> {
        if let Ok(f) = File::open("keys.txt") {
            serde_json::from_reader(f).unwrap()
        } else {
            save(Vec::new());
            Vec::new()
        }
    }
}
