extern crate chrono;
extern crate serde;

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

pub mod hash {
    use std::convert::TryInto;

    #[derive(Debug)]
    struct SHA1Hash(u32, u32, u32, u32, u32);

    impl SHA1Hash {
        const H0: u32 = 0x67452301;
        const H1: u32 = 0xEFCDAB89;
        const H2: u32 = 0x98BADCFE;
        const H3: u32 = 0x10325476;
        const H4: u32 = 0xC3D2E1F0;

        fn new() -> Self {
            Self(Self::H0, Self::H1, Self::H2, Self::H3, Self::H4)
        }

        fn to_vec(&self) -> Vec<u8> {
            let mut v = Vec::new();
            v.append(&mut self.0.to_be_bytes().to_vec());
            v.append(&mut self.1.to_be_bytes().to_vec());
            v.append(&mut self.2.to_be_bytes().to_vec());
            v.append(&mut self.3.to_be_bytes().to_vec());
            v.append(&mut self.4.to_be_bytes().to_vec());
            v
        }
    }

    impl std::ops::Add for SHA1Hash {
        type Output = Self;

        fn add(self, rhs: Self) -> Self::Output {
            // Prevents overflows
            Self(
                self.0.wrapping_add(rhs.0),
                self.1.wrapping_add(rhs.1),
                self.2.wrapping_add(rhs.2),
                self.3.wrapping_add(rhs.3),
                self.4.wrapping_add(rhs.4),
            )
        }
    }

    pub fn sha1(message: &[u8]) -> Vec<u8> {
        // Message length in bits
        let ml: u64 = TryInto::<u64>::try_into(message.len()).unwrap() * 8;
        let mut message = message.to_vec();

        // Pre-processing
        message.push(0x80);

        // message len needs to be multiple of (512-64)/8 = 56
        message = pad_mult(message, 64, 8);
        message.append(&mut u64::to_be_bytes(ml).to_vec());

        // chunk into 512/8= 64 byte chunks
        let chunks = message.chunks(64);

        let hash = chunks.fold(SHA1Hash::new(), |acc, x| process_chunks(&acc, x) + acc);

        hash.to_vec()
    }

    fn process_chunks(hash: &SHA1Hash, chunk: &[u8]) -> SHA1Hash {
        // Convert 64 byte chunks to 16 32-bit big-endian words
        let mut words: Vec<u32> = chunk
            .chunks(4)
            .map(|x| u32::from_be_bytes(x.try_into().unwrap()))
            .collect();

        // Creates 80 long vec
        for i in 16..80 {
            let item = words[i - 3] ^ words[i - 8] ^ words[i - 14] ^ words[i - 16];
            words.push(left_rot(item, 1));
        }

        // Init values
        let mut a = hash.0;
        let mut b = hash.1;
        let mut c = hash.2;
        let mut d = hash.3;
        let mut e = hash.4;

        for i in 0..80 {
            let (f, k): (u32, u32) = match i {
                0..=19 => (d ^ (b & (c ^ d)), 0x5A827999), // ((b & c) | (!b & d), 0xfa827999),
                20..=39 => (b ^ c ^ d, 0x6ed9eba1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8f1bbcdc),
                _ => (b ^ c ^ d, 0xca62c1d6), // 60..=79
            };

            // Wrapping add keeps number as u32
            let temp = left_rot(a, 5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(words[i]);

            e = d;
            d = c;
            c = left_rot(b, 30);
            b = a;
            a = temp;
        }

        SHA1Hash(a, b, c, d, e)
    }

    // Circular left shift
    fn left_rot(num: u32, by: u8) -> u32 {
        (num << by) | (num >> (32 - by))
    }

    fn pad_mult(message: Vec<u8>, mult: usize, sub: usize) -> Vec<u8> {
        let message_len = message.len();

        let size = (((message_len + sub + mult - 1) / mult) * mult) - sub;

        let mut pad = message;
        pad.resize(size, 0);
        pad
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn rot0() {
            assert_eq!(
                left_rot(0b00001110_00001110_00001110_00001110, 2),
                0b00111000_00111000_00111000_00111000
            )
        }

        #[test]
        fn rot1() {
            assert_eq!(
                left_rot(0b10111001_10111001_10111001_10111001, 4),
                0b10011011_10011011_10011011_10011011
            )
        }

        #[test]
        fn pad() {
            assert_eq!(
                pad_mult(vec![20, 82, 21, 05], 3, 1),
                vec![20, 82, 21, 05, 0]
            )
        }

        #[test]
        fn pad_overflow() {
            assert_eq!(
                pad_mult(vec![20, 82, 21, 05, 22, 40, 34, 15], 3, 2),
                vec![20, 82, 21, 05, 22, 40, 34, 15, 0, 0]
            )
        }

        #[test]
        fn sha1_empty() {
            let key = b"";
            let result = vec![
                0xda, 0x39, 0xa3, 0xee, 0x5e, 0x6b, 0x4b, 0x0d, 0x32, 0x55, 0xbf, 0xef, 0x95, 0x60,
                0x18, 0x90, 0xaf, 0xd8, 0x07, 0x09,
            ];
            assert_eq!(sha1(key), result)
        }

        #[test]
        fn sha1_single_chunk() {
            let key = b"Primm";
            let result = vec![
                0x59, 0x07, 0x84, 0x5c, 0xeb, 0x72, 0x05, 0x8d, 0xa5, 0x36, 0xa6, 0x23, 0xa0, 0x83,
                0x8c, 0x5c, 0x1b, 0x92, 0x57, 0xe0,
            ];
            assert_eq!(sha1(key), result)
        }

        #[test]
        fn sha1_mult_chunk() {
            let key = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz01234567890";
            let result = vec![
                0xd2, 0x6c, 0xf5, 0xf8, 0x56, 0xae, 0xaa, 0x77, 0xa7, 0xfb, 0xaa, 0x32, 0x6f, 0x7d,
                0x31, 0x2c, 0xba, 0xb5, 0xaa, 0x4b,
            ];
            assert_eq!(sha1(key), result)
        }
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
        pad
    }

    fn concat(a: Vec<u8>, b: Vec<u8>) -> Vec<u8> {
        vec![a, b].concat()
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn regular_hmac() {
            let mac = generate(b"key", b"Primm");
            assert_eq!(
                mac,
                vec![
                    203, 50, 188, 168, 102, 194, 103, 213, 122, 33, 67, 152, 75, 183, 227, 89, 0,
                    149, 161, 215
                ]
            )
        }

        #[test]
        fn empty_hmac() {
            let mac = generate(b"", b"");
            assert_eq!(
                mac,
                vec![
                    251, 219, 29, 27, 24, 170, 108, 8, 50, 75, 125, 100, 183, 31, 183, 99, 112,
                    105, 14, 29
                ]
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
