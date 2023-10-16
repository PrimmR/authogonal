extern crate chrono;
extern crate serde;

use serde::{Deserialize, Serialize};

// Structs used for the whole library
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Key {
    secret: String,
    name: String,
    options: CodeOptions,
}

impl Key {
    pub fn new(secret: String, name: String, options: CodeOptions) -> Self {
        Self {
            secret,
            name,
            options,
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug)]
pub struct CodeOptions {
    method: otp::OTPMethod,
    hash: hash::HashFn,
    length: u8,
}

impl CodeOptions {
    pub fn new(method: otp::OTPMethod, hash: hash::HashFn, length: u8) -> Self {
        Self {
            method,
            hash,
            length,
        }
    }
}

impl std::default::Default for CodeOptions {
    fn default() -> Self {
        Self {
            method: otp::OTPMethod::TOTP,
            hash: hash::HashFn::SHA1,
            length: 6,
        }
    }
}

pub mod hash {
    use serde::{Deserialize, Serialize};

    pub trait Hash {
        fn to_vec(&self) -> Vec<u8>;
        fn process_chunks(&self, chunk: &[u8]) -> Self;

        fn get_block_size(&self) -> usize {
            64
        }
    }

    #[derive(Serialize, Deserialize, Clone, Copy, Debug)]
    pub enum HashFn {
        SHA1,
        SHA256,
        SHA512,
    }

    impl HashFn {
        pub fn digest(&self, message: &Vec<u8>) -> Vec<u8> {
            match self {
                Self::SHA1 => hash(sha1::SHA1Hash::new(), message),
                Self::SHA256 => hash(sha2::SHA256Hash::new(), message),
                Self::SHA512 => todo!(),
            }
        }
    }

    pub fn hash<T: Hash + std::ops::Add<Output = T>>(hash: T, message: &[u8]) -> Vec<u8> {
        // Message length in bits
        let ml: u64 = TryInto::<u64>::try_into(message.len()).unwrap() * 8;
        let mut message = message.to_vec();

        // Pre-processing
        message.push(0x80);

        // message len needs to be multiple of (512-64)/8 = 56
        message = pad_mult(message, hash.get_block_size(), 8);
        message.append(&mut u64::to_be_bytes(ml).to_vec());

        // chunk into 512/8= 64 byte chunks
        let chunks = message.chunks(64);

        let hash = chunks.fold(hash, |acc, x| acc.process_chunks(x) + acc);

        hash.to_vec()
    }

    pub mod sha1 {
        use super::*;

        #[derive(Debug)]
        pub struct SHA1Hash(u32, u32, u32, u32, u32);

        impl SHA1Hash {
            const H0: u32 = 0x67452301;
            const H1: u32 = 0xEFCDAB89;
            const H2: u32 = 0x98BADCFE;
            const H3: u32 = 0x10325476;
            const H4: u32 = 0xC3D2E1F0;

            pub fn new() -> Self {
                Self(Self::H0, Self::H1, Self::H2, Self::H3, Self::H4)
            }
        }

        impl Hash for SHA1Hash {
            fn to_vec(&self) -> Vec<u8> {
                let mut v = Vec::new();
                v.append(&mut self.0.to_be_bytes().to_vec());
                v.append(&mut self.1.to_be_bytes().to_vec());
                v.append(&mut self.2.to_be_bytes().to_vec());
                v.append(&mut self.3.to_be_bytes().to_vec());
                v.append(&mut self.4.to_be_bytes().to_vec());
                v
            }

            fn process_chunks(&self, chunk: &[u8]) -> SHA1Hash {
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
                let mut a = self.0;
                let mut b = self.1;
                let mut c = self.2;
                let mut d = self.3;
                let mut e = self.4;

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
        }

        impl std::ops::Add for SHA1Hash {
            type Output = Self;

            fn add(self, rhs: Self) -> Self::Output {
                // Addition that prevents overflows
                Self(
                    self.0.wrapping_add(rhs.0),
                    self.1.wrapping_add(rhs.1),
                    self.2.wrapping_add(rhs.2),
                    self.3.wrapping_add(rhs.3),
                    self.4.wrapping_add(rhs.4),
                )
            }
        }
    }

    pub mod sha2 {
        use super::*;

        #[derive(Debug)]
        pub struct SHA256Hash(u32, u32, u32, u32, u32, u32, u32, u32);

        impl SHA256Hash {
            const H0: u32 = 0x6A09E667;
            const H1: u32 = 0xBB67AE85;
            const H2: u32 = 0x3C6EF372;
            const H3: u32 = 0xA54FF53A;
            const H4: u32 = 0x510E527F;
            const H5: u32 = 0x9B05688C;
            const H6: u32 = 0x1F83D9AB;
            const H7: u32 = 0x5BE0CD19;

            const K: [u32; 64] = [
                0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5, 0x3956C25B, 0x59F111F1, 0x923F82A4,
                0xAB1C5ED5, 0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3, 0x72BE5D74, 0x80DEB1FE,
                0x9BDC06A7, 0xC19BF174, 0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC, 0x2DE92C6F,
                0x4A7484AA, 0x5CB0A9DC, 0x76F988DA, 0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7,
                0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967, 0x27B70A85, 0x2E1B2138, 0x4D2C6DFC,
                0x53380D13, 0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85, 0xA2BFE8A1, 0xA81A664B,
                0xC24B8B70, 0xC76C51A3, 0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070, 0x19A4C116,
                0x1E376C08, 0x2748774C, 0x34B0BCB5, 0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
                0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208, 0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7,
                0xC67178F2,
            ];

            pub fn new() -> Self {
                Self(
                    Self::H0,
                    Self::H1,
                    Self::H2,
                    Self::H3,
                    Self::H4,
                    Self::H5,
                    Self::H6,
                    Self::H7,
                )
            }
        }

        impl Hash for SHA256Hash {
            fn to_vec(&self) -> Vec<u8> {
                let mut v = Vec::new();
                v.append(&mut self.0.to_be_bytes().to_vec());
                v.append(&mut self.1.to_be_bytes().to_vec());
                v.append(&mut self.2.to_be_bytes().to_vec());
                v.append(&mut self.3.to_be_bytes().to_vec());
                v.append(&mut self.4.to_be_bytes().to_vec());
                v.append(&mut self.5.to_be_bytes().to_vec());
                v.append(&mut self.6.to_be_bytes().to_vec());
                v.append(&mut self.7.to_be_bytes().to_vec());
                v
            }

            fn process_chunks(&self, chunk: &[u8]) -> SHA256Hash {
                // Convert 64 byte chunks to 16 32-bit big-endian words
                let mut words: Vec<u32> = chunk
                    .chunks(4)
                    .map(|x| u32::from_be_bytes(x.try_into().unwrap()))
                    .collect();

                // Creates 64 long vec
                for i in 16..64 {
                    let s0 = right_rot(words[i - 15], 7)
                        ^ right_rot(words[i - 15], 18)
                        ^ (words[i - 15] >> 3);
                    let s1 = right_rot(words[i - 2], 17)
                        ^ right_rot(words[i - 2], 19)
                        ^ (words[i - 2] >> 10);
                    words.push(
                        words[i - 16]
                            .wrapping_add(s0)
                            .wrapping_add(words[i - 7])
                            .wrapping_add(s1),
                    );
                }

                // Init values
                let mut a = self.0;
                let mut b = self.1;
                let mut c = self.2;
                let mut d = self.3;
                let mut e = self.4;
                let mut f = self.5;
                let mut g = self.6;
                let mut h = self.7;

                for i in 0..64 {
                    let s1 = right_rot(e, 6) ^ right_rot(e, 11) ^ right_rot(e, 25);
                    let ch = (e & f) ^ ((!e) & g);
                    let temp1 = h
                        .wrapping_add(s1)
                        .wrapping_add(ch)
                        .wrapping_add(SHA256Hash::K[i])
                        .wrapping_add(words[i]);
                    let s0 = right_rot(a, 2) ^ right_rot(a, 13) ^ right_rot(a, 22);
                    let maj = (a & b) ^ (a & c) ^ (b & c);
                    let temp2 = s0.wrapping_add(maj);

                    h = g;
                    g = f;
                    f = e;
                    e = d.wrapping_add(temp1);
                    d = c;
                    c = b;
                    b = a;
                    a = temp1.wrapping_add(temp2);
                }

                SHA256Hash(a, b, c, d, e, f, g, h)
            }
        }

        impl std::ops::Add for SHA256Hash {
            type Output = Self;

            fn add(self, rhs: Self) -> Self::Output {
                // Addition that prevents overflows
                Self(
                    self.0.wrapping_add(rhs.0),
                    self.1.wrapping_add(rhs.1),
                    self.2.wrapping_add(rhs.2),
                    self.3.wrapping_add(rhs.3),
                    self.4.wrapping_add(rhs.4),
                    self.5.wrapping_add(rhs.5),
                    self.6.wrapping_add(rhs.6),
                    self.7.wrapping_add(rhs.7),
                )
            }
        }
    }

    // Circular left shift
    fn left_rot(num: u32, by: u8) -> u32 {
        (num << by) | (num >> (32 - by))
    }

    // Circular right shift
    fn right_rot(num: u32, by: u8) -> u32 {
        (num >> by) | (num << (32 - by))
    }

    // Pad with 0s to next multiple of mult - sub
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
        fn lrot0() {
            assert_eq!(
                left_rot(0b00001110_00001110_00001110_00001110, 2),
                0b00111000_00111000_00111000_00111000
            )
        }

        #[test]
        fn lrot1() {
            assert_eq!(
                left_rot(0b10111001_10111001_10111001_10111001, 4),
                0b10011011_10011011_10011011_10011011
            )
        }

        #[test]
        fn rrot0() {
            assert_eq!(
                right_rot(0b00001110_00001110_00001110_00001100, 2),
                0b00000011_10000011_10000011_10000011
            )
        }

        #[test]
        fn rrot1() {
            assert_eq!(
                right_rot(0b10111001_10111001_10111001_10111001, 4),
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
            assert_eq!(hash(sha1::SHA1Hash::new(), key), result)
        }

        #[test]
        fn sha1_single_chunk() {
            let key = b"Primm";
            let result = vec![
                0x59, 0x07, 0x84, 0x5c, 0xeb, 0x72, 0x05, 0x8d, 0xa5, 0x36, 0xa6, 0x23, 0xa0, 0x83,
                0x8c, 0x5c, 0x1b, 0x92, 0x57, 0xe0,
            ];
            assert_eq!(hash(sha1::SHA1Hash::new(), key), result)
        }

        #[test]
        fn sha1_mult_chunk() {
            let key = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz01234567890";
            let result = vec![
                0xd2, 0x6c, 0xf5, 0xf8, 0x56, 0xae, 0xaa, 0x77, 0xa7, 0xfb, 0xaa, 0x32, 0x6f, 0x7d,
                0x31, 0x2c, 0xba, 0xb5, 0xaa, 0x4b,
            ];
            assert_eq!(hash(sha1::SHA1Hash::new(), key), result)
        }

        #[test]
        fn sha256_empty() {
            let key = b"";
            let result = vec![
                0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f,
                0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b,
                0x78, 0x52, 0xb8, 0x55,
            ];
            assert_eq!(hash(sha2::SHA256Hash::new(), key), result)
        }

        #[test]
        fn sha256_single_chunk() {
            let key = b"Primm";
            let result = vec![
                0xc0, 0xdb, 0x4a, 0xab, 0x55, 0x0b, 0x16, 0xb1, 0xeb, 0x4a, 0xbf, 0x1b, 0xca, 0xf3,
                0xb3, 0x42, 0x65, 0x39, 0xf9, 0x83, 0x8e, 0xd2, 0x1f, 0x70, 0x75, 0x22, 0x3f, 0x90,
                0xbc, 0x3a, 0xd2, 0x2d,
            ];
            assert_eq!(hash(sha2::SHA256Hash::new(), key), result)
        }

        #[test]
        fn sha256_mult_chunk() {
            let key = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz01234567890";
            let result = vec![
                0x60, 0x24, 0x4f, 0x16, 0x18, 0x27, 0xbb, 0x1f, 0xe6, 0x2a, 0xcc, 0xf0, 0xd4, 0xa5,
                0x42, 0x16, 0xdf, 0x21, 0x03, 0x14, 0x6b, 0x18, 0xe4, 0xce, 0xe6, 0x10, 0xac, 0x97,
                0x24, 0x6c, 0x0b, 0x0b,
            ];
            assert_eq!(hash(sha2::SHA256Hash::new(), key), result)
        }
    }
}

pub mod hmac {
    use crate::CodeOptions;
    const IPAD: u8 = 0x36;
    const OPAD: u8 = 0x5c;

    pub fn generate(key: &[u8], message: &[u8], options: CodeOptions) -> Vec<u8> {
        let block_size = 64; // Block size in bytes
                             // let output_size = 40; // Always truncated

        let block_sized_key = compute_block_sized_key(key, options, block_size);

        let input_key_pad: Vec<u8> = block_sized_key.iter().map(|x| x ^ IPAD).collect();
        let output_key_pad: Vec<u8> = block_sized_key.iter().map(|x| x ^ OPAD).collect();

        let digest: Vec<u8> = options
            .hash
            .digest(&concat(input_key_pad, message.to_vec()));
        options.hash.digest(&concat(output_key_pad, digest))
    }

    fn compute_block_sized_key(key: &[u8], options: CodeOptions, block_size: usize) -> Vec<u8> {
        if key.len() > block_size {
            options.hash.digest(&key.to_vec())
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
            let mac = generate(b"key", b"Primm", Default::default());
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
            let mac = generate(b"", b"", Default::default());
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

pub mod otp {
    use std::convert::TryInto;
    use std::str;

    use crate::hmac;
    use crate::Key;
    use chrono::Utc;

    use serde::{Deserialize, Serialize};

    #[derive(Serialize, Deserialize, Clone, Copy, Debug)]
    pub enum OTPMethod {
        TOTP,
        HOTP(u64),
    }

    impl Key {
        fn to_b32(&self) -> Result<Vec<u8>, char> {
            let base32chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
            let upper = self.secret.to_ascii_uppercase();

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
    }

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

    pub fn generate(key: &Key) -> u32 {
        let b32key = key.to_b32().expect("Key contains invalid characters");

        let now = Utc::now();
        let timestep = now.timestamp() / 30;

        let count: u64 = match key.options.method {
            OTPMethod::TOTP => timestep.try_into().unwrap(),
            OTPMethod::HOTP(c) => c,
        };

        let mac = hmac::generate(&b32key[..], &count.to_be_bytes(), key.options);

        let totp = truncate(&mac) % 10_u32.pow(key.options.length.into());

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
            let key = Key::new(String::from("Primm"), String::new(), Default::default());
            let expect = vec![0x7c, 0x50, 0xc6, 0x00];
            assert_eq!(key.to_b32().unwrap(), expect)
        }

        #[test]
        fn empty_to_b32() {
            let key = Key::new(String::new(), String::new(), Default::default());
            let expect: Vec<u8> = Vec::new();
            assert_eq!(key.to_b32().unwrap(), expect);
        }

        #[test]
        fn invalid_to_b32() {
            let key = Key::new(String::from("&"), String::new(), Default::default());
            assert_eq!(key.to_b32(), Err('&'));
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

    use crate::otp::generate;

    use crate::Key;

    pub enum OTPMessage {
        Code(u32),
    }

    pub fn display_key(key: &Key) {
        let otp_channel = spawn_thread(key);

        loop {
            match otp_channel.recv().unwrap() {
                OTPMessage::Code(c) => {
                    let d: usize = key.options.length.into();
                    println!("{:0>d$}", c, d = d)
                }
            }
        }
    }

    fn spawn_thread(key: &Key) -> Receiver<OTPMessage> {
        let (tx, rx) = mpsc::channel::<OTPMessage>();
        let key_clone = key.clone();

        let code = generate(&key_clone);
        tx.send(OTPMessage::Code(code)).unwrap();

        thread::spawn(move || loop {
            let now = Utc::now();

            if now.second() == 0 || now.second() == 30 {
                let code = generate(&key_clone);

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

    pub fn save(keys: &Vec<Key>) {
        let path = Path::new("keys.txt");
        let file = File::create(path).unwrap();
        serde_json::to_writer_pretty(file, &keys).unwrap();
    }

    pub fn load() -> Vec<Key> {
        if let Ok(f) = File::open("keys.txt") {
            serde_json::from_reader(f).unwrap()
        } else {
            save(&Vec::new());
            Vec::new()
        }
    }
}
