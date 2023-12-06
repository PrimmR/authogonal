// Generates password code from HMAC

use std::convert::TryInto;
use std::str;

use crate::hmac;
use crate::key::Key;
use chrono::Utc;

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum OTPMethod {
    TOTP,
    HOTP(u64),
}

impl OTPMethod {
    pub fn increment_counter(&mut self) {
        match self {
            Self::HOTP(ref mut c) => *c += 1,
            Self::TOTP => (),
        }
    }
}

impl Key {
    // Validation done when keys entered
    fn to_b32(&self) -> Vec<u8> {
        let base32chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        let upper = self.secret.to_ascii_uppercase();

        let i = upper.chars().fold(String::new(), |acc, x| {
            acc + format!("{:05b}", base32chars.find(x).unwrap()).as_str()
        });

        let bytes = i.into_bytes();

        bytes
            .chunks(8)
            .map(|x| {
                u8::from_str_radix(String::from_utf8(x.to_vec()).unwrap().as_str(), 2).unwrap()
            })
            .collect()
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

pub fn generate(key: &Key) -> u32 {
    let b32key = key.to_b32();

    let now = Utc::now();
    // Timestep updates every interval seconds
    let timestep = now.timestamp() / key.options.interval as i64;

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
            239, 175, 55, 150, 38, 85, 24, 149, 68, 234, 249, 243, 110, 126, 48, 57, 73, 119, 39,
            232,
        ];
        assert_eq!(truncate(&mac), 1156250099);
    }

    #[test]
    fn extract_high_unset() {
        let mac: Vec<_> = vec![
            239, 175, 55, 150, 38, 85, 24, 149, 68, 234, 249, 243, 110, 126, 48, 57, 73, 119, 39,
            232,
        ];
        assert_eq!(extract31(&mac, 2), [55, 150, 38, 85]);
    }

    #[test]
    fn extract_high_set() {
        let mac: Vec<_> = vec![
            239, 175, 55, 150, 38, 85, 24, 149, 68, 234, 249, 243, 110, 126, 48, 57, 73, 119, 39,
            232,
        ];
        assert_eq!(extract31(&mac, 10), [121, 243, 110, 126]);
    }

    #[test]
    fn regular_to_b32() {
        let key = Key::new(String::from("Primm"), String::new(), Default::default());
        let expect = vec![0x7c, 0x50, 0xc6, 0x00];
        assert_eq!(key.to_b32(), expect)
    }
}
