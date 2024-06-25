// Generates password code from HMAC

use crate::hmac;
use crate::key::Key;
use chrono::Utc;

use serde::{Deserialize, Serialize};

/// An enum to represent the main method to generate codes, either being a time based code (TOTP), or a counter based code (HOTP)
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)] // Needed to be converted to json, cloned implicitly & sorted
pub enum OTPMethod {
    TOTP,
    HOTP(u64), // Stores current count value
}

impl OTPMethod {
    // This is a method to allow for modification of the enum within Rust's concurrency checker
    /// Increments counter within HOTP variant, doing nothing if self is a TOTP variant
    pub fn increment_counter(&mut self) {
        match self {
            Self::HOTP(ref mut c) => *c += 1,
            Self::TOTP => (),
        }
    }

    pub fn strip(&self) -> OTPMethodStripped {
        match self {
            Self::HOTP(_) => OTPMethodStripped::HOTP,
            Self::TOTP => OTPMethodStripped::TOTP,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)] // Needed to be converted to json, cloned implicitly & sorted

pub enum OTPMethodStripped {
    TOTP,
    HOTP
}

impl Key {
    /// Converts key's secret to base 32
    // Validation done when keys entered, so can be treated as always valid
    fn to_b32(&self) -> Vec<u8> {
        // Base 32 character set in index order, so find method will return base 32 representation of a char
        let base32chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        let upper = self.secret.to_ascii_uppercase();

        // Fold through each character, appending the binary representation of its corresponding base 32 value to a string with each item
        let b32 = upper.chars().fold(String::new(), |acc, x| {
            acc + format!("{:05b}", base32chars.find(x).unwrap()).as_str()
        });

        // Converts into byte array
        let bytes = b32.into_bytes();

        // Outputs bytes, with any trailing bits after the last full bytes being padded with 0s to the left
        bytes
            .chunks(8)
            .map(|x| {
                u8::from_str_radix(String::from_utf8(x.to_vec()).unwrap().as_str(), 2).unwrap()
            })
            .collect()
    }
}

/// Truncate the MAC array with a generated index to 31 bits
fn truncate(mac: &Vec<u8>) -> u32 {
    // Takes the 4 least significant bits of the MAC and use them as a byte offset
    let lsb = mac[mac.len() - 1] & 0b00001111;
    let extracted = extract31(mac, lsb.into());

    u32::from_be_bytes(extracted)
}

/// Take 31 bits from a byte index into the MAC array
/// Only 31 bits are taken, as the most significant bit is always set to 0  
fn extract31(mac: &Vec<u8>, i: usize) -> [u8; 4] {
    let mut extract: [u8; 4] = mac[i..i + 4].try_into().unwrap();
    // Set the MSB to 0
    extract[0] &= 0x7F;
    extract
}

/// Generate a OTP code from a key
pub fn generate(key: &Key) -> u32 {
    // Convert the key to base 32, won't fail as key previously validated
    let b32key = key.to_b32();

    // If TOTP, count variable used in HMAC is based on current time
    // If HOTP, count variable is stored with key

    let count: u64 = match key.options.method {
        OTPMethod::TOTP => {
            // Calculate timestep
            // Timestep updates by 1 every interval seconds, achieved by rounding current timestamp down to multiple of interval
            let now = Utc::now();
            let timestep = now.timestamp() / key.options.interval as i64;
            timestep.try_into().unwrap()
        }
        OTPMethod::HOTP(c) => c,
    };

    // Calculate HMAC value, with the key as the base 32 secret, message as a big endian representation of the count, and the hash function specified by the key
    let mac = hmac::generate(&b32key[..], &count.to_be_bytes(), &key.options.hash);

    // Truncate the HMAC into 31 bits and then further into a key.options.length length code
    let totp = truncate(&mac) % 10_u32.pow(key.options.length.into());

    // Return the code as a u32, which can safely store all generated numbers, as the max code value is 999,999
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
    fn b32_0() {
        let key = Key::new(String::from("Primm"), String::new(), Default::default());
        let expect = vec![0x7c, 0x50, 0xc6, 0x00];
        assert_eq!(key.to_b32(), expect)
    }

    #[test]
    fn b32_1() {
        let key = Key::new(String::from("manonam"), String::new(), Default::default());
        let expect = vec![0x60, 0x1a, 0xe6, 0x81, 0x04];
        assert_eq!(key.to_b32(), expect)
    }
}
