use std::convert::TryInto;
use std::str;

use chrono::Utc;
// use hex;
use hmac::{Hmac, Mac};
use sha1::Sha1;

type HmacSha1 = Hmac<Sha1>;

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

fn to_b32(key: &str) -> Vec<u8> {
    let base32chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let upper = key.to_ascii_uppercase();
    let i = upper.chars().fold(String::new(), |acc, x| {
        acc + format!("{:05b}", base32chars.find(x).unwrap()).as_str()
    });

    let bytes = i.into_bytes();

    bytes
        .chunks(8)
        .map(|x| u8::from_str_radix(String::from_utf8(x.to_vec()).unwrap().as_str(), 2).unwrap())
        .collect::<Vec<u8>>()
}

fn main() {
    let key = "Primm";
    let b32key = to_b32(key);

    let now = Utc::now();
    let timestep = now.timestamp() / 30;

    let mut mac = HmacSha1::new_from_slice(&b32key).expect("HMAC can take key of any size");
    mac.update(&timestep.to_be_bytes());

    let mac = mac.finalize().into_bytes()[..].to_vec();

    let hotp = truncate(&mac) % 10_u32.pow(6);

    // let num = u16::from_be_bytes(totp[])
    println!("OTP: {:0>6}", hotp);
}
