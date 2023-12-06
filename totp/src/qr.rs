// Handles QR code parsing

use std::path::PathBuf;

use crate::key::{CodeOptions, Key};
use crate::otp::OTPMethod;
use hash::HashFn;
use regex::Regex;

// Reads raw data from QR
fn read_qr(img_path: PathBuf) -> Result<String, Box<dyn std::error::Error>> {
    let img = image::open(img_path)?;

    // Use default decoder
    let decoder = bardecoder::default_decoder();

    let results = decoder.decode(&img);
    Ok(results.into_iter().nth(0).ok_or(Error::Read)??)
}

// Parses the main, fixed structure of the URI scheme using RE
pub fn parse(img_path: PathBuf) -> Result<Key, Box<dyn std::error::Error>> {
    let uri = read_qr(img_path)?;
    let re = Regex::new(r"^otpauth://(?<type>(?:h|t)otp)/(?<label>.+)\?(?<params>.*)$").unwrap();

    let caps = re.captures(&uri).ok_or(Error::Read)?;

    let params = parse_params(caps["params"].to_owned())?;

    let method = match &caps["type"] {
        "totp" => OTPMethod::TOTP,
        "hotp" => OTPMethod::HOTP(params.counter.unwrap_or(0)),
        _ => panic!(),
    };

    let name = caps["label"].to_string();

    Ok(Key::new(
        params.secret,
        name,
        CodeOptions::new_or_default(Some(method), params.algorithm, params.digits, params.period),
    ))
}

// Ignore Issuer
#[derive(Debug)]
struct Params {
    secret: String,
    algorithm: Option<HashFn>,
    digits: Option<u8>,
    counter: Option<u64>,
    period: Option<u32>,
}

// Parses from paramaters field, which can be in any order, using RE
fn parse_params(params: String) -> Result<Params, Box<dyn std::error::Error>> {
    let secret_re = Regex::new(r"(?:^|\?|&)secret=([^&?]+)(?:&|$)").unwrap();
    let algorithm_re = Regex::new(r"(?:^|\?|&)algorithm=(SHA(?:1|256|512))(?:&|$)").unwrap();
    let digits_re = Regex::new(r"(?:^|\?|&)digits=(\d+)(?:&|$)").unwrap();
    let counter_re = Regex::new(r"(?:^|\?|&)counter=(\d+)(?:&|$)").unwrap();
    let period_re = Regex::new(r"(?:^|\?|&)period=(\d+)(?:&|$)").unwrap();

    let secret = secret_re.captures(&params).ok_or(Error::NoSecret)?[1].to_owned();

    let algorithm = if let Some(algorithm) = algorithm_re.captures(&params) {
        let string = algorithm.get(1).ok_or(Error::InvalidParamater)?.as_str();
        match string {
            "SHA1" => Some(HashFn::SHA1),
            "SHA256" => Some(HashFn::SHA256),
            "SHA512" => Some(HashFn::SHA512),
            _ => return Err(Box::new(Error::InvalidParamater)),
        }
    } else {
        None
    };

    let digits = if let Some(digits) = digits_re.captures(&params) {
        Some(
            digits
                .get(1)
                .ok_or(Error::InvalidParamater)?
                .as_str()
                .parse()?,
        )
    } else {
        None
    };

    let counter = if let Some(counter) = counter_re.captures(&params) {
        Some(
            counter
                .get(1)
                .ok_or(Error::InvalidParamater)?
                .as_str()
                .parse()?,
        )
    } else {
        None
    };

    let period = if let Some(period) = period_re.captures(&params) {
        Some(
            period
                .get(1)
                .ok_or(Error::InvalidParamater)?
                .as_str()
                .parse()?,
        )
    } else {
        None
    };

    Ok(Params {
        secret,
        algorithm,
        digits,
        counter,
        period,
    })
}

// All errors that can occur
#[derive(Debug)]
pub enum Error {
    NoSecret,
    InvalidParamater,
    Read,
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
    fn google() {
        let key = parse(PathBuf::from("src/test_data/qr/google.png"));
        assert_eq!(
            key.unwrap(),
            Key::new(
                String::from("JBSWY3DPEHPK3PXP"),
                String::from("Example:alice@google.com"),
                Default::default()
            )
        )
    }

    #[test]
    fn hotp() {
        let key = parse(PathBuf::from("src/test_data/qr/hotp.png"));
        let options = CodeOptions::new_or_default(
            Some(OTPMethod::HOTP(20)),
            Some(HashFn::SHA256),
            None,
            None,
        );
        assert_eq!(
            key.unwrap(),
            Key::new(
                String::from("JBSWY3DPEHPK3PXP"),
                String::from("Example:alice@google.com"),
                options
            )
        )
    }

    #[test]
    fn totp() {
        let key = parse(PathBuf::from("src/test_data/qr/totp.png"));
        let options = CodeOptions::new_or_default(
            Some(OTPMethod::TOTP),
            Some(HashFn::SHA512),
            Some(4),
            Some(15),
        );
        assert_eq!(
            key.unwrap(),
            Key::new(String::from("manonam"), String::from("Primm"), options)
        )
    }

    // Has an empty secret
    #[test]
    fn invalid() {
        assert!(parse(PathBuf::from("src/test_data/qr/err.png")).is_err())
    }
}
