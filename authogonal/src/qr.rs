// Handles QR code parsing, using the URI schema from https://github.com/google/google-authenticator/wiki/Key-Uri-Format

use std::path::PathBuf;

use crate::key::{CodeOptions, Key};
use crate::otp::OTPMethod;
use hash::HashFn;
use regex::Regex;

/// Reads raw data from QR
fn read_qr(img_path: PathBuf) -> Result<String, Box<dyn std::error::Error>> {
    // Open image from entered bath
    let img = image::open(img_path)?;

    // Use default bardecoder decoder to decode image
    let decoder = bardecoder::default_decoder();
    let results = decoder.decode(&img);
    // Return the 1st decoded QR code, or if one cannot be found return a read error 
    Ok(results.into_iter().nth(0).ok_or(Error::Read)??)
}

/// Parses the main required structure of the URI scheme using RegEx
pub fn parse(img_path: PathBuf) -> Result<Key, Box<dyn std::error::Error>> {
    // Read in the uri text
    let uri = read_qr(img_path)?;

    // Regex to match to text read from QR
    let re = Regex::new(r"^otpauth://(?<type>(?:h|t)otp)/(?<label>.+)\?(?<params>.*)$").unwrap();

    // Match the URI string to the regex, saving the data that falls within capturing groups (i.e. within brackets)
    let caps = re.captures(&uri).ok_or(Error::Read)?;

    // Parse any optional paramaters
    let params = parse_params(caps["params"].to_owned())?;

    // Match the method string to respective enum
    let method = match &caps["type"] {
        "totp" => OTPMethod::TOTP,
        "hotp" => OTPMethod::HOTP(params.counter.unwrap_or(0)),
        _ => panic!(),
    };

    let name = caps["label"].to_string();

    // Return a new key built from the QR data, with all non-present parameters being initialised to default
    Ok(Key::new(
        params.secret,
        name,
        CodeOptions::new_or_default(Some(method), params.algorithm, params.digits, params.period),
    ))
}

/// Struct to store the data that can be found in the PARAMETERS section of the URI schema
/// Allows for easier passing between functions
/// Optional data is stored within an option, with secret being the only required parameter
#[derive(Debug)]
struct Params {
    secret: String,
    algorithm: Option<HashFn>,
    digits: Option<u8>,
    counter: Option<u64>,
    period: Option<u32>,
}

/// Parses String data from the parameters field, using RegEx
/// The parameters can be in any order, and are mostly optional
fn parse_params(params: String) -> Result<Params, Box<dyn std::error::Error>> {
    // RegEx to match an individual parameter, all checked separately as the parameters are unordered
    let secret_re = Regex::new(r"(?:^|\?|&)secret=([^&?]+)(?:&|$)").unwrap();
    let algorithm_re = Regex::new(r"(?:^|\?|&)algorithm=(SHA(?:1|256|512))(?:&|$)").unwrap();
    let digits_re = Regex::new(r"(?:^|\?|&)digits=(\d+)(?:&|$)").unwrap();
    let counter_re = Regex::new(r"(?:^|\?|&)counter=(\d+)(?:&|$)").unwrap();
    let period_re = Regex::new(r"(?:^|\?|&)period=(\d+)(?:&|$)").unwrap();

    // 1 is used as the index for the 1st capturing group, as 0 returns the whole string

    // Match the secret in the string, if not present, throw error as is a required field
    let secret = secret_re.captures(&params).ok_or(Error::NoSecret)?[1].to_owned();

    // Map the algorithm string (if present) to its respective enum varient
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

    // If digits value present, parse to u8
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

    // If counter value present, parse to u64
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

    // If period value present, parse to u32
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

    // Return parsed parameters
    Ok(Params {
        secret,
        algorithm,
        digits,
        counter,
        period,
    })
}

/// Error enum to handle errors with QR parsing
#[derive(Debug)]
pub enum Error {
    NoSecret, // No secret was found in QR
    InvalidParamater, // Another paramater is invalid
    Read, // QR could not be read from image
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
