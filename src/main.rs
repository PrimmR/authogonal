extern crate totp;
use totp::totp::*;

fn main() {
    let key = "Primm";

    let code = generate(key);

    println!("OTP: {:0>6}", code);
}
