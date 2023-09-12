extern crate totp;
use totp::*;

fn main() {
    let keys = file::load();

    // file::save(keys);

    display::display_key(keys[0].clone());

    //let code = generate(key);
    //println!("OTP: {:0>6}", code);
}
