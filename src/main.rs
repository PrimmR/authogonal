extern crate totp;
use totp::display::*;

fn main() {
    let key = "Primm";
    update_display(key);

    //let code = generate(key);
    //println!("OTP: {:0>6}", code);
}
