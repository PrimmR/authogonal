extern crate totp;
use totp::*;

fn main() {
    let keys = file::load();

    let selected = display::display_choice(&keys);
    display::display_key(selected);
}
