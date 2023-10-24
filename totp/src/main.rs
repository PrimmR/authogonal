extern crate totp;
use totp::*;

fn main() -> Result<(), eframe::Error>{
    let keys = file::load();
    ui::gui(keys)
}
