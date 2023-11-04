extern crate totp;
use totp::*;

fn main() -> Result<(), eframe::Error> {
    let e_key = ui::password::gui()?;
    if let Some(k) = e_key {
        ui::main::gui(k)?;
    }
    Ok(())
}
