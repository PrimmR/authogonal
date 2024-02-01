#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")] // hide console window on Windows in release
// Handles creation of windows & passing encryption key between them
// Called upon program execution


extern crate totp;
use totp::*;
fn main() -> Result<(), eframe::Error> {
    let e_key = ui::password::gui()?;
    if let Some(k) = e_key {
        ui::main::gui(k)?;
    }
    Ok(())
}
