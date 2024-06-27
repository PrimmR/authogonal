#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")] // hide console window on Windows in release profile

use authogonal::*;

// Executed when the program is run, with all errors propegated through the function using the ? operator
fn main() -> Result<(), eframe::Error> {
    // Create & display the password window
    let e_key = ui::password::gui()?;
    // If there is a key (the user entered their password), create the main window
    // Otherwise the user pressed the window close button, so skip window creation
    if let Some(k) = e_key {
        ui::main::gui(k)?;
    }

    // Return success
    Ok(())
}
