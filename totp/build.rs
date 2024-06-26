use std::env;
use winresource::WindowsResource;

// Applies app icon to Windows release
fn main() -> Result<(), Box<dyn std::error::Error>> {
    if env::var_os("CARGO_CFG_WINDOWS").is_some() {
        WindowsResource::new()
            .set_icon("../icon/Icon.ico")
            .compile()?;
    }

    Ok(())
}
