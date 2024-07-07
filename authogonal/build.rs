use std::env;


// Applies app icon to Windows release
fn main() -> Result<(), Box<dyn std::error::Error>> {
    if env::var_os("CARGO_CFG_WINDOWS").is_some() {
        use winresource::WindowsResource;
        
        WindowsResource::new()
            .set_icon("../icon/Icon.ico")
            .compile()?;
    }

    Ok(())
}
