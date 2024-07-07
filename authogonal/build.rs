// Applies app icon to Windows release
fn main() -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(target_os = "windows")]
    {
        use winresource::WindowsResource;

        WindowsResource::new()
            .set_icon("../icon/Icon.ico")
            .compile()?;
    }

    Ok(())
}
