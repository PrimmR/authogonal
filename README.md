<h1 align="center">
    <picture>
        <img height="256px" style="margin: 0; padding: 0" src="./icon/Banner.svg">
    </picture>
</h1>

*Disclaimer: this application is a proof of concept and has not been tested for true security, use at your own risk*  

This is a small app that will generate One Time Password authentication codes, which can be used with a variety of online services to verify your identity, often used as a form of 2 Factor Authentication. This application supports both time-based and counter-based passwords, as well as different code lengths, hash functions, and time intervals. The data required to generate the codes for a specific service can either be added manually through text, or through a QR code saved as an image.

This project was made to demonstrate programming ability, so I have implemented several features that are already available in common crates or the standard library. These crates are available in this repo using Rust's workspace feature, but these crates only have enough functionality to work for the main application. An exception to this is for file encryption, where the [aes_gcm crate](https://docs.rs/aes-gcm/latest/aes_gcm/) is used to ensure some layer of security.

## Install

The application is available for Windows, macOS, and Linux, and can be found under the releases tab. The app creates 2 files to save its data, so I recommend keeping the app in its own directory.

### Windows

Download the executable file and run it by double-clicking. Except for any smart screen complaints, this is all you should need to do.

### macOS

Firstly, download the app file and copy it into the system's `Applications` folder (it will not work when run from `Desktop` or `Downloads`).

Then, because I don't have an Apple developer account, macs will try their hardest to prevent the app from running. To circumvent this, you will need to navigate to the `Security & Privacy` menu in System Preferences after attempting to run it, and then choose the `Open Anyway` option next to the message stating that the app has been blocked. You should only have to do this once.

Alternatively, you can build and run the application from source to avoid having to do this, which will also give the application permission to be executed from anywhere.

### Linux

Once downloaded, make sure you have executable permissions for the file, using either `chmod` or the file browser UI. Then you should be able to execute the executable as usual, either by double-clicking or by using the terminal.

## Usage

When you run the application, you will be prompted for a password. On your first time, the password you enter will be set, and it is used to decrypt all important saved data on subsequent uses of the app. To change your password to a new one, please use the `Set as new password` button, which will delete all saved data.

To add a new service that codes will be generated for, navigate to the `Add` tab. If you have been given a secret in text form, fill out the necessary fields (if you're unsure, most services use the default options), including giving it an appropriate name. Then add it to the main tab using the `Add` button.  
Alternatively, if you've been given a QR code, download the image to your machine, then use the `Add From QR` button to select the QR code to add.

The `Main` tab displays the current code that corresponds to each registered service. If the code is time-based (TOTP), a countdown bar will be visible, indicating the time until the code next updates. If the code is counter-based (HOTP), the counter and code can be updated by left clicking it. A context menu is available for each service, allowing the current code to be copied to the machine's clipboard, or for the service to be removed from the application.

A small number of user preferences are available under the `Options` tab:  
`Sort By` affects the order of codes on the main tab
`Spacer` decides whether a space should be present in the middle of even-length codes to improve readability  
`Accent` decides the main colour used by the user interface

## Issues

As this project has served its primary purpose, I'm unlikely to add new feature requests to the app, however if there are any bugs or issues that have been overlooked, please raise an issue in the issue tracker.

## Build

Firstly, [install Rust](https://www.rust-lang.org/tools/install).

### Windows & Linux

In the root of this repo, run:  
`cargo build --release`

The resulting binary can then be found in `target/release/`.

### MacOS

To correctly build the app file, you will need [cargo-bundle](https://github.com/burtonageo/cargo-bundle), which can be installed with `cargo install cargo-bundle`.

Then, in the `authogonal` directory, run:  
`cargo bundle --release`

The resulting app file can then be found in `target/release/bundle/osx/`.