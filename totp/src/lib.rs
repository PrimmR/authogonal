extern crate chrono;
extern crate serde;

use serde::{Deserialize, Serialize};

// Structs used for the whole library
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Key {
    secret: String,
    name: String,
    options: CodeOptions,
}

impl Key {
    pub fn new(secret: String, name: String, options: CodeOptions) -> Self {
        Self {
            secret,
            name,
            options,
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(remote = "hash::HashFn")]
enum HashFnDef {
    SHA1,
    SHA256,
    SHA512,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug)]
pub struct CodeOptions {
    method: otp::OTPMethod,
    #[serde(with = "HashFnDef")]
    hash: hash::HashFn,
    length: u8,
}

impl CodeOptions {
    pub fn new(method: otp::OTPMethod, hash: hash::HashFn, length: u8) -> Self {
        Self {
            method,
            hash,
            length,
        }
    }
}

impl std::default::Default for CodeOptions {
    fn default() -> Self {
        Self {
            method: otp::OTPMethod::TOTP,
            hash: hash::HashFn::SHA1,
            length: 6,
        }
    }
}

pub mod hmac {
    use crate::CodeOptions;
    const IPAD: u8 = 0x36;
    const OPAD: u8 = 0x5c;

    pub fn generate(key: &[u8], message: &[u8], options: CodeOptions) -> Vec<u8> {
        let block_size = options.hash.get_block_size(); // Block size in bytes
                                                        // let output_size = 40; // Always truncated

        let block_sized_key = compute_block_sized_key(key, options, block_size);

        let input_key_pad: Vec<u8> = block_sized_key.iter().map(|x| x ^ IPAD).collect();
        let output_key_pad: Vec<u8> = block_sized_key.iter().map(|x| x ^ OPAD).collect();

        let digest: Vec<u8> = options
            .hash
            .digest(&concat(input_key_pad, message.to_vec()));
        options.hash.digest(&concat(output_key_pad, digest))
    }

    fn compute_block_sized_key(key: &[u8], options: CodeOptions, block_size: usize) -> Vec<u8> {
        if key.len() > block_size {
            options.hash.digest(&key.to_vec())
        } else if key.len() < block_size {
            pad(key, block_size)
        } else {
            key[..].to_vec()
        }
    }

    fn pad(key: &[u8], block_size: usize) -> Vec<u8> {
        // Panics if too large
        let mut pad = key[..].to_vec();
        // Pads to right
        pad.resize(block_size, 0);
        pad
    }

    fn concat(a: Vec<u8>, b: Vec<u8>) -> Vec<u8> {
        vec![a, b].concat()
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn regular_hmac() {
            let mac = generate(b"key", b"Primm", Default::default());
            assert_eq!(
                mac,
                vec![
                    203, 50, 188, 168, 102, 194, 103, 213, 122, 33, 67, 152, 75, 183, 227, 89, 0,
                    149, 161, 215
                ]
            )
        }

        #[test]
        fn empty_hmac() {
            let mac = generate(b"", b"", Default::default());
            assert_eq!(
                mac,
                vec![
                    251, 219, 29, 27, 24, 170, 108, 8, 50, 75, 125, 100, 183, 31, 183, 99, 112,
                    105, 14, 29
                ]
            )
        }

        #[test]
        fn padding_key() {
            assert_eq!(pad(&[20, 82], 8), vec![20, 82, 0, 0, 0, 0, 0, 0]);
        }

        #[test]
        fn padding_key_shrink() {
            assert_eq!(pad(&[20, 82], 1), vec![20]);
        }
    }
}

pub mod otp {
    use std::convert::TryInto;
    use std::str;

    use crate::hmac;
    use crate::Key;
    use chrono::Utc;

    use serde::{Deserialize, Serialize};

    #[derive(Serialize, Deserialize, Clone, Copy, Debug)]
    pub enum OTPMethod {
        TOTP,
        HOTP(u64),
    }

    impl Key {
        fn to_b32(&self) -> Result<Vec<u8>, char> {
            let base32chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
            let upper = self.secret.to_ascii_uppercase();

            upper
                .chars()
                .map(|c| validate(base32chars, c))
                .collect::<Result<(), char>>()?;

            let i = upper.chars().fold(String::new(), |acc, x| {
                acc + format!("{:05b}", base32chars.find(x).unwrap()).as_str()
            });

            let bytes = i.into_bytes();

            Ok(bytes
                .chunks(8)
                .map(|x| {
                    u8::from_str_radix(String::from_utf8(x.to_vec()).unwrap().as_str(), 2).unwrap()
                })
                .collect::<Vec<u8>>())
        }
    }

    fn truncate(mac: &Vec<u8>) -> u32 {
        // Truncation first takes the 4 least significant bits of the MAC and uses them as a byte offset i:
        let lsb = mac[mac.len() - 1] & 0b00001111;
        let extracted = extract31(mac, lsb.into());

        u32::from_be_bytes(extracted)
    }

    fn extract31(mac: &Vec<u8>, i: usize) -> [u8; 4] {
        let mut extract: [u8; 4] = mac[i..i + 4].try_into().unwrap();
        extract[0] &= 0x7F;
        extract
    }

    pub fn validate(string: &str, character: char) -> Result<(), char> {
        if !string.contains(character) {
            Err(character)
        } else {
            Ok(())
        }
    }

    pub fn generate(key: &Key) -> u32 {
        let b32key = key.to_b32().expect("Key contains invalid characters");

        let now = Utc::now();
        let timestep = now.timestamp() / 30;

        let count: u64 = match key.options.method {
            OTPMethod::TOTP => timestep.try_into().unwrap(),
            OTPMethod::HOTP(c) => c,
        };

        let mac = hmac::generate(&b32key[..], &count.to_be_bytes(), key.options);

        let totp = truncate(&mac) % 10_u32.pow(key.options.length.into());

        totp
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn truncation() {
            let mac: Vec<_> = vec![
                239, 175, 55, 150, 38, 85, 24, 149, 68, 234, 249, 243, 110, 126, 48, 57, 73, 119,
                39, 232,
            ];
            assert_eq!(truncate(&mac), 1156250099);
        }

        #[test]
        fn extract_high_unset() {
            let mac: Vec<_> = vec![
                239, 175, 55, 150, 38, 85, 24, 149, 68, 234, 249, 243, 110, 126, 48, 57, 73, 119,
                39, 232,
            ];
            assert_eq!(extract31(&mac, 2), [55, 150, 38, 85]);
        }

        #[test]
        fn extract_high_set() {
            let mac: Vec<_> = vec![
                239, 175, 55, 150, 38, 85, 24, 149, 68, 234, 249, 243, 110, 126, 48, 57, 73, 119,
                39, 232,
            ];
            assert_eq!(extract31(&mac, 10), [121, 243, 110, 126]);
        }

        #[test]
        fn regular_to_b32() {
            let key = Key::new(String::from("Primm"), String::new(), Default::default());
            let expect = vec![0x7c, 0x50, 0xc6, 0x00];
            assert_eq!(key.to_b32().unwrap(), expect)
        }

        #[test]
        fn empty_to_b32() {
            let key = Key::new(String::new(), String::new(), Default::default());
            let expect: Vec<u8> = Vec::new();
            assert_eq!(key.to_b32().unwrap(), expect);
        }

        #[test]
        fn invalid_to_b32() {
            let key = Key::new(String::from("&"), String::new(), Default::default());
            assert_eq!(key.to_b32(), Err('&'));
        }
    }
}

pub mod ui {
    use chrono::Timelike;
    use chrono::Utc;

    use std::sync::mpsc;
    use std::sync::mpsc::Receiver;
    // use std::sync::mpsc::TryRecvError;
    use std::thread;
    use std::time::Duration;

    use crate::otp::generate;
    use crate::Key;

    use eframe::{egui, CreationContext};
    use eframe::egui::Context;

    #[derive(Debug)]
    pub enum OTPMessage {
        Code(u32),
    }

    // Data retained to be displayed
    struct DisplayKey {
        code: u32,
        length: u8,
        name: String,
        thread: Receiver<OTPMessage>,
    }

    impl DisplayKey {
        fn new(name: String, length: u8, thread: Receiver<OTPMessage>) -> Self {
            Self {
                code: 0, // Code updated on thread startup
                length,
                name,
                thread,
            }
        }

        // Converts code to string & gives leading 0s
        fn generate_code_string(&self) -> String {
            let d: usize = self.length.into();
            format!("{:0>d$}", self.code, d = d)
        }
    }

    // 1 thread for each code to generate
    fn spawn_thread(ctx: &Context, key: &Key) -> Receiver<OTPMessage> {
        let (tx, rx) = mpsc::channel::<OTPMessage>();
        let key_clone = key.clone();

        // Generates initial code
        let code = generate(&key_clone);
        tx.send(OTPMessage::Code(code)).unwrap();

        // CTX cheap to clone
        let ctx = ctx.clone();

        thread::spawn(move || loop {
            let now = Utc::now();

            // Allow for different periods   sleep until?
            // Every 'x' seconds, generates new code and sends it to the App thread
            if now.second() == 0 || now.second() == 30 {
                let code = generate(&key_clone);

                if let Ok(_) = tx.send(OTPMessage::Code(code)) {
                    ctx.request_repaint(); // Only called on updates, to prevent CPU overhead
                                           // println!("Sent {}", code)
                }
                thread::sleep(Duration::from_secs(2));
            } else {
                thread::sleep(Duration::from_millis(50));
            }
        });
        rx
    }

    // Create App instance & run
    pub fn gui(keys: Vec<Key>) -> Result<(), eframe::Error> {
        let options = eframe::NativeOptions {
            initial_window_size: Some(egui::vec2(320., 240.)),
            resizable: false,
            centered: true,
            ..Default::default()
        };
        eframe::run_native(
            "TOTP",
            options,
            Box::new(|cc| Box::<App>::new(App::new(cc, keys))),
        )
    }

    struct App {
        keys: Vec<DisplayKey>, // Vec of key data to display
    }

    impl eframe::App for App {
        // Called on interaction / new code
        fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
            self.update_codes();
            self.draw(&ctx);
        }
    }

    impl App {
        // Takes necessary data from Keys and converts into DisplayKey
        fn new(cc: &CreationContext, keys: Vec<Key>) -> Self {
            let key = Key::new(
                String::from("Primm"),
                String::from("Text"),
                Default::default(),
            );
            let thread = spawn_thread(&cc.egui_ctx, &key);

            let dkey = DisplayKey::new(key.name, key.options.length, thread);
            Self { keys: vec![dkey] }
        }

        // When thread updates key, write to App state
        fn update_codes(&mut self) {
            for key in &mut self.keys {
                if let Ok(v) = key.thread.try_recv() {
                    // println!("received {:?}", v);
                    match v {
                        OTPMessage::Code(c) => {
                            key.code = c;
                        }
                    }
                }
            }
        }

        // GUI elements
        fn draw(&mut self, ctx: &egui::Context) {
            egui::CentralPanel::default().show(ctx, |ui| {
                ui.horizontal(|ui| {
                    for key in &self.keys {
                        ui.heading(key.generate_code_string());
                    }
                });
            });
        }
    }
}

pub mod file {
    use crate::Key;
    use std::fs::File;
    use std::path::Path;

    pub fn save(keys: &Vec<Key>) {
        let path = Path::new("keys.txt");
        let file = File::create(path).unwrap();
        serde_json::to_writer_pretty(file, &keys).unwrap();
    }

    pub fn load() -> Vec<Key> {
        if let Ok(f) = File::open("keys.txt") {
            serde_json::from_reader(f).unwrap()
        } else {
            save(&Vec::new());
            Vec::new()
        }
    }
}
