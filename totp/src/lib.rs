extern crate chrono;
extern crate serde;

use std::default;

use serde::{Deserialize, Serialize};

// Structs used for the whole library
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
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

    pub fn increment(&mut self) {
        file::save_increment(&self);
        self.options.method.increment_counter();
    }
}

impl default::Default for Key {
    fn default() -> Self {
        Self {
            secret: String::from(""),
            name: String::from(""),
            options: CodeOptions::default(),
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

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
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

    #[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
    pub enum OTPMethod {
        TOTP,
        HOTP(u64),
    }

    impl OTPMethod {
        pub fn increment_counter(&mut self) {
            match self {
                Self::HOTP(ref mut c) => *c += 1,
                Self::TOTP => (),
            }
        }
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
    use std::collections::HashMap;

    use std::sync::mpsc;
    use std::sync::mpsc::{Receiver, Sender};
    use std::thread;
    use std::time::Duration;

    use crate::file;
    use crate::otp::generate;
    use crate::otp::OTPMethod;
    use crate::Key;

    use eframe::{egui, CreationContext};

    use sort::merge_sort;

    #[derive(Debug)]
    pub enum OTPMessageOut {
        Code(u32),
    }

    #[derive(Debug)]
    pub enum OTPMessageIn {
        Increment,
    }

    // Data retained to be displayed
    #[derive(Clone)]
    struct DisplayKey {
        id: usize,
        code: u32,
        length: u8,
        name: String,
        sender: Option<Sender<OTPMessageIn>>,
    }

    impl DisplayKey {
        fn new(id: usize, name: String, length: u8, sender: Option<Sender<OTPMessageIn>>) -> Self {
            Self {
                id,
                code: 0, // Code updated on thread startup
                length,
                name,
                sender,
            }
        }

        // Converts code to string & gives leading 0s
        fn generate_code_string(&self) -> String {
            let d: usize = self.length.into();
            let mut code = format!("{:0>d$}", self.code, d = d);
            // Insert space in centre
            if code.len() % 2 == 0 {
                code.insert(code.len() / 2, ' ')
            }
            code
        }
    }

    #[derive(PartialEq)]
    enum SortBy {
        Date, // Oldest one added will have lowest id
        Name,
    }

    impl Default for SortBy {
        fn default() -> Self {
            Self::Date
        }
    }

    #[derive(PartialEq)]
    enum Tab {
        Main,
        Add,
        Options,
    }

    #[derive(Default)]
    struct AppOptions {
        sort: SortBy,
    }

    // 1 thread for each code to generate
    fn spawn_thread(
        ctx: &egui::Context,
        key: &Key,
    ) -> (Receiver<OTPMessageOut>, Option<Sender<OTPMessageIn>>) {
        // Channel for sending codes out
        let (tx_out, rx_out) = mpsc::channel::<OTPMessageOut>();
        // Channel for receiving updates from GUI (only for incrementing counter)
        let (tx_in, rx_in) = if let OTPMethod::HOTP(_) = key.options.method {
            let (t, r) = mpsc::channel::<OTPMessageIn>();
            (Some(t), Some(r))
        } else {
            (None, None)
        };

        let mut key_clone = key.clone();

        // Generates initial code
        let code = generate(&key_clone);
        tx_out.send(OTPMessageOut::Code(code)).unwrap();

        // CTX cheap to clone
        let ctx = ctx.clone();

        match key.options.method {
            OTPMethod::TOTP => {
                thread::spawn(move || loop {
                    let now = Utc::now();

                    // Allow for different periods   sleep until?
                    // Every 'x' seconds, generates new code and sends it to the App thread
                    if now.second() == 0 || now.second() == 30 {
                        let code = generate(&key_clone);

                        if let Ok(_) = tx_out.send(OTPMessageOut::Code(code)) {
                            ctx.request_repaint(); // Only called on updates, to prevent CPU overhead
                                                   // println!("Sent {}", code)
                        }
                        thread::sleep(Duration::from_secs(2));
                    } else {
                        thread::sleep(Duration::from_millis(50));
                    }
                });
            }
            OTPMethod::HOTP(_) => {
                thread::spawn(move || loop {
                    if let Some(r) = &rx_in {
                        if let Ok(r) = r.recv() {
                            match r {
                                OTPMessageIn::Increment => {
                                    key_clone.increment();
                                    let code = generate(&key_clone);
                                    if let Ok(_) = tx_out.send(OTPMessageOut::Code(code)) {
                                        ctx.request_repaint();
                                    }
                                }
                            }
                        }
                    }
                });
            }
        }
        (rx_out, tx_in)
    }

    fn generate_display_keys(
        ctx: &egui::Context,
        keys: Vec<Key>,
        sort: &SortBy,
    ) -> (Vec<DisplayKey>, HashMap<usize, Receiver<OTPMessageOut>>) {
        let mut i = 0;
        let mut display_keys = Vec::new();
        let mut receivers = HashMap::new();

        for key in keys {
            i += 1;

            let (receive, send) = spawn_thread(&ctx, &key);

            display_keys.push(DisplayKey::new(
                i,
                (key.name).to_string(),
                key.options.length,
                send,
            ));
            receivers.insert(i, receive);
        }

        let display_keys = match sort {
            SortBy::Date => merge_sort(&display_keys, |v| v.id),
            SortBy::Name => merge_sort(&display_keys, |v| v.name.clone()),
        };
        (display_keys, receivers)
    }

    // Create App instance & run
    pub fn gui(keys: Vec<Key>) -> Result<(), eframe::Error> {
        let options = eframe::NativeOptions {
            initial_window_size: Some(egui::vec2(320., 342.)),
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
        keys: Vec<DisplayKey>,
        receivers: HashMap<usize, Receiver<OTPMessageOut>>, // Threads separate to keys as cannot be cloned - 1-1 relationship between id and thread
        tab: Tab,
        add_key: Key,
        options: AppOptions,
    }

    impl eframe::App for App {
        // Called on interaction / new code
        fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
            self.update_codes();
            self.draw_menu(&ctx);
            match self.tab {
                Tab::Main => self.draw_main(&ctx),
                Tab::Add => self.draw_add(&ctx),
                Tab::Options => self.draw_options(&ctx),
            }
        }
    }

    impl App {
        // Takes necessary data from Keys and converts into DisplayKey
        fn new(cc: &CreationContext, keys: Vec<Key>) -> Self {
            let (display_keys, receivers) =
                generate_display_keys(&cc.egui_ctx, keys, &Default::default());
            Self {
                keys: display_keys,
                receivers,
                options: Default::default(),
                tab: Tab::Main,
                add_key: Key::default(),
            }
        }

        // When thread updates key, write to App state
        fn update_codes(&mut self) {
            for key in &mut self.keys {
                if let Ok(v) = self.receivers[&key.id].try_recv() {
                    // println!("received {:?}", v);
                    match v {
                        OTPMessageOut::Code(c) => {
                            key.code = c;
                        }
                    }
                }
            }
        }

        // GUI elements
        fn draw_menu(&mut self, ctx: &egui::Context) {
            egui::TopBottomPanel::top("Menu").show(ctx, |ui| {
                ui.horizontal(|ui| {
                    // Make into macro?
                    if ui.selectable_label(self.tab == Tab::Main, "Main").clicked() {
                        self.tab = Tab::Main;
                    }
                    if ui.selectable_label(self.tab == Tab::Add, "Add").clicked() {
                        self.tab = Tab::Add;
                    }
                    if ui
                        .selectable_label(self.tab == Tab::Options, "Options")
                        .clicked()
                    {
                        self.tab = Tab::Options;
                    }
                })
            });
        }

        fn draw_main(&mut self, ctx: &egui::Context) {
            egui::CentralPanel::default().show(ctx, |ui| {
                egui::ScrollArea::vertical().show(ui, |ui| {
                    for key in &self.keys {
                        ui.push_id(key.id, |ui| {
                            let response = ui
                                .vertical(|ui| {
                                    ui.label(egui::RichText::new(&*key.name).size(20.));
                                    ui.label(
                                        egui::RichText::new(key.generate_code_string())
                                            .size(30.)
                                            .strong(),
                                    );
                                    ui.separator();
                                })
                                .response;

                            if let Some(s) = &key.sender {
                                if response.interact(egui::Sense::click()).clicked() {
                                    s.send(OTPMessageIn::Increment).unwrap();
                                }
                            }
                        });
                    }
                });
            });
        }

        fn draw_add(&mut self, ctx: &egui::Context) {
            egui::CentralPanel::default().show(ctx, |ui| {
                ui.horizontal(|ui| {
                    ui.label("Secret");
                    ui.text_edit_singleline(&mut self.add_key.secret);
                });
                ui.horizontal(|ui| {
                    ui.label("Name ");
                    ui.text_edit_singleline(&mut self.add_key.name);
                });
                ui.horizontal(|ui| {
                    ui.label("Method");
                    ui.radio_value(&mut self.add_key.options.method, OTPMethod::TOTP, "TOTP");
                    ui.radio_value(&mut self.add_key.options.method, OTPMethod::HOTP(0), "HOTP");
                });
                ui.horizontal(|ui| {
                    ui.label("Length  ");
                    ui.radio_value(&mut self.add_key.options.length, 4, "4");
                    ui.radio_value(&mut self.add_key.options.length, 5, "5");
                    ui.radio_value(&mut self.add_key.options.length, 6, "6");
                });
                ui.horizontal(|ui| {
                    ui.label("Hash Fn ");
                    ui.radio_value(&mut self.add_key.options.hash, hash::HashFn::SHA1, "SHA1");
                    ui.radio_value(
                        &mut self.add_key.options.hash,
                        hash::HashFn::SHA256,
                        "SHA256",
                    );
                    ui.radio_value(
                        &mut self.add_key.options.hash,
                        hash::HashFn::SHA512,
                        "SHA512",
                    );
                });
                ui.separator();
                if ui.button("Add").clicked() {
                    file::add(&self.add_key);
                    (self.keys, self.receivers) =
                        generate_display_keys(&ctx, file::load(), &self.options.sort);
                    self.add_key = Default::default();
                    self.tab = Tab::Main;
                }
            });
        }

        fn draw_options(&mut self, ctx: &egui::Context) {
            egui::CentralPanel::default().show(ctx, |ui| {
                ui.horizontal(|ui| {
                    ui.label("Sort");
                    if ui
                        .radio_value(&mut self.options.sort, SortBy::Date, "Date Added")
                        .clicked()
                        || ui
                            .radio_value(&mut self.options.sort, SortBy::Name, "Name")
                            .clicked()
                    {
                        (self.keys, self.receivers) =
                            generate_display_keys(&ctx, file::load(), &self.options.sort);
                    }
                })
            });
        }
    }
}

pub mod file {
    use crate::Key;
    use std::fs::File;
    use std::path::Path;

    pub fn add(key: &Key) {
        let mut load = load();
        load.push(key.clone());
        save(&load);
    }

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

    pub fn save_increment(key: &Key) {
        let mut keys = load();
        if let Some(k) = keys.iter_mut().find(|k| *k == key) {
            (*k).options.method.increment_counter();
            save(&keys)
        }
    }
}
