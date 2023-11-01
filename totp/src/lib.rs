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
    time: i64,
}

impl Key {
    pub fn new(secret: String, name: String, options: CodeOptions, time: i64) -> Self {
        Self {
            secret,
            name,
            options,
            time,
        }
    }

    fn validate(&self) -> Result<(), String> {
        // Make sure name not empty
        if self.name.len() == 0 {
            return Err(String::from("Name cannot be empty"));
        }

        let secret = &self.secret;

        // Make sure secret at least 2 characters
        if secret.len() <= 1 {
            return Err(String::from("Invalid secret length"));
        }

        let secret = secret.to_ascii_uppercase();
        Self::validate_char(&secret)?;
        Self::validate_len(&secret)?;

        Ok(())
    }

    // Validate that chars in Base-32 set
    fn validate_char(secret: &String) -> Result<(), String> {
        let base32chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        let upper = secret.to_ascii_uppercase();

        if upper.chars().any(|c| !base32chars.contains(c)) {
            return Err(String::from("Invalid character in secret"));
        }
        Ok(())
    }

    // Validate any overflow when converting to b32 just contains 0s
    fn validate_len(secret: &String) -> Result<(), String> {
        let base32chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

        let mut backwards = secret.chars().rev();
        let last = backwards.next().unwrap();
        let penultimate = backwards.next().unwrap();
        let ending_binary = format!(
            "{:05b}{:05b}",
            base32chars.find(penultimate).unwrap(),
            base32chars.find(last).unwrap()
        );

        // The right index to start the check from
        let bit_len = secret.len() * 5;
        let rem_i = bit_len - bit_len / 8 * 8;

        let bits: Vec<char> = ending_binary.chars().collect();
        // Len is always 10, so gives left index
        if bits[10 - rem_i..].iter().any(|b| *b == '1') {
            return Err(String::from("Invalid secret"));
        }
        Ok(())
    }

    pub fn increment(&mut self) {
        file::keys::save_increment(&self);
        self.options.method.increment_counter();
    }
}

impl default::Default for Key {
    fn default() -> Self {
        Self {
            secret: String::from(""),
            name: String::from(""),
            options: CodeOptions::default(),
            time: 0,
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
    interval: u32,
}

impl CodeOptions {
    pub fn new(method: otp::OTPMethod, hash: hash::HashFn, length: u8, interval: u32) -> Self {
        Self {
            method,
            hash,
            length,
            interval,
        }
    }
}

impl std::default::Default for CodeOptions {
    fn default() -> Self {
        Self {
            method: otp::OTPMethod::TOTP,
            hash: hash::HashFn::SHA1,
            length: 6,
            interval: 30,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_validate_empty() {
        Key::new(
            String::from(""),
            String::new(),
            Default::default(),
            Default::default(),
        )
        .validate()
        .unwrap_err();
    }

    #[test]
    fn secret_validate_non_empty() {
        Key::new(
            String::from("7A"),
            String::new(),
            Default::default(),
            Default::default(),
        )
        .validate()
        .unwrap();
    }

    #[test]
    fn secret_validate_invalid_char() {
        Key::validate_char(&String::from("2082")).unwrap_err();
    }

    #[test]
    fn secret_validate_valid_char() {
        Key::validate_char(&String::from("manonam")).unwrap();
    }

    #[test]
    fn secret_validate_invalid_len() {
        // 00000000_1000000
        // ACA
        Key::validate_len(&String::from("ACA")).unwrap_err();
    }

    #[test]
    fn secret_validate_valid_len() {
        // 01111100_01010000_11000110_0
        // Primm
        Key::validate_len(&String::from("PRIMM")).unwrap();
    }

    #[test]
    fn secret_validate_exact_len() {
        // 10010001_11011101_01101000_10111001_11001100
        // Showroom
        Key::validate_len(&String::from("SHOWROOM")).unwrap();
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
        // Validation done when keys entered
        fn to_b32(&self) -> Vec<u8> {
            let base32chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
            let upper = self.secret.to_ascii_uppercase();

            let i = upper.chars().fold(String::new(), |acc, x| {
                acc + format!("{:05b}", base32chars.find(x).unwrap()).as_str()
            });

            let bytes = i.into_bytes();

            bytes
                .chunks(8)
                .map(|x| {
                    u8::from_str_radix(String::from_utf8(x.to_vec()).unwrap().as_str(), 2).unwrap()
                })
                .collect()
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

    pub fn generate(key: &Key) -> u32 {
        let b32key = key.to_b32();

        let now = Utc::now();
        // Timestep updates every interval seconds
        let timestep = now.timestamp() / key.options.interval as i64;

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
            let key = Key::new(
                String::from("Primm"),
                String::new(),
                Default::default(),
                Default::default(),
            );
            let expect = vec![0x7c, 0x50, 0xc6, 0x00];
            assert_eq!(key.to_b32(), expect)
        }
    }
}

mod thread {
    use chrono::Utc;

    use std::sync::mpsc;
    use std::sync::mpsc::{Receiver, Sender};
    use std::thread;
    use std::time::Duration;

    use crate::otp::{generate, OTPMethod};
    use crate::ui::{OTPMessageIn, OTPMessageOut};
    use crate::Key;

    use eframe::egui;

    fn time_to_timestep(interval: u32) -> Duration {
        let now_stamp: u64 = Utc::now().timestamp_millis().try_into().unwrap();
        let interval: u64 = <u32 as Into<u64>>::into(interval) * 1000;
        let next_timestep_stamp = ((now_stamp / interval) + 1) * interval;

        Duration::from_millis(next_timestep_stamp - now_stamp)
    }

    // 1 thread for each code to generate
    pub fn spawn_thread(
        ctx: &egui::Context,
        key: &Key,
    ) -> (Receiver<OTPMessageOut>, Sender<OTPMessageIn>) {
        // Channel for sending codes out
        let (tx_out, rx_out) = mpsc::channel::<OTPMessageOut>();
        // Channel for receiving updates from GUI (only for incrementing counter)
        let (tx_in, rx_in) = mpsc::channel::<OTPMessageIn>();

        let mut key_clone = key.clone();

        // Generates initial code
        let code = generate(&key_clone);
        tx_out.send(OTPMessageOut::Code(code)).unwrap();

        // CTX cheap to clone
        let ctx = ctx.clone();

        match key.options.method {
            OTPMethod::TOTP => {
                thread::spawn(move || loop {
                    let wait = time_to_timestep(key_clone.options.interval);
                    thread::sleep(wait);

                    // Close if recieved message while sleeping
                    if let Ok(r) = rx_in.try_recv() {
                        if let OTPMessageIn::Close = r {
                            break;
                        }
                    }

                    let code = generate(&key_clone);

                    if let Ok(_) = tx_out.send(OTPMessageOut::Code(code)) {
                        ctx.request_repaint(); // Only called on updates, to prevent CPU overhead
                    }
                });
            }
            OTPMethod::HOTP(_) => {
                thread::spawn(move || loop {
                    if let Ok(r) = rx_in.recv() {
                        match r {
                            OTPMessageIn::Increment => {
                                key_clone.increment();
                                let code = generate(&key_clone);
                                if let Ok(_) = tx_out.send(OTPMessageOut::Code(code)) {
                                    ctx.request_repaint();
                                }
                            }
                            OTPMessageIn::Close => break,
                        }
                    }
                });
            }
        }
        (rx_out, tx_in)
    }
}

pub mod ui {
    use chrono::Utc;
    use eframe::egui::RichText;
    use eframe::epaint::Color32;
    use eframe::{egui, CreationContext};
    use serde::{Deserialize, Serialize};
    use std::collections::HashMap;
    use std::sync::mpsc::{Receiver, Sender};

    use crate::file;
    use crate::otp::OTPMethod;
    use crate::thread;
    use crate::Key;

    use sort::merge_sort;

    #[derive(Debug)]
    pub enum OTPMessageOut {
        Code(u32),
    }

    #[derive(Debug)]
    pub enum OTPMessageIn {
        Increment,
        Close,
    }

    // Data retained to be displayed
    #[derive(Clone)]
    struct DisplayKey {
        code: u32,
        length: u8,
        name: String,
        sender: Sender<OTPMessageIn>,
        time: i64,
    }

    impl DisplayKey {
        fn new(name: String, length: u8, sender: Sender<OTPMessageIn>, time: i64) -> Self {
            Self {
                code: 0, // Code updated on thread startup
                length,
                name,
                sender,
                time,
            }
        }

        // Converts code to string & gives leading 0s
        fn generate_code_string(&self, spacer: bool) -> String {
            let d: usize = self.length.into();
            let mut code = format!("{:0>d$}", self.code, d = d);
            // Insert space in centre
            if spacer && code.len() % 2 == 0 {
                code.insert(code.len() / 2, ' ')
            }
            code
        }
    }

    #[derive(PartialEq, Serialize, Deserialize)]
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

    impl Tab {
        fn to_str(&self) -> String {
            match self {
                Self::Main => String::from("Main"),
                Self::Add => String::from("Add"),
                Self::Options => String::from("Options"),
            }
        }
    }

    #[derive(Serialize, Deserialize)]
    pub struct AppOptions {
        sort: SortBy,
        spacer: bool,
    }

    impl Default for AppOptions {
        fn default() -> Self {
            Self {
                sort: Default::default(),
                spacer: true,
            }
        }
    }

    fn generate_display_keys(
        ctx: &egui::Context,
        keys: Vec<Key>,
        sort: &SortBy,
    ) -> (Vec<DisplayKey>, HashMap<String, Receiver<OTPMessageOut>>) {
        let mut display_keys = Vec::new();
        let mut receivers = HashMap::new();

        for key in keys {
            let (key, reciever) = generate_display_key(ctx, &key);
            receivers.insert(key.name.clone(), reciever);
            display_keys.push(key)
        }

        let display_keys = sort_keys(display_keys, sort);
        (display_keys, receivers)
    }

    fn generate_display_key(
        ctx: &egui::Context,
        key: &Key,
    ) -> (DisplayKey, Receiver<OTPMessageOut>) {
        let (receive, send) = thread::spawn_thread(&ctx, &key);
        let display_key =
            DisplayKey::new((key.name).to_string(), key.options.length, send, key.time);

        (display_key, receive)
    }

    fn sort_keys(keys: Vec<DisplayKey>, sort: &SortBy) -> Vec<DisplayKey> {
        match sort {
            SortBy::Date => merge_sort(&keys, |v| v.time),
            SortBy::Name => merge_sort(&keys, |v| v.name.to_uppercase()),
        }
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
        receivers: HashMap<String, Receiver<OTPMessageOut>>, // Threads separate to keys as cannot be cloned - 1-1 relationship between id and thread
        tab: Tab,
        add_key: Key,
        options: AppOptions,
        add_err: String,
        to_delete: Option<DisplayKey>,
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

            // As keys can't be deleted when being iterated, they are done here
            if let Some(k) = &self.to_delete {
                file::keys::remove(&k.name);

                k.sender.send(OTPMessageIn::Close).unwrap();
                self.keys
                    .remove(self.keys.iter().position(|x| x.name == k.name).unwrap());
                self.receivers.remove(&k.name).unwrap();
                self.to_delete = None;
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
                options: file::options::load(),
                tab: Tab::Main,
                add_key: Key::default(),
                add_err: String::new(),
                to_delete: None,
            }
        }

        // When thread updates key, write to App state
        fn update_codes(&mut self) {
            for key in &mut self.keys {
                if let Ok(v) = self.receivers[&key.name].try_recv() {
                    match v {
                        OTPMessageOut::Code(c) => {
                            key.code = c;
                        }
                    }
                }
            }
        }

        //////////////////
        // GUI elements //
        //////////////////
        fn draw_menu(&mut self, ctx: &egui::Context) {
            // Creates clickable labels for each tab that switches window
            macro_rules! menu_tabs {
                ($w:expr, $($x:expr), *) => {
                    let ui = $w;
                    $(
                        if ui.selectable_label(self.tab == $x, $x.to_str()).clicked() {
                            self.tab = $x;
                        }
                    )*
                }
            }

            egui::TopBottomPanel::top("Menu").show(ctx, |ui| {
                ui.horizontal(|ui| {
                    menu_tabs!(ui, Tab::Main, Tab::Add, Tab::Options);
                })
            });
        }

        fn draw_main(&mut self, ctx: &egui::Context) {
            egui::CentralPanel::default().show(ctx, |ui| {
                egui::ScrollArea::vertical().show(ui, |ui| {
                    for key in &self.keys {
                        ui.push_id(&key.name, |ui| {
                            let response = ui
                                .vertical(|ui| {
                                    ui.label(egui::RichText::new(&*key.name).size(20.));
                                    ui.label(
                                        egui::RichText::new(
                                            key.generate_code_string(self.options.spacer),
                                        )
                                        .size(30.)
                                        .strong(),
                                    );
                                    ui.separator();
                                })
                                .response;

                            // No harm if sent to TOTP
                            if response.interact(egui::Sense::click()).clicked() {
                                key.sender.send(OTPMessageIn::Increment).unwrap();
                            }

                            let popup_id = ui.make_persistent_id("my_unique_id");

                            if response.interact(egui::Sense::click()).secondary_clicked() {
                                ui.memory_mut(|mem| mem.toggle_popup(popup_id));
                            }

                            egui::popup::popup_above_or_below_widget(
                                ui,
                                popup_id,
                                &response,
                                egui::AboveOrBelow::Below,
                                |ui| {
                                    ui.set_max_width(20.0); // if you want to control the size
                                    if ui.button("Delete").clicked() {
                                        self.to_delete = Some(key.clone());
                                    }
                                },
                            );
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
                ui.horizontal(|ui| {
                    ui.label("Interval");
                    ui.add(
                        egui::DragValue::new(&mut self.add_key.options.interval)
                            .speed(0.2)
                            .clamp_range(10..=300),
                    );
                });
                ui.label(RichText::new(&self.add_err).color(Color32::RED));
                ui.separator();
                if ui.button("Add").clicked() {
                    // If error: display, else: refresh all fields
                    if let Err(e) = file::keys::add(&self.add_key) {
                        self.add_err = e;
                    } else {
                        self.add_key.time = Utc::now().timestamp();

                        let (key, reciever) = generate_display_key(ctx, &self.add_key);
                        self.receivers.insert(key.name.clone(), reciever);
                        self.keys.push(key);

                        self.add_key = Default::default();
                        self.tab = Tab::Main;
                        self.add_err = String::new();
                    }
                }
            });
        }

        fn draw_options(&mut self, ctx: &egui::Context) {
            egui::CentralPanel::default().show(ctx, |ui| {
                ui.horizontal(|ui| {
                    ui.label("Sort");
                    if ui
                        .radio_value(&mut self.options.sort, SortBy::Date, "Time Added")
                        .clicked()
                        || ui
                            .radio_value(&mut self.options.sort, SortBy::Name, "Name")
                            .clicked()
                    {
                        self.keys = sort_keys(self.keys.clone(), &self.options.sort);
                        file::options::save(&self.options)
                    }
                });
                ui.horizontal(|ui| {
                    let selected = &mut self.options.spacer;
                    ui.label("Spacer");
                    if ui.toggle_value(selected, if *selected { "Enabled" } else { "Disabled" }).clicked() {
                        file::options::save(&self.options)
                    }
                });
            });
        }
    }
}

pub mod file {
    use std::fs::File;
    use std::path::Path;

    const KEYPATH: &str = "keys.txt";
    const SETTINGSPATH: &str = "settings.txt";

    pub mod keys {
        use super::*;
        use crate::Key;

        // Fails if key with name already exists
        pub fn add(key: &Key) -> Result<(), String> {
            key.validate()?;
            let mut load = load();

            // Validation
            if let None = load.iter_mut().find(|k| *k.name == key.name) {
                load.push(key.clone());
                save(&load);
                Ok(())
            } else {
                Err(String::from("A key with that name already exists"))
            }
        }

        // Removes key with name
        pub fn remove(key_name: &String) {
            let mut load = load();
            load.remove(
                load.iter()
                    .position(|k| &k.name == key_name)
                    .expect("Key not found"),
            );
            save(&load);
        }

        fn save(keys: &Vec<Key>) {
            let path = Path::new(KEYPATH);
            let file = File::create(path).unwrap();
            serde_json::to_writer_pretty(file, &keys).unwrap();
        }

        pub fn load() -> Vec<Key> {
            if let Ok(f) = File::open(KEYPATH) {
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

    pub mod options {
        use super::*;
        use crate::ui::AppOptions;

        pub fn save(options: &AppOptions) {
            let path = Path::new(SETTINGSPATH);
            let file = File::create(path).unwrap();
            serde_json::to_writer_pretty(file, &options).unwrap();
        }

        pub fn load() -> AppOptions {
            if let Ok(f) = File::open(SETTINGSPATH) {
                serde_json::from_reader(f).unwrap()
            } else {
                save(&Default::default());
                Default::default()
            }
        }
    }
}
