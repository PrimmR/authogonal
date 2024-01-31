mod file;
mod hmac;
mod key;
mod otp;
mod qr;
mod thread;

// GUI
pub mod ui {
    use crate::file;
    use eframe::egui::RichText;
    use eframe::epaint::Color32;
    use eframe::{egui, CreationContext};
    use encrypt::EncryptionKey;

    // Code for main window
    pub mod main {
        use super::*;

        use chrono::Utc;
        use hash_table::hash_map::HashMap;
        use serde::{Deserialize, Serialize};
        use std::sync::mpsc::{Receiver, Sender};

        use crate::key::Key;
        use crate::otp::OTPMethod;
        use crate::qr;
        use crate::thread;
        use sort::merge_sort;

        // Message from thread -> app
        #[derive(Debug)]
        pub enum OTPMessageOut {
            Code(u32), // Code to display
        }

        // Message from app -> thread
        #[derive(Debug)]
        pub enum OTPMessageIn {
            Increment(encrypt::EncryptionKey), // HOTP count should be incremented & saved (w/ encryption key)
            Close, // Key has been deleted, so thread needs to be closed
        }

        /// Acts as a stripped down version of [Key] 
        /// Held by the app instance to be used to display a code
        #[derive(Clone)]
        struct DisplayKey {
            code: u32,
            length: u8,
            name: String,
            sender: Sender<OTPMessageIn>, // Additionally stores a sender to act as a link between application and an individual key's thread
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

            // Converts code to String to be displayed
            fn generate_code_string(&self, spacer: bool) -> String {
                // Converts self.length into usize to be used as a length
                let d: usize = self.length.into();
                // Creates a string of a d length representation of the self.code, padded with leading 0s if necessary
                let mut code = format!("{:0>d$}", self.code, d = d);
                // Insert space in centre if requested and the length is of an even number
                if spacer && code.len() % 2 == 0 {
                    code.insert(code.len() / 2, ' ')
                }
                code
            }
        }

        /// An enum to represent a choice of how to sort codes when displayed to the user
        #[derive(PartialEq, Serialize, Deserialize)]
        enum SortBy {
            Date, // Oldest one added will have lowest id, so displayed first
            Name, // Displayed alphabetically ascending
        }

        impl Default for SortBy {
            fn default() -> Self {
                Self::Date
            }
        }

        /// This enum represents the different tabs that are available in the GUI
        #[derive(PartialEq)]
        enum Tab {
            Main,
            Add,
            Options,
        }

        impl Tab {
            // To allow the tab name drawn to the GUI procedurally (using the menu_tabs! macro)
            fn to_str(&self) -> String {
                match self {
                    Self::Main => String::from("Main"),
                    Self::Add => String::from("Add"),
                    Self::Options => String::from("Options"),
                }
            }
        }

        /// This struct is held in app memory and stores all the user's preferences about the program
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

        // Creates threads and display keys for each key
        fn generate_display_keys(
            ctx: &egui::Context,
            keys: Vec<Key>,
            sort: &SortBy,
        ) -> (Vec<DisplayKey>, HashMap<String, Receiver<OTPMessageOut>>) {
            let mut display_keys = Vec::new();
            // Hashmap size static during runtime, as many new keys are unlikely to be added at once
            let mut receivers = HashMap::new_with_size(keys.len() + 8);

            for key in keys {
                let (key, reciever) = generate_display_key(ctx, &key);
                receivers.insert(key.name.clone(), reciever);
                display_keys.push(key)
            }

            let display_keys = sort_keys(display_keys, sort);
            (display_keys, receivers)
        }

        // Creates a thread and display key for a key (discards unnecessary fields from key)
        fn generate_display_key(
            ctx: &egui::Context,
            key: &Key,
        ) -> (DisplayKey, Receiver<OTPMessageOut>) {
            let (receive, send) = thread::spawn_thread(&ctx, &key);
            let display_key =
                DisplayKey::new((key.name).to_string(), key.options.length, send, key.time);

            (display_key, receive)
        }

        // Sorts using merge sort based on user choice
        fn sort_keys(keys: Vec<DisplayKey>, sort: &SortBy) -> Vec<DisplayKey> {
            match sort {
                SortBy::Date => merge_sort(&keys, |v| v.time),
                SortBy::Name => merge_sort(&keys, |v| v.name.to_uppercase()),
            }
        }

        // Create App instance & run
        pub fn gui(encryption_key: EncryptionKey) -> Result<(), eframe::Error> {
            let options = eframe::NativeOptions {
                viewport: egui::ViewportBuilder::default()
                    .with_inner_size(egui::vec2(320., 342.))
                    .with_resizable(false),
                centered: true,
                ..Default::default()
            };
            eframe::run_native(
                "TOTP",
                options,
                Box::new(move |cc| Box::<App>::new(App::new(cc, encryption_key))),
            )
        }

        /// Controls the function and state of the GUI
        struct App {
            encryption_key: EncryptionKey,
            keys: Vec<DisplayKey>,
            receivers: HashMap<String, Receiver<OTPMessageOut>>, // Threads separate to keys as cannot be cloned - 1-1 relationship between id and thread
            tab: Tab,
            add_key: Key,
            options: AppOptions,
            add_err: String,
            to_delete: Option<DisplayKey>,
        }

        impl eframe::App for App {
            // Called on user interaction / new code
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
                    file::keys::remove(&k.name, &self.encryption_key);

                    k.sender.send(OTPMessageIn::Close).unwrap();
                    self.keys
                        .remove(self.keys.iter().position(|x| x.name == k.name).unwrap());
                    self.receivers.remove(&k.name);
                    self.to_delete = None;
                }
            }
        }

        impl App {
            // Takes necessary data from Keys and converts into DisplayKey
            fn new(cc: &CreationContext, encryption_key: EncryptionKey) -> Self {
                let keys = file::keys::load(&encryption_key);
                let (display_keys, receivers) =
                    generate_display_keys(&cc.egui_ctx, keys, &Default::default());
                Self {
                    encryption_key,
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
                    if let Ok(v) = self.receivers.get(&key.name).unwrap().try_recv() {
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
                                    key.sender
                                        .send(OTPMessageIn::Increment(self.encryption_key.clone()))
                                        .unwrap();
                                }

                                let popup_id = ui.make_persistent_id("DEL");

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
                        ui.radio_value(
                            &mut self.add_key.options.method,
                            OTPMethod::HOTP(0),
                            "HOTP",
                        );
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
                    ui.vertical_centered(|ui| {
                        ui.label(RichText::new(&self.add_err).color(Color32::RED))
                    });

                    ui.separator();
                    ui.horizontal(|ui| {
                        if ui.button("Add").clicked() {
                            self.add_key.time = Utc::now().timestamp();

                            // If the key is valid: display, else: refresh all fields
                            if let Err(e) = file::keys::add(&self.add_key, &self.encryption_key) {
                                self.add_err = e;
                            } else {
                                let (key, reciever) = generate_display_key(ctx, &self.add_key);
                                self.receivers.insert(key.name.clone(), reciever);
                                self.keys.push(key);

                                self.add_key = Default::default();
                                self.tab = Tab::Main;
                                self.add_err = String::new();
                            }
                        };

                        if ui.button("Add From QR").clicked() {
                            // Ignore if dialogue just closed
                            if let Some(path) = rfd::FileDialog::new().pick_file() {
                                // If parsed QR correct: add, if not: throw error
                                if let Ok(key) = qr::parse(path) {
                                    // Make sure the key itself is valid
                                    if let Err(e) = file::keys::add(&key, &self.encryption_key) {
                                        self.add_err = e;
                                    } else {
                                        let (key, reciever) = generate_display_key(ctx, &key);
                                        self.receivers.insert(key.name.clone(), reciever);
                                        self.keys.push(key);

                                        self.add_key = Default::default();
                                        self.tab = Tab::Main;
                                        self.add_err = String::new();
                                    }
                                } else {
                                    self.add_err = String::from("Could not parse QR")
                                }
                            }
                        };
                    });
                });
            }

            fn draw_options(&mut self, ctx: &egui::Context) {
                egui::CentralPanel::default().show(ctx, |ui| {
                    ui.horizontal(|ui| {
                        ui.label("Sort By");
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
                        if ui
                            .toggle_value(selected, if *selected { "Enabled" } else { "Disabled" })
                            .clicked()
                        {
                            file::options::save(&self.options)
                        }
                    });
                });
            }
        }
    }

    pub mod password {
        use std::cell::RefCell;
        use std::path::Path;
        use std::rc::Rc;

        use super::*;

        // Create App instance & run
        // This app takes input, validates the password, then passes the encryption key to the main app through main.rs
        pub fn gui() -> Result<Option<EncryptionKey>, eframe::Error> {
            let options = eframe::NativeOptions {
                viewport: egui::ViewportBuilder::default()
                    .with_inner_size(egui::vec2(320., 160.))
                    .with_resizable(false),
                centered: true,
                ..Default::default()
            };

            let encryption_key = Rc::new(RefCell::new(None));
            let encryption_key_clone = encryption_key.clone();

            {
                eframe::run_native(
                    "TOTP",
                    options,
                    Box::new(|_cc| Box::<App>::new(App::new(encryption_key_clone))),
                )?;
            }

            // No chance of panicing, as this code is run after app is dropped
            let out_ref_c = encryption_key.borrow();

            // Return Option<e_key>
            Ok(*out_ref_c)
        }

        struct App {
            // Password not kept in memory, only the hash is
            encryption_key: Rc<RefCell<Option<EncryptionKey>>>, // Allows for the string to have multiple references + be interior mutable
            password_field: String,
            error: String,
        }

        impl eframe::App for App {
            fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
                egui::CentralPanel::default().show(ctx, |ui| {
                    ui.label("Please enter a password");
                    ui.text_edit_singleline(&mut self.password_field);
                    ui.vertical_centered(|ui| {
                        ui.label(RichText::new(&self.error).color(Color32::RED))
                    });
                    ui.separator();

                    ui.horizontal(|ui| {
                        if ui.button("Enter").clicked() {
                            let path = Path::new(crate::file::KEYPATH);
                            let e_key = encrypt::password_to_key(&self.password_field);

                            if let Err(e) = encrypt::load(path, &e_key) {
                                self.error =
                                    if let encrypt::Error::ReadError = *(e.downcast().unwrap()) {
                                        String::from("Incorrect password")
                                    } else {
                                        String::from("An error occurred")
                                    }
                            } else {
                                *(*self.encryption_key).borrow_mut() = Some(e_key);
                                ctx.send_viewport_cmd(egui::ViewportCommand::Close)
                            }
                        }
                        let response = ui
                            .button("Set as new password")
                            .on_hover_text("Warning, this will delete all currently stored codes");
                        if response.clicked() {
                            // Deletes all old codes so new key can be used
                            file::keys::delete_all(&encrypt::password_to_key(&self.password_field));
                            *(*self.encryption_key).borrow_mut() =
                                Some(encrypt::password_to_key(&self.password_field));
                            ctx.send_viewport_cmd(egui::ViewportCommand::Close)
                        }
                    })
                });
            }
        }

        impl App {
            fn new(encryption_key: Rc<RefCell<Option<EncryptionKey>>>) -> Self {
                Self {
                    encryption_key,
                    password_field: String::new(),
                    error: String::new(),
                }
            }
        }
    }
}
