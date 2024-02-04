// Collate external modules into library
mod file;
mod hmac;
mod key;
mod otp;
mod qr;
mod thread;

/// GUI related module
pub mod ui {
    use crate::file;
    use eframe::egui::RichText;
    use eframe::epaint::Color32;
    use eframe::{egui, CreationContext};
    use encrypt::EncryptionKey;

    /// Handles the main window
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
            Close,                             // Key has been deleted, so thread needs to be closed
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

        /// Creates [DisplayKey]s for each key, initialising threads and using a [HashMap] to store the Receivers (as they can't be cloned)
        fn generate_display_keys(
            ctx: &egui::Context,
            keys: Vec<Key>,
            sort: &SortBy,
        ) -> (Vec<DisplayKey>, HashMap<String, Receiver<OTPMessageOut>>) {
            let mut display_keys = Vec::new();
            // Hashmap size static during runtime, as many new keys are unlikely to be added at once
            let mut receivers = HashMap::new_with_size(keys.len() + 8);

            // Iterate through all keys, generating a DisplayKey and Receiver and adding it to its respective data structure
            for key in keys {
                let (key, receiver) = generate_display_key(ctx, &key);
                receivers.insert(key.name.clone(), receiver);
                display_keys.push(key)
            }
            // Original Keys go out of scope here, being dropped from memory

            // Sort the keys based on the user's sort preference, then return
            let display_keys = sort_keys(display_keys, sort);
            (display_keys, receivers)
        }

        /// Spawns a thread and creates a [DisplayKey] for a given [Key], discarding fields that aren't necessary for the [App] itself to store
        fn generate_display_key(
            ctx: &egui::Context,
            key: &Key,
        ) -> (DisplayKey, Receiver<OTPMessageOut>) {
            // Spawns a thread from the key and saves the Receiver and Sender for 2 way messaging
            let (receive, send) = thread::spawn_thread(&ctx, &key);
            // Creates new display key from attributes of the key
            let display_key =
                DisplayKey::new((key.name).to_string(), key.options.length, send, key.time);

            (display_key, receive)
        }

        /// Sorts using merge sort based on user choice
        fn sort_keys(keys: Vec<DisplayKey>, sort: &SortBy) -> Vec<DisplayKey> {
            // Passes in a different closure (first citizen function) to change how the list is sorted, using the merge_sort crate
            match sort {
                SortBy::Date => merge_sort(&keys, |v| v.time),
                SortBy::Name => merge_sort(&keys, |v| v.name.to_uppercase()),
            }
        }

        /// Creates App instance for the main window
        pub fn gui(encryption_key: EncryptionKey) -> Result<(), eframe::Error> {
            // App is 320 by 342 and isn't resizable
            // 342px height allows for 4 codes to be displayed without needing to scroll
            let options = eframe::NativeOptions {
                viewport: egui::ViewportBuilder::default()
                    .with_inner_size(egui::vec2(320., 342.))
                    .with_resizable(false),
                centered: true,
                ..Default::default()
            };
            eframe::run_native(
                "TOTP", // Window title
                options,
                Box::new(move |cc| Box::<App>::new(App::new(cc, encryption_key))),
            )
        }

        /// Controls the function and state of the main app GUI
        struct App {
            encryption_key: EncryptionKey,
            keys: Vec<DisplayKey>,
            receivers: HashMap<String, Receiver<OTPMessageOut>>, // Thread receivers separate to keys as cannot be cloned - 1-1 relationship between name and thread, as name unique
            tab: Tab,
            add_key: Key,
            options: AppOptions,
            add_err: String,
            to_delete: Option<DisplayKey>,
        }

        impl eframe::App for App {
            /// Called on user interaction / new code being received
            fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
                // Updates any codes that have been messaged in by other threads
                self.update_codes();
                // Draws tab bar (as always present)
                self.draw_menu(&ctx);
                // Draws correct window body, depending on which tab is currently selected
                match self.tab {
                    Tab::Main => self.draw_main(&ctx),
                    Tab::Add => self.draw_add(&ctx),
                    Tab::Options => self.draw_options(&ctx),
                }

                // As keys can't be deleted when being iterated through, they are saved in to_delete attribute and done here
                if let Some(k) = &self.to_delete {
                    file::keys::remove(&k.name, &self.encryption_key);

                    // Request the respective thread to close, otherwise it would continue running, unnecessarily using system resources
                    k.sender.send(OTPMessageIn::Close).unwrap();
                    // Remove from internal state
                    self.keys
                        .remove(self.keys.iter().position(|x| x.name == k.name).unwrap());
                    self.receivers.remove(&k.name);
                    // Resets attribute so key isn't attempted to be deleted twice
                    self.to_delete = None;
                }
            }
        }

        impl App {
            /// Create App window - Loading key data from Keys file using encryption key parameter
            fn new(cc: &CreationContext, encryption_key: EncryptionKey) -> Self {
                // Loads the options file
                let options = file::options::load();

                // Loads keys and converts them into display keys
                let keys = file::keys::load(&encryption_key);
                let (display_keys, receivers) =
                    generate_display_keys(&cc.egui_ctx, keys, &options.sort);

                // Returns App type with loaded keys and options, other attributes are set to default
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

            /// Handle receiving keys from threads
            fn update_codes(&mut self) {
                // Iterate through all keys, checking to see if any have data to receive
                for key in &mut self.keys {
                    if let Ok(v) = self.receivers.get(&key.name).unwrap().try_recv() {
                        match v {
                            OTPMessageOut::Code(c) => {
                                // If a code is received, update the key's old code with the new one
                                key.code = c;
                            }
                        }
                    }
                }
            }

            //////////////////
            // GUI elements //
            //////////////////

            /// Draw the tab bar to the window
            /// This is always called, as the tab bar is always displayed
            /// The currently selected tab is highlighted in blue
            fn draw_menu(&mut self, ctx: &egui::Context) {
                /// Macro to procedurely generate code that creates clickable buttons for each of the tabs
                // Defined within the function implementation so that self can refer to the app
                macro_rules! menu_tabs {
                    // $w is the UI, which is required to draw to the window
                    // $($x:expr), * is 0 or more occurrences of tabs to display in the tab bar - drawn in order of occurrence
                    ($w:expr, $($x:expr), *) => {
                        let ui = $w;
                        $(
                            // For each tab entered, create a button (selectable label), that is highlighted if the current tab is itself, and switches the app's tab to its own when clicked
                            if ui.selectable_label(self.tab == $x, $x.to_str()).clicked() {
                                self.tab = $x;
                            }
                        )*
                    }
                }

                // Create top panel with id Menu and call the macro defined above to draw tabs to the tab bar
                egui::TopBottomPanel::top("Menu").show(ctx, |ui| {
                    ui.horizontal(|ui| {
                        menu_tabs!(ui, Tab::Main, Tab::Add, Tab::Options);
                    })
                });
            }

            /// Draw the main tab to the window
            fn draw_main(&mut self, ctx: &egui::Context) {
                egui::CentralPanel::default().show(ctx, |ui| {
                    // Allow for scrolling
                    egui::ScrollArea::vertical().show(ui, |ui| {
                        // Iterate through keys
                        for key in &self.keys {
                            // Uses key name as internal ID to keep track of which element has been clicked
                            ui.push_id(&key.name, |ui| {
                                let response = ui // Draw individual key to screen & bind to any interactions (clicks) that occur
                                    .vertical(|ui| {
                                        ui.label(egui::RichText::new(&*key.name).size(20.)); // Display name
                                        ui.label(
                                            // Display code in bold and large text size, using the generate_code_string to get the code as a string
                                            egui::RichText::new(
                                                key.generate_code_string(self.options.spacer),
                                            )
                                            .size(30.)
                                            .strong(),
                                        );
                                        ui.separator(); // Horizontal Rule
                                    })
                                    .response;

                                // Send message to key's thread to increment the counter when clicked
                                // DisplayKeys don't store the type that the key is meaning it cannot be checked for, however the message will be ignored if the key is TOTP, so its fine to send message to either type
                                if response.interact(egui::Sense::click()).clicked() {
                                    key.sender
                                        .send(OTPMessageIn::Increment(self.encryption_key.clone()))
                                        .unwrap();
                                }

                                // If right clicked, create a context menu (popup) with option to delete the key
                                let popup_id = ui.make_persistent_id("DEL");
                                if response.interact(egui::Sense::click()).secondary_clicked() {
                                    ui.memory_mut(|mem| mem.toggle_popup(popup_id));
                                }

                                // Defines the popup
                                egui::popup::popup_above_or_below_widget(
                                    ui,
                                    popup_id,
                                    &response,
                                    egui::AboveOrBelow::Below, // Menu appears below code
                                    |ui| {
                                        ui.set_max_width(20.0);
                                        if ui.button("Delete").clicked() {
                                            // Show delete button that adds the key to the to_delete attribute when clicked
                                            // Cannot be deleted here, as the keys are currently being iterated through
                                            self.to_delete = Some(key.clone());
                                        }
                                    },
                                );
                            });
                        }
                    });
                });
            }

            /// Draw the add tab to the window
            fn draw_add(&mut self, ctx: &egui::Context) {
                // add_key attribute used to store the state of all manually entered key attributes
                egui::CentralPanel::default().show(ctx, |ui| {
                    ui.horizontal(|ui| {
                        // Secret entry with text box
                        ui.label("Secret");
                        ui.text_edit_singleline(&mut self.add_key.secret);
                    });
                    ui.horizontal(|ui| {
                        // Name entry with text box
                        ui.label("Name ");
                        ui.text_edit_singleline(&mut self.add_key.name);
                    });
                    ui.horizontal(|ui| {
                        // Key type entry with radio buttons
                        ui.label("Method");
                        ui.radio_value(&mut self.add_key.options.method, OTPMethod::TOTP, "TOTP");
                        ui.radio_value(
                            &mut self.add_key.options.method,
                            OTPMethod::HOTP(0), // Counter defaults to 0
                            "HOTP",
                        );
                    });
                    ui.horizontal(|ui| {
                        // Code length entry with radio buttons 4..=6
                        ui.label("Length  ");
                        ui.radio_value(&mut self.add_key.options.length, 4, "4");
                        ui.radio_value(&mut self.add_key.options.length, 5, "5");
                        ui.radio_value(&mut self.add_key.options.length, 6, "6");
                    });
                    ui.horizontal(|ui| {
                        // Hash function entry with radio buttons
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
                        // Time interval entry with integer selection
                        ui.label("Interval");
                        ui.add(
                            egui::DragValue::new(&mut self.add_key.options.interval)
                                .speed(0.2) // Low speed for fine slider control
                                .clamp_range(10..=300), // Clamped between 10 and 300 incl.
                        );
                    });
                    ui.vertical_centered(|ui| {
                        // Error display for invalid codes, defaults to empty string so isn't shown until an error occurs
                        // Displays in red
                        ui.label(RichText::new(&self.add_err).color(Color32::RED))
                    });

                    ui.separator();
                    ui.horizontal(|ui| {
                        if ui.button("Add").clicked() {
                            // When add button clicked
                            // Get current time
                            self.add_key.time = Utc::now().timestamp();

                            // If the key is valid: display and refresh all fields, else: display error to user
                            if let Err(e) = file::keys::add(&self.add_key, &self.encryption_key) {
                                self.add_err = e;
                            } else {
                                // Generate DisplayKey and Receiver from manually entered key, adding it to the respective data structures stored as attributes in the App
                                let (key, receiver) = generate_display_key(ctx, &self.add_key);
                                self.receivers.insert(key.name.clone(), receiver);
                                self.keys.push(key);

                                // Reset all fields and switch to main tab
                                self.add_key = Default::default();
                                self.tab = Tab::Main;
                                self.add_err = String::new();
                            }
                        };

                        if ui.button("Add From QR").clicked() {
                            // If QR button just pressed
                            // Allow the user to select a file using their system explorer using rfd crate
                            if let Some(path) = rfd::FileDialog::new().pick_file() {
                                // Parse QR code with parse fn from qr module - if correct: add it to internal state, if not: show error to user
                                if let Ok(key) = qr::parse(path) {
                                    // Make sure the key itself is valid
                                    if let Err(e) = file::keys::add(&key, &self.encryption_key) {
                                        self.add_err = e;
                                    } else {
                                        // Process key the same way as with manually added key
                                        let (key, receiver) = generate_display_key(ctx, &key);
                                        self.receivers.insert(key.name.clone(), receiver);
                                        self.keys.push(key);

                                        self.add_key = Default::default();
                                        self.tab = Tab::Main;
                                        self.add_err = String::new();
                                    }
                                } else {
                                    self.add_err = String::from("Could not parse QR code")
                                }
                            }
                        };
                    });
                });
            }

            /// Draw the options tab to the window
            /// The settings file is automatically saved to upon any change to an option
            fn draw_options(&mut self, ctx: &egui::Context) {
                egui::CentralPanel::default().show(ctx, |ui| {
                    ui.horizontal(|ui| {
                        // Sort By option, selected using radio buttons
                        ui.label("Sort By");
                        if ui
                            .radio_value(&mut self.options.sort, SortBy::Date, "Time Added")
                            .clicked()
                            || ui
                                .radio_value(&mut self.options.sort, SortBy::Name, "Name")
                                .clicked()
                        {
                            // If either option selected, refresh the keys with the new sorting choice and save the choice to the settings file
                            self.keys = sort_keys(self.keys.clone(), &self.options.sort);
                            file::options::save(&self.options)
                        }
                    });
                    ui.horizontal(|ui| {
                        // Spacer option, selected using a toggle button
                        let selected = &mut self.options.spacer;
                        ui.label("Spacer");
                        if ui
                            .toggle_value(selected, if *selected { "Enabled" } else { "Disabled" }) // Reads Enabled when true and Disabled when false
                            .clicked()
                        {
                            // If changed, save choice to settings file
                            file::options::save(&self.options)
                        }
                    });
                });
            }
        }
    }

    /// Handles the initial password window
    pub mod password {
        use std::cell::RefCell;
        use std::path::Path;
        use std::rc::Rc;

        use super::*;

        // Create App instance & run
        // This app takes input, validates the password, then passes the encryption key to the main app through main.rs
        pub fn gui() -> Result<Option<EncryptionKey>, eframe::Error> {
            // App is 320 by 160 and isn't resizable
            let options = eframe::NativeOptions {
                viewport: egui::ViewportBuilder::default()
                    .with_inner_size(egui::vec2(320., 160.))
                    .with_resizable(false),
                centered: true,
                ..Default::default()
            };

            // Encryption key is of composite type involving Rc and RefCell smart pointers
            // The combination of these types allow for separate mutable references to the same data, without the borrows being checked at compile time
            // This allows for some data to be returned upon the app closing, as ordinarily data is moved into the App struct and isn't able to be returned
            // Initialised as None, which is only updated on the user entering a correct password, allowing the main fn to distinguish between a password being entered and pressing the close button
            let encryption_key: Rc<RefCell<Option<EncryptionKey>>> = Rc::new(RefCell::new(None));
            let encryption_key_clone = encryption_key.clone();

            // Extra scope so the App is dropped as soon as possible, meaning the entered password exits memory faster
            {
                eframe::run_native(
                    "TOTP", // Window title
                    options,
                    Box::new(|_cc| Box::<App>::new(App::new(encryption_key_clone))),
                )?;
            }

            // Window Closed

            // No chance of panicing, as this code is run after app is dropped, so satisfies concurrent mutable references rule
            let out_ref_c = encryption_key.borrow();

            // Return Option<e_key> by dereference
            Ok(*out_ref_c)
        }

        /// Struct that handles the password window & its stored data
        struct App {
            // Password not kept in memory after App closed, only the hash is
            encryption_key: Rc<RefCell<Option<EncryptionKey>>>, // Allows for the string to have multiple references + be interior mutable
            password_field: String,
            error: String,
        }

        impl eframe::App for App {
            /// Called every frame to update the winow
            fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
                egui::CentralPanel::default().show(ctx, |ui| {
                    ui.label("Please enter a password"); // Label
                    ui.text_edit_singleline(&mut self.password_field); // Text entry
                    ui.vertical_centered(|ui| {
                        ui.label(RichText::new(&self.error).color(Color32::RED))
                        // Error message display in red colour (defaults to not showing)
                    });
                    ui.separator();

                    ui.horizontal(|ui| {
                        if ui.button("Enter").clicked() {
                            // Logic for when enter button clicked

                            // Calculate encryption key from
                            let e_key = encrypt::password_to_key(&self.password_field);

                            // Try to
                            let path = Path::new(crate::file::KEYPATH);
                            if let Err(e) = encrypt::load(path, &e_key) {
                                self.error =
                                    if let encrypt::Error::ReadError = *(e.downcast().unwrap()) {
                                        // Downcast converts generic to concrete type
                                        // If error returned is ReadError, set the error box of the GUI to display incorrect password
                                        String::from("Incorrect password")
                                    } else {
                                        // If error returned isn't ReadError , set the error box of the GUI to display generic error message
                                        String::from("An error occurred")
                                    }
                            } else {
                                // If the password is correct, mutably deref the encryption key attribute and assign the previously calculated key to it
                                *(*self.encryption_key).borrow_mut() = Some(e_key);
                                // Close the window, allowing gui fn to continue
                                ctx.send_viewport_cmd(egui::ViewportCommand::Close)
                            }
                        }
                        let response = ui
                            .button("Set as new password")
                            .on_hover_text("Warning, this will delete all currently stored codes"); // Tooltip
                        if response.clicked() {
                            // If reset password button pressed, deletes all old codes so new key can be used
                            file::keys::delete_all(&encrypt::password_to_key(&self.password_field));
                            // Sets the key attribute and closes the window, as with enter button
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
