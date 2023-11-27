use chrono::Utc;

use std::sync::mpsc;
use std::sync::mpsc::{Receiver, Sender};
use std::thread;
use std::time::Duration;

use crate::key::Key;
use crate::otp::{generate, OTPMethod};
use crate::ui::main::{OTPMessageIn, OTPMessageOut};

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
                        OTPMessageIn::Increment(e_key) => {
                            key_clone.increment(&e_key);
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
