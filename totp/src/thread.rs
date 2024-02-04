// Handles creation of backend threads that handle an individual key

use chrono::Utc;

use std::sync::mpsc;
use std::sync::mpsc::{Receiver, Sender};
use std::thread;
use std::time::Duration;

use crate::key::Key;
use crate::otp::{generate, OTPMethod};
use crate::ui::main::{OTPMessageIn, OTPMessageOut};

use eframe::egui;

/// Calculates duration between current time and the next timestep increment
fn time_to_timestep(interval: u32) -> Duration {
    // Gets current UNIX (millisecond) time
    let now_stamp: u64 = Utc::now().timestamp_millis().try_into().unwrap();
    // Gets UNIX (millisecond) time of next timestap
    let interval: u64 = <u32 as Into<u64>>::into(interval) * 1000;
    let next_timestep_stamp = ((now_stamp / interval) + 1) * interval;

    // Return duration between the two times
    // Next timestep time always greater than current
    Duration::from_millis(next_timestep_stamp - now_stamp)
}

/// Spawns a thread that handles the code generation for a single key
/// Returns a Sender of [OTPMessageIn] to send messages to the thread and a Receiver [OTPMessageOut] to receive code messages from the thread
/// The EGUI context is used within the thread to signal a screen refresh
pub fn spawn_thread(
    ctx: &egui::Context,
    key: &Key,
) -> (Receiver<OTPMessageOut>, Sender<OTPMessageIn>) {
    // Channel for sending codes out
    let (tx_out, rx_out) = mpsc::channel::<OTPMessageOut>();
    // Channel for receiving updates from GUI, either to close the thread or
    let (tx_in, rx_in) = mpsc::channel::<OTPMessageIn>();

    // Clone the key and context so they can be owned by the thread
    let mut key_clone = key.clone();
    let ctx = ctx.clone(); // CTX designed to be cheap to clone

    // Generates initial code and sends it to the GUI
    let code = generate(&key_clone);
    tx_out.send(OTPMessageOut::Code(code)).unwrap();

    // Determine type of key, as TOTP and HOTP codes need to be handled by different logic
    match key.options.method {
        OTPMethod::TOTP => {
            // Thread for time based keys
            thread::spawn(move || loop {
                // Wait until code needs to be next updated
                let wait = time_to_timestep(key_clone.options.interval);
                thread::sleep(wait); // Guaranteed to last for at least the duration of wait

                // Close if Close message recieved while sleeping
                if let Ok(r) = rx_in.try_recv() {
                    if let OTPMessageIn::Close = r {
                        // Exit loop, terminating thread
                        break;
                    }
                }

                // Generate code from key, now that the timestep has updated
                let code = generate(&key_clone);

                // Send code to GUI
                if let Ok(_) = tx_out.send(OTPMessageOut::Code(code)) {
                    ctx.request_repaint(); // Only called on updates, to prevent CPU overhead
                }
            });
        }
        OTPMethod::HOTP(_) => {
            // Thread for counter based keys
            thread::spawn(move || loop {
                // Blocking wait until any message received 
                if let Ok(r) = rx_in.recv() {
                    match r {
                        OTPMessageIn::Increment(e_key) => {
                            // On increment message, increment counter, calculate code & send to GUI
                            key_clone.increment(&e_key);
                            let code = generate(&key_clone);
                            if let Ok(_) = tx_out.send(OTPMessageOut::Code(code)) {
                                ctx.request_repaint();
                            }
                        }
                        OTPMessageIn::Close => break, // Break on close message, terminating thread
                    }
                }
            });
        }
    }
    // Return receiver and sender to be used by main thread
    (rx_out, tx_in)
}
