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

const TICK_SPEED: Duration = Duration::from_millis(1000);

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

    // Generates initial progress and sends it to the GUI
    let wait = time_to_timestep(key_clone.options.interval);
    let progress = 1. - (wait.as_secs_f32() / key_clone.options.interval as f32);
    tx_out.send(OTPMessageOut::Tick(progress)).unwrap();

    // Determine type of key, as TOTP and HOTP codes need to be handled by different logic
    match key.options.method {
        OTPMethod::TOTP => {
            // Thread for time based keys
            thread::spawn(move || loop {
                // Wait until next tick or code needs to be updated
                let dur_to_code = time_to_timestep(key_clone.options.interval);

                // Handles when application first opened and ticks aren't in sync with code
                let dur_to_tick =
                    Duration::from_secs_f32(dur_to_code.as_secs_f32() % TICK_SPEED.as_secs_f32());

                let update_code = dur_to_code <= dur_to_tick + TICK_SPEED / 2;
                let to_sleep = dur_to_code.min(dur_to_tick);

                thread::sleep(to_sleep); // Guaranteed to last for at least the duration of wait

                // Close if Close message recieved while sleeping
                if let Ok(r) = rx_in.try_recv() {
                    if let OTPMessageIn::Close = r {
                        // Exit loop, terminating thread
                        break;
                    }
                }

                // Calculate percentage of time remaining
                let time = time_to_timestep(key_clone.options.interval);
                let progress = 1. - (time.as_secs_f32() / key_clone.options.interval as f32);

                if let Err(_) = tx_out.send(OTPMessageOut::Tick(progress)) {
                    continue;
                }

                if update_code {
                    // Generate code from key, now that the timestep has updated
                    let code = generate(&key_clone);

                    if let Err(_) = tx_out.send(OTPMessageOut::Code(code)) {
                        continue;
                    }
                }

                ctx.request_repaint(); // Only called on updates, to prevent CPU overhead
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
