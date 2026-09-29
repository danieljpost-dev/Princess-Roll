//! Wiring: the gate, the paste handshake, the room, and the frame loop.
//!
//! The sound level is the only thing persisted, under VOLUME_KEY. Everything
//! else the app knows lives in this struct and dies with the tab.

use crate::audio::Sfx;
use crate::crypto::random;
use crate::dice::{commit_matches, commit_to, derive_roll, Geometry, Quat, Roll, Tumble, Vec3};
use crate::pairing::{Pairing, Role};
use crate::protocol::{
    derive_session_key, verification_phrase, Msg, Session, CHUNK_BYTES, MAX_FILE_BYTES,
};
use crate::render::{Highlight, Renderer};
use crate::rtc::Peer;
use crate::signal::{Blob, Kind};

use std::cell::RefCell;
use std::rc::Rc;
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::{spawn_local, JsFuture};
use web_sys::{Document, HtmlInputElement, HtmlTextAreaElement};
use x25519_dalek::{PublicKey, StaticSecret};

const MAX_CHALLENGE: usize = 240;

/// The only key this app ever writes.
const VOLUME_KEY: &str = "princess-roll:volume";
const VOLUME_STEPS: [u8; 4] = [0, 25, 50, 100];
const DEFAULT_VOLUME: u8 = 100;

/// Throws in a private window or with site data blocked, so every access is
/// fallible and failure just means "no preference".
fn local_storage() -> Option<web_sys::Storage> {
    web_sys::window()?.local_storage().ok().flatten()
}

fn read_volume() -> u8 {
    let stored = local_storage()
        .and_then(|storage| storage.get_item(VOLUME_KEY).ok().flatten())
        .and_then(|raw| raw.parse::<u8>().ok());

    match stored {
        Some(percent) if VOLUME_STEPS.contains(&percent) => percent,
        _ => DEFAULT_VOLUME,
    }
}

fn write_volume(percent: u8) {
    if let Some(storage) = local_storage() {
        let _ = storage.set_item(VOLUME_KEY, &percent.to_string());
    }
}

fn show_volume(percent: u8) {
    select_by_id("volume").set_value(&percent.to_string());
}

// ------------------------------------------------------------------ DOM helpers

fn document() -> Document {
    web_sys::window()
        .expect("a window")
        .document()
        .expect("a document")
}

/// Deliberately `Element`, not `HtmlElement`: the success and failure sigils
/// are `<svg>`, which is an `SVGElement` and does **not** inherit from
/// `HTMLElement`. Casting them blindly panics, and everything we need here —
/// text, classes, attributes, scrolling — lives on `Element` anyway.
fn by_id(id: &str) -> web_sys::Element {
    document()
        .get_element_by_id(id)
        .unwrap_or_else(|| panic!("the page is missing #{id}"))
}

/// For the few places that genuinely need an HTML-only method, such as `click`.
fn html_by_id(id: &str) -> web_sys::HtmlElement {
    by_id(id)
        .dyn_into()
        .unwrap_or_else(|_| panic!("#{id} is not an HTML element"))
}

fn input_by_id(id: &str) -> HtmlInputElement {
    by_id(id).dyn_into().expect("an input element")
}

fn select_by_id(id: &str) -> web_sys::HtmlSelectElement {
    by_id(id).dyn_into().expect("a select element")
}

fn on_change(id: &str, handler: impl FnMut() + 'static) {
    let closure = Closure::<dyn FnMut()>::new(handler);
    by_id(id)
        .add_event_listener_with_callback("change", closure.as_ref().unchecked_ref())
        .unwrap_or_else(|_| panic!("could not attach a change handler to #{id}"));
    closure.forget();
}

fn textarea_by_id(id: &str) -> HtmlTextAreaElement {
    by_id(id).dyn_into().expect("a textarea element")
}

fn set_text(id: &str, text: &str) {
    by_id(id).set_text_content(Some(text));
}

fn show(id: &str, visible: bool) {
    let element = by_id(id);
    let _ = if visible {
        element.class_list().remove_1("hidden")
    } else {
        element.class_list().add_1("hidden")
    };
}

/// Drives the whole-page alert styling from one class on `<body>`, so the
/// colour scheme lives in CSS rather than being poked element by element.
fn set_body_alert(on: bool) {
    let Some(body) = document().body() else {
        return;
    };
    let classes = body.class_list();
    let _ = if on {
        classes.add_1("alert")
    } else {
        classes.remove_1("alert")
    };
}

fn set_disabled(id: &str, disabled: bool) {
    let element = by_id(id);
    if disabled {
        let _ = element.set_attribute("disabled", "true");
    } else {
        element.remove_attribute("disabled").ok();
    }
}

fn on_click(id: &str, handler: impl FnMut() + 'static) {
    let closure = Closure::<dyn FnMut()>::new(handler);
    by_id(id)
        .add_event_listener_with_callback("click", closure.as_ref().unchecked_ref())
        .unwrap_or_else(|_| panic!("could not attach a click handler to #{id}"));
    closure.forget();
}

/// `document.execCommand("copy")` reached through `Reflect`, because web-sys
/// does not surface it on `Document` and it is the only copy path that works
/// outside a secure context.
fn exec_copy() -> bool {
    let doc = JsValue::from(document());
    js_sys::Reflect::get(&doc, &"execCommand".into())
        .ok()
        .and_then(|f| f.dyn_into::<js_sys::Function>().ok())
        .and_then(|f| f.call1(&doc, &"copy".into()).ok())
        .and_then(|result| result.as_bool())
        .unwrap_or(false)
}

async fn sleep_ms(ms: i32) {
    let promise = js_sys::Promise::new(&mut |resolve, _| {
        if let Some(window) = web_sys::window() {
            let _ = window.set_timeout_with_callback_and_timeout_and_arguments_0(&resolve, ms);
        }
    });
    let _ = JsFuture::from(promise).await;
}

/// Yield to the browser so a status message actually paints before a long
/// synchronous job (Argon2) blocks the thread.
async fn next_paint() {
    sleep_ms(16).await;
}

fn human_size(bytes: u64) -> String {
    const UNITS: [&str; 4] = ["B", "KB", "MB", "GB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if 0 == unit {
        format!("{bytes} B")
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

/// A peer-supplied filename only ever becomes link text and a `download`
/// attribute, never a path — but strip separators and control characters
/// anyway, and bound the length.
fn sanitise_name(name: &str) -> String {
    let cleaned: String = name
        .chars()
        .map(|c| {
            if c.is_control() || '/' == c || '\\' == c {
                '_'
            } else {
                c
            }
        })
        .collect();

    let trimmed = cleaned.trim();
    if trimmed.is_empty() {
        "attachment".to_string()
    } else {
        trimmed.chars().take(120).collect()
    }
}

fn is_previewable(mime: &str) -> bool {
    mime.starts_with("image/") || mime.starts_with("video/")
}

async fn fetch_pairing_file() -> Result<Vec<u8>, String> {
    let window = web_sys::window().ok_or("no window")?;

    // Relative, so it resolves the same on localhost and under the
    // /Princess-Roll/ path GitHub Pages serves a project site from.
    let response = JsFuture::from(window.fetch_with_str("./pairing.bin"))
        .await
        .map_err(|_| "could not load pairing.bin".to_string())?
        .dyn_into::<web_sys::Response>()
        .map_err(|_| "unexpected response for pairing.bin".to_string())?;

    if !response.ok() {
        return Err(format!(
            "pairing.bin is missing ({}). Run `cargo run --bin setup` and rebuild.",
            response.status()
        ));
    }

    let buffer = JsFuture::from(
        response
            .array_buffer()
            .map_err(|_| "could not read pairing.bin".to_string())?,
    )
    .await
    .map_err(|_| "could not read pairing.bin".to_string())?;

    Ok(js_sys::Uint8Array::new(&buffer).to_vec())
}

// ------------------------------------------------------------------- app state

/// Chunks are folded into a blob part once this much has accumulated. Keeping
/// thousands of small typed arrays alive is what would exhaust memory; a Blob
/// is browser-managed and may be paged to disk.
const COALESCE_BYTES: usize = 8 * 1024 * 1024;

/// A file arriving from the peer.
///
/// Chunks go straight to the browser as blob parts and never accumulate in a
/// Rust `Vec`. That is not tidiness: wasm32 linear memory tops out at 4 GiB
/// and `usize` is 32-bit, so a multi-gigabyte file cannot exist in this
/// address space at all. Nothing is written to disk by us — whether the
/// browser backs a large blob with a temp file is its own business — and the
/// whole thing evaporates when the tab closes.
struct Incoming {
    id: u32,
    name: String,
    mime: String,
    size: u64,
    received: u64,
    /// Chunks not yet folded into a part.
    pending: js_sys::Array,
    pending_bytes: usize,
    /// Sealed-off blob parts.
    parts: js_sys::Array,
    /// Last percentage written to the DOM. A 4 GiB file is ~147,000 chunks;
    /// updating the page on each one would cost more than the transfer.
    last_percent: u8,
}

impl Incoming {
    fn new(id: u32, name: String, mime: String, size: u64) -> Incoming {
        Incoming {
            id,
            name,
            mime,
            size,
            received: 0,
            pending: js_sys::Array::new(),
            pending_bytes: 0,
            parts: js_sys::Array::new(),
            last_percent: u8::MAX,
        }
    }

    fn push(&mut self, data: &[u8]) -> Result<(), JsValue> {
        self.pending.push(&js_sys::Uint8Array::from(data));
        self.pending_bytes += data.len();
        self.received += data.len() as u64;

        if self.pending_bytes >= COALESCE_BYTES {
            self.fold()?;
        }
        Ok(())
    }

    fn fold(&mut self) -> Result<(), JsValue> {
        if 0 == self.pending.length() {
            return Ok(());
        }
        let part = web_sys::Blob::new_with_u8_array_sequence(&self.pending)?;
        self.parts.push(&part);
        self.pending = js_sys::Array::new();
        self.pending_bytes = 0;
        Ok(())
    }

    /// The Blob constructor accepts Blobs as parts, and this binding takes an
    /// untyped sequence, so the finished file is assembled without any of it
    /// passing back through wasm memory.
    fn finish(&mut self) -> Result<web_sys::Blob, JsValue> {
        self.fold()?;
        let options = web_sys::BlobPropertyBag::new();
        options.set_type(&self.mime);
        web_sys::Blob::new_with_u8_array_sequence_and_options(&self.parts, &options)
    }

    /// `Some(percent)` only when the figure actually changed.
    fn progress(&mut self) -> Option<u8> {
        let percent = (self.received.saturating_mul(100) / self.size.max(1)).min(100) as u8;
        if percent == self.last_percent {
            return None;
        }
        self.last_percent = percent;
        Some(percent)
    }
}

struct Animation {
    tumble: Tumble,
    roll: Roll,
    threshold: u8,
    started: f64,
    resolved: bool,
}

pub struct App {
    role: Role,
    pairing_secret: [u8; 32],
    secret: StaticSecret,
    public: [u8; 32],

    /// Shared so a handshake step can hold the peer across an `await` without
    /// keeping the surrounding `App` borrowed.
    peer: Rc<Peer>,
    session: Option<Session>,

    geometry: Geometry,
    renderer: Option<Renderer>,
    sfx: Sfx,

    challenge: Option<(String, u8)>,
    round: u32,
    /// Daddy's nonce for the round he has committed to but not yet opened.
    my_nonce: Option<[u8; 32]>,
    /// Princess's record of his commitment, checked when he opens it.
    their_commit: Option<[u8; 32]>,
    animation: Option<Animation>,
    orientation: Quat,

    incoming: Option<Incoming>,
    /// Monotonic, so a late chunk from an abandoned transfer cannot be mistaken
    /// for part of the current one.
    next_file_id: u32,
    sending_file: bool,
    /// Princess only: a challenge is waiting and she has not answered it.
    alerting: bool,
}

type Shared = Rc<RefCell<App>>;

impl App {
    fn is_daddy(&self) -> bool {
        Role::Daddy == self.role
    }

    // ------------------------------------------------------------- transport

    fn send(&mut self, msg: &Msg) {
        let frame = match self.session.as_mut() {
            Some(session) => session.seal_msg(msg),
            None => return,
        };
        if let Err(_e) = self.peer.send(&frame) {
            self.log_system("The connection dropped that message.");
        }
    }

    fn log(&self, who: &str, text: &str, kind: &str) {
        let doc = document();
        let line = match doc.create_element("div") {
            Ok(line) => line,
            Err(_) => return,
        };
        let _ = line.set_attribute("class", &format!("line {kind}"));

        if let Ok(label) = doc.create_element("span") {
            let _ = label.set_attribute("class", "who");
            label.set_text_content(Some(who));
            let _ = line.append_child(&label);
        }
        if let Ok(body) = doc.create_element("span") {
            let _ = body.set_attribute("class", "said");
            // set_text_content escapes, so a message can never inject markup.
            body.set_text_content(Some(text));
            let _ = line.append_child(&body);
        }

        let log = by_id("log");
        let _ = log.append_child(&line);
        log.set_scroll_top(log.scroll_height());
    }

    fn log_system(&self, text: &str) {
        self.log("", text, "system");
    }

    fn set_transfer(&self, text: &str) {
        set_text("transfer", text);
    }

    /// Princess only. Chimes every time, even if the page is already alerting:
    /// a replaced challenge is new news.
    fn raise_alert(&mut self) {
        if self.is_daddy() {
            return;
        }
        self.alerting = true;
        set_body_alert(true);
        self.sfx.alert();
    }

    fn clear_alert(&mut self) {
        if !self.alerting {
            return;
        }
        self.alerting = false;
        set_body_alert(false);
    }

    /// Hand received bytes back to the browser as an in-memory blob URL, with
    /// an inline preview and a save link. The URL is never written anywhere
    /// and dies with the tab, which is the whole storage policy.
    fn append_media(
        &self,
        who: &str,
        name: &str,
        mime: &str,
        blob: &web_sys::Blob,
    ) -> Result<(), JsValue> {
        let doc = document();
        let url = web_sys::Url::create_object_url_with_blob(blob)?;

        let line = doc.create_element("div")?;
        line.set_attribute("class", "line media")?;

        let label = doc.create_element("span")?;
        label.set_attribute("class", "who")?;
        label.set_text_content(Some(who));
        line.append_child(&label)?;

        let frame = doc.create_element("div")?;
        frame.set_attribute("class", "attachment")?;

        if mime.starts_with("image/") {
            let image = doc.create_element("img")?;
            image.set_attribute("src", &url)?;
            image.set_attribute("alt", name)?;
            frame.append_child(&image)?;
        } else if mime.starts_with("video/") {
            let video = doc.create_element("video")?;
            video.set_attribute("src", &url)?;
            video.set_attribute("controls", "")?;
            // Stops iOS taking the video fullscreen the moment it plays.
            video.set_attribute("playsinline", "")?;
            frame.append_child(&video)?;
        }

        let link = doc.create_element("a")?;
        link.set_attribute("href", &url)?;
        link.set_attribute("download", name)?;
        link.set_attribute("class", "download")?;
        link.set_text_content(Some(&format!("{name} · {}", human_size(blob.size() as u64))));
        frame.append_child(&link)?;

        line.append_child(&frame)?;

        let log = by_id("log");
        log.append_child(&line)?;
        log.set_scroll_top(log.scroll_height());
        Ok(())
    }

    // -------------------------------------------------------------- challenge

    fn apply_challenge(&mut self, challenge: Option<(String, u8)>) {
        self.challenge = challenge;
        match &self.challenge {
            Some((text, threshold)) => {
                set_text("challenge-current", text);
                set_text("threshold-display", &threshold.to_string());
                show("challenge-active", true);
                show("challenge-empty", false);
            }
            None => {
                show("challenge-active", false);
                show("challenge-empty", true);
            }
        }

        // Sending a file is part of answering a challenge, so the picker only
        // exists while one is set. Clear any stale error on the way out, or it
        // would still be sitting there when the block reappears.
        let has_challenge = self.challenge.is_some();
        show("file-share", has_challenge);
        if !has_challenge {
            set_text("transfer-error", "");
            // A withdrawn challenge leaves nothing to answer, so the page must
            // not stay alerting with no way out of it.
            self.clear_alert();
        }

        self.refresh_roll_button();
    }

    /// Princess may roll only when there is a challenge, a fresh commitment
    /// from Daddy, and nothing already in flight.
    fn refresh_roll_button(&self) {
        let ready = !self.is_daddy()
            && self.challenge.is_some()
            && self.their_commit.is_some()
            && self.animation.is_none();
        set_disabled("roll", !ready);

        set_text(
            "roll-hint",
            if self.is_daddy() {
                "Only Princess may roll."
            } else if self.challenge.is_none() {
                "Waiting for Daddy to set a challenge."
            } else if self.animation.is_some() {
                "The die is still falling."
            } else if self.their_commit.is_none() {
                "Waiting for Daddy's client to commit."
            } else {
                "Your roll."
            },
        );
    }

    /// Daddy publishes a commitment for the next round. Doing this before she
    /// can roll is what stops either side steering the result.
    fn commit_next_round(&mut self) {
        if !self.is_daddy() {
            return;
        }
        self.round += 1;
        let nonce: [u8; 32] = random();
        let hash = commit_to(&nonce);
        self.my_nonce = Some(nonce);

        let round = self.round;
        self.send(&Msg::Commit { round, hash });
    }

    // ------------------------------------------------------------------ dice

    fn begin_animation(&mut self, roll: Roll, threshold: u8) {
        let tumble = Tumble::new(
            &self.geometry,
            roll.value,
            &roll.animation_seed,
            self.orientation,
        );
        self.animation = Some(Animation {
            tumble,
            roll,
            threshold,
            started: now_seconds(),
            resolved: false,
        });
        show("result", false);
        self.refresh_roll_button();
    }

    fn resolve_animation(&mut self) {
        let Some(animation) = self.animation.as_mut() else {
            return;
        };
        if animation.resolved {
            return;
        }
        animation.resolved = true;

        let roll = animation.roll;
        let threshold = animation.threshold;
        let success = roll.succeeds_against(threshold);

        set_text("result-value", &roll.value.to_string());
        set_text(
            "result-line",
            &format!(
                "{} against {}",
                roll.value, threshold
            ),
        );
        show("result", true);
        show("result-success", success);
        show("result-failure", !success);

        let verdict = if success { "SUCCESS" } else { "FAILURE" };
        self.log(
            "the die",
            &format!("{} — {} vs {}", verdict, roll.value, threshold),
            if success { "success" } else { "failure" },
        );

        if success {
            self.sfx.success();
        } else {
            self.sfx.failure();
        }
    }

    // --------------------------------------------------------------- receive

    fn handle(&mut self, msg: Msg) {
        match msg {
            Msg::Chat(text) => {
                let who = self.role.other().as_str();
                self.log(who, &text, "them");
                self.sfx.blip();
            }

            Msg::Challenge { text, threshold } => {
                self.apply_challenge(Some((text.clone(), threshold)));
                self.log_system(&format!("Daddy set a challenge, needing {threshold} or better."));
                self.raise_alert();
            }

            Msg::ClearChallenge => {
                self.apply_challenge(None);
                self.log_system("Daddy cleared the challenge.");
            }

            Msg::Commit { round, hash } => {
                if self.is_daddy() {
                    return;
                }
                self.round = round;
                self.their_commit = Some(hash);
                self.refresh_roll_button();
            }

            Msg::Reveal { round, nonce } => {
                // Only Daddy answers a reveal, and only for the round he is
                // currently committed to.
                if !self.is_daddy() || round != self.round {
                    return;
                }
                let Some(my_nonce) = self.my_nonce.take() else {
                    return;
                };
                let Some((_, threshold)) = self.challenge.clone() else {
                    return;
                };

                self.send(&Msg::Open {
                    round,
                    nonce: my_nonce,
                });
                let roll = derive_roll(&my_nonce, &nonce);
                self.begin_animation(roll, threshold);
            }

            Msg::Open { round, nonce } => {
                if self.is_daddy() || round != self.round {
                    return;
                }
                let Some(commitment) = self.their_commit.take() else {
                    return;
                };
                let Some(my_nonce) = self.my_nonce.take() else {
                    return;
                };
                let Some((_, threshold)) = self.challenge.clone() else {
                    return;
                };

                if !commit_matches(&commitment, &nonce) {
                    self.log_system(
                        "Refused: Daddy's client opened a value that does not match what it \
                         committed to. That roll was discarded.",
                    );
                    self.refresh_roll_button();
                    return;
                }

                let roll = derive_roll(&nonce, &my_nonce);
                self.begin_animation(roll, threshold);
            }

            Msg::FileStart {
                id,
                name,
                mime,
                size,
            } => {
                if !is_previewable(&mime) {
                    self.send(&Msg::FileAbort {
                        id,
                        reason: "only images and videos are accepted".into(),
                    });
                    return self.log_system("Refused a file that was not an image or a video.");
                }
                if size > MAX_FILE_BYTES {
                    self.send(&Msg::FileAbort {
                        id,
                        reason: "larger than the agreed maximum".into(),
                    });
                    return self.log_system("Refused a file over the size limit.");
                }

                let name = sanitise_name(&name);
                self.set_transfer(&format!("Receiving {name}…"));
                self.incoming = Some(Incoming::new(id, name, mime, size));
            }

            Msg::FileChunk { id, data } => {
                // The borrow must end before touching the DOM helpers below.
                let outcome = match self.incoming.as_mut() {
                    Some(incoming) if incoming.id == id => {
                        if incoming.received + data.len() as u64 > incoming.size {
                            Err("more data than it declared")
                        } else if incoming.push(&data).is_err() {
                            Err("more data than this browser would hold")
                        } else {
                            Ok(incoming
                                .progress()
                                .map(|percent| (incoming.name.clone(), percent)))
                        }
                    }
                    // A chunk for a transfer we are not tracking: ignore it.
                    _ => return,
                };

                match outcome {
                    Ok(Some((name, percent))) => {
                        self.set_transfer(&format!("Receiving {name} — {percent}%"))
                    }
                    Ok(None) => {}
                    Err(why) => {
                        self.incoming = None;
                        self.set_transfer("");
                        self.log_system(&format!("A file sent {why}. Discarded."));
                    }
                }
            }

            Msg::FileEnd { id } => {
                let Some(mut incoming) = self.incoming.take() else {
                    return;
                };
                if incoming.id != id {
                    return;
                }
                self.set_transfer("");

                if incoming.received != incoming.size {
                    return self.log_system("A file arrived incomplete and was discarded.");
                }

                let Ok(blob) = incoming.finish() else {
                    return self.log_system("A file arrived but could not be assembled.");
                };

                let who = self.role.other().as_str();
                if self
                    .append_media(who, &incoming.name, &incoming.mime, &blob)
                    .is_err()
                {
                    self.log_system("A file arrived but the browser would not display it.");
                }
            }

            Msg::FileAbort { id, reason } => {
                if self.incoming.as_ref().is_some_and(|f| f.id == id) {
                    self.incoming = None;
                }
                self.set_transfer("");
                self.log_system(&format!("File transfer cancelled: {reason}"));
            }
        }
    }

    // ----------------------------------------------------------- frame loop

    fn frame(&mut self, time: f64) {
        let (orientation, lift, highlight) = match self.animation.as_ref() {
            Some(animation) => {
                let elapsed = (time - animation.started) as f32;
                let progress = (elapsed / crate::dice::TUMBLE_SECONDS).min(1.0);

                let orientation = animation.tumble.orientation_at(progress);
                let lift = animation.tumble.height_at(progress);

                let highlight = if animation.resolved {
                    let success = animation.roll.succeeds_against(animation.threshold);
                    let glow = ((time - animation.started - 2.6) as f32 * 2.2).min(1.0);
                    Highlight {
                        colour: if success {
                            Vec3::new(1.0, 0.82, 0.35)
                        } else {
                            Vec3::new(0.22, 0.24, 0.30)
                        },
                        amount: (glow * 0.35).clamp(0.0, 0.35),
                    }
                } else {
                    Highlight::NONE
                };

                if 1.0 <= progress {
                    self.orientation = orientation;
                }
                (orientation, lift, highlight)
            }
            None => {
                // Idle: a slow drift about a tilted axis so it reads as three
                // dimensional without being distracting.
                let drift = Quat::from_axis_angle(
                    Vec3::new(0.25, 1.0, 0.12),
                    (time * 0.35) as f32,
                );
                (drift * self.orientation, 0.0, Highlight::NONE)
            }
        };

        let finished = self
            .animation
            .as_ref()
            .is_some_and(|a| (time - a.started) as f32 >= crate::dice::TUMBLE_SECONDS);
        if finished {
            self.resolve_animation();
        }

        if let Some(renderer) = &self.renderer {
            renderer.resize(
                web_sys::window()
                    .and_then(|w| w.device_pixel_ratio().into())
                    .unwrap_or(1.0),
            );
            renderer.draw(orientation, lift, &highlight);
        }

        // Once the glow has played out, hand the next round to Daddy's client
        // and let her roll again.
        let settled = self
            .animation
            .as_ref()
            .is_some_and(|a| a.resolved && (time - a.started) > 4.0);
        if settled {
            self.animation = None;
            if self.is_daddy() {
                self.commit_next_round();
            }
            self.refresh_roll_button();
        }
    }
}

fn now_seconds() -> f64 {
    web_sys::window()
        .and_then(|w| w.performance())
        .map(|p| p.now() / 1000.0)
        .unwrap_or(0.0)
}

// ----------------------------------------------------------------- entry point

#[wasm_bindgen]
pub fn start() {
    console_error_panic_hook::set_once();
    wire_gate();
}

fn wire_gate() {
    on_click("unlock", || {
        let code = input_by_id("code-input").value();
        if code.trim().is_empty() {
            set_text("gate-error", "Enter your secret code.");
            return;
        }
        spawn_local(async move {
            if let Err(message) = unlock(code).await {
                set_text("gate-error", &message);
                set_text("gate-status", "");
                set_disabled("unlock", false);
            }
        });
    });

    // Enter submits, because typing a 25-character code and then hunting for a
    // button is needless friction.
    let closure = Closure::<dyn FnMut(web_sys::KeyboardEvent)>::new(
        move |event: web_sys::KeyboardEvent| {
            if "Enter" == event.key() {
                html_by_id("unlock").click();
            }
        },
    );
    input_by_id("code-input").set_onkeydown(Some(closure.as_ref().unchecked_ref()));
    closure.forget();
}

async fn unlock(code: String) -> Result<(), String> {
    set_disabled("unlock", true);
    set_text("gate-error", "");
    set_text("gate-status", "Deriving key — this is deliberately slow…");
    next_paint().await;

    let bytes = fetch_pairing_file().await?;
    let pairing = Pairing::decode(&bytes)?;

    next_paint().await;
    let (role, pairing_secret) = pairing
        .unlock(&code)
        .ok_or("That code does not open this page.")?;

    set_text("gate-status", "");
    enter_pairing(role, pairing_secret).map_err(|e| format!("{e:?}"))
}

fn enter_pairing(role: Role, pairing_secret: [u8; 32]) -> Result<(), JsValue> {
    let secret_bytes: [u8; 32] = random();
    let secret = StaticSecret::from(secret_bytes);
    let public = PublicKey::from(&secret).to_bytes();

    let geometry = Geometry::new();
    let app: Shared = Rc::new(RefCell::new(App {
        role,
        pairing_secret,
        secret,
        public,
        peer: Rc::new(Peer::new()?),
        session: None,
        geometry,
        renderer: None,
        sfx: Sfx::new(read_volume() as f32 / 100.0),
        challenge: None,
        round: 0,
        my_nonce: None,
        their_commit: None,
        animation: None,
        orientation: Quat::IDENTITY,
        incoming: None,
        next_file_id: 0,
        sending_file: false,
        alerting: false,
    }));

    // A click has happened, so this is the moment audio is allowed to start.
    app.borrow_mut().sfx.unlock();

    show("gate", false);
    show("pair", true);
    set_text("pair-role", role.as_str());
    show("pair-daddy", Role::Daddy == role);
    show("pair-princess", Role::Princess == role);

    wire_pairing(&app);
    Ok(())
}

fn wire_pairing(app: &Shared) {
    // --- Daddy: make an invite, then take her reply.
    {
        let app = Rc::clone(app);
        on_click("make-invite", move || {
            let app = Rc::clone(&app);
            set_disabled("make-invite", true);
            set_text("pair-status", "Asking the network how to reach you…");
            spawn_local(async move {
                // Take what is needed and drop the borrow before awaiting.
                let (peer, secret, public) = {
                    let a = app.borrow();
                    (Rc::clone(&a.peer), a.pairing_secret, a.public)
                };

                let result = peer.create_invite().await.map(|sdp| {
                    Blob {
                        kind: Kind::Invite,
                        sender: Role::Daddy,
                        public_key: public,
                        sdp,
                    }
                    .encode(&secret)
                });

                match result {
                    Ok(code) => {
                        textarea_by_id("invite-out").set_value(&code);
                        show("invite-ready", true);
                        set_text("pair-status", "Send this to Princess, then paste her reply.");
                    }
                    Err(_) => {
                        set_text("pair-error", "Could not build an invite in this browser.");
                        set_disabled("make-invite", false);
                    }
                }
            });
        });
    }

    {
        let app = Rc::clone(app);
        on_click("accept-reply", move || {
            let app = Rc::clone(&app);
            let pasted = textarea_by_id("reply-in").value();
            set_text("pair-error", "");

            spawn_local(async move {
                let (peer, secret) = {
                    let a = app.borrow();
                    (Rc::clone(&a.peer), a.pairing_secret)
                };

                let blob = match Blob::decode(&pasted, &secret) {
                    Ok(blob) => blob,
                    Err(message) => return set_text("pair-error", &message),
                };
                if Kind::Reply != blob.kind || Role::Princess != blob.sender {
                    return set_text("pair-error", "That is not Princess's reply code.");
                }

                if peer.accept_reply(&blob.sdp).await.is_err() {
                    return set_text("pair-error", "That reply code could not be applied.");
                }
                finish_handshake(&app, blob.public_key);
            });
        });
    }

    // --- Princess: take his invite, produce a reply.
    {
        let app = Rc::clone(app);
        on_click("accept-invite", move || {
            let app = Rc::clone(&app);
            let pasted = textarea_by_id("invite-in").value();
            set_text("pair-error", "");
            set_text("pair-status", "Working out how to reach him…");

            spawn_local(async move {
                let (peer, secret, public) = {
                    let a = app.borrow();
                    (Rc::clone(&a.peer), a.pairing_secret, a.public)
                };

                let blob = match Blob::decode(&pasted, &secret) {
                    Ok(blob) => blob,
                    Err(message) => {
                        set_text("pair-status", "");
                        return set_text("pair-error", &message);
                    }
                };
                if Kind::Invite != blob.kind || Role::Daddy != blob.sender {
                    set_text("pair-status", "");
                    return set_text("pair-error", "That is not Daddy's invite code.");
                }

                let answer = peer.accept_invite(&blob.sdp).await;
                let Ok(sdp) = answer else {
                    set_text("pair-status", "");
                    return set_text("pair-error", "That invite code could not be applied.");
                };

                let reply = Blob {
                    kind: Kind::Reply,
                    sender: Role::Princess,
                    public_key: public,
                    sdp,
                }
                .encode(&secret);

                textarea_by_id("reply-out").set_value(&reply);
                show("reply-ready", true);
                set_text("pair-status", "Send this back to Daddy.");
                finish_handshake(&app, blob.public_key);
            });
        });
    }

    for (button, source, label) in [
        ("copy-invite", "invite-out", "Invite"),
        ("copy-reply", "reply-out", "Reply"),
    ] {
        on_click(button, move || {
            let area = textarea_by_id(source);
            area.focus().ok();
            area.select();

            // execCommand is deprecated but works over plain http, which
            // navigator.clipboard does not: serving on a LAN address is not a
            // secure context, and that is exactly how this gets tested.
            if !exec_copy() {
                if let Some(clipboard) = web_sys::window().map(|w| w.navigator().clipboard()) {
                    let _ = clipboard.write_text(&area.value());
                }
            }

            set_text(
                "pair-status",
                &format!("{label} copied. It is selected too, if you would rather copy it yourself."),
            );
        });
    }
}

/// Both sides reach this once they hold the other's public key. The channel may
/// not be open yet; the room opens when it is.
fn finish_handshake(app: &Shared, their_public: [u8; 32]) {
    let session_key = {
        let a = app.borrow();
        let shared = a.secret.diffie_hellman(&PublicKey::from(their_public));

        let (daddy_public, princess_public) = if a.is_daddy() {
            (a.public, their_public)
        } else {
            (their_public, a.public)
        };
        derive_session_key(
            shared.as_bytes(),
            &a.pairing_secret,
            &daddy_public,
            &princess_public,
        )
    };

    set_text("verify-phrase", &verification_phrase(&session_key));

    {
        let mut a = app.borrow_mut();
        let role = a.role;
        a.session = Some(Session::new(session_key, role));
    }

    let opened = Rc::clone(app);
    let received = Rc::clone(app);
    let closed = Rc::clone(app);

    let peer = Rc::clone(&app.borrow().peer);
    peer.listen(
        move || open_room(&opened),
        move |bytes| {
            // Each borrow is released before the next begins: `handle` reaches
            // back into the same cell.
            let decoded = received
                .borrow_mut()
                .session
                .as_mut()
                .map(|session| session.open_msg(&bytes));

            match decoded {
                Some(Ok(msg)) => received.borrow_mut().handle(msg),
                Some(Err(_)) => received
                    .borrow()
                    .log_system("A frame failed authentication and was dropped."),
                None => {}
            }
        },
        move || {
            set_text("link-state", "disconnected");
            closed
                .borrow()
                .log_system("The connection closed. Reload and pair again.");
        },
    );

    // If the channel opened while the codes were being pasted, no `onopen`
    // will fire — open the room directly.
    if peer.is_open() {
        open_room(app);
    }
}

fn open_room(app: &Shared) {
    if !by_id("room").class_list().contains("hidden") {
        return; // already open
    }

    show("pair", false);
    show("room", true);
    set_text("link-state", "connected, direct");

    {
        let mut a = app.borrow_mut();
        let role = a.role;
        set_text("role-badge", role.as_str());
        show("daddy-controls", Role::Daddy == role);
        show("princess-controls", Role::Princess == role);

        let canvas: web_sys::HtmlCanvasElement =
            by_id("dice").dyn_into().expect("a canvas element");
        match Renderer::new(canvas, &a.geometry) {
            Ok(renderer) => a.renderer = Some(renderer),
            Err(_) => a.log_system("WebGL2 is unavailable, so the die will not be drawn."),
        }

        show_volume(read_volume());
        a.apply_challenge(None);
        a.log_system(&format!("Connected as {}. Compare the phrase above.", role.as_str()));
    }

    wire_room(app);

    if app.borrow().is_daddy() {
        app.borrow_mut().commit_next_round();
    }
    start_frames(app);
}

fn wire_room(app: &Shared) {
    // --- chat, both roles
    {
        let app = Rc::clone(app);
        let send = move || {
            let field = input_by_id("chat-input");
            let text = field.value().trim().to_string();
            if text.is_empty() {
                return;
            }
            field.set_value("");

            let mut a = app.borrow_mut();
            a.sfx.unlock();
            // Answering in words counts as answering.
            a.clear_alert();
            a.send(&Msg::Chat(text.clone()));
            let me = a.role.as_str();
            a.log(me, &text, "me");
        };

        on_click("send", send.clone());

        let closure = Closure::<dyn FnMut(web_sys::KeyboardEvent)>::new(
            move |event: web_sys::KeyboardEvent| {
                if "Enter" == event.key() && !event.shift_key() {
                    event.prevent_default();
                    send();
                }
            },
        );
        input_by_id("chat-input").set_onkeydown(Some(closure.as_ref().unchecked_ref()));
        closure.forget();
    }

    // --- Daddy: set and clear the challenge
    {
        let app = Rc::clone(app);
        on_click("set-challenge", move || {
            let text = input_by_id("challenge-text").value().trim().to_string();
            let threshold = input_by_id("threshold").value().parse::<u8>().unwrap_or(0);

            if text.is_empty() {
                return set_text("challenge-error", "Give the challenge some words.");
            }
            if !(1..=20).contains(&threshold) {
                return set_text("challenge-error", "The threshold must be between 1 and 20.");
            }
            set_text("challenge-error", "");

            let text = text.chars().take(MAX_CHALLENGE).collect::<String>();
            let mut a = app.borrow_mut();
            a.sfx.unlock();
            a.send(&Msg::Challenge {
                text: text.clone(),
                threshold,
            });
            a.apply_challenge(Some((text, threshold)));
            a.log_system(&format!("You set a challenge, needing {threshold} or better."));
        });
    }

    {
        let app = Rc::clone(app);
        on_click("clear-challenge", move || {
            let mut a = app.borrow_mut();
            a.send(&Msg::ClearChallenge);
            a.apply_challenge(None);
            a.log_system("You cleared the challenge.");
        });
    }

    // --- Princess: roll
    {
        let app = Rc::clone(app);
        on_click("roll", move || {
            let mut a = app.borrow_mut();
            a.sfx.unlock();

            if a.is_daddy() || a.animation.is_some() || a.their_commit.is_none() {
                return;
            }
            a.clear_alert();

            let nonce: [u8; 32] = random();
            a.my_nonce = Some(nonce);

            let round = a.round;
            a.send(&Msg::Reveal { round, nonce });
            a.refresh_roll_button();
        });
    }

    // --- sound level
    {
        let app = Rc::clone(app);
        on_change("volume", move || {
            let percent = select_by_id("volume")
                .value()
                .parse::<u8>()
                .unwrap_or(DEFAULT_VOLUME);
            {
                let mut a = app.borrow_mut();
                a.sfx.set_volume(percent as f32 / 100.0);
                // Play it back so the level is audible, not just asserted.
                a.sfx.alert();
            }
            write_volume(percent);
        });
    }

    // --- Princess: send an image or a video
    {
        let app = Rc::clone(app);
        on_click("send-file", move || {
            let input = input_by_id("file-input");
            let Some(file) = input.files().and_then(|list| list.get(0)) else {
                return set_text("transfer-error", "Choose a file first.");
            };
            if app.borrow().sending_file {
                return set_text("transfer-error", "One at a time — a file is already going.");
            }

            // The picker is cleared inside `send_file`, once the file has
            // passed its checks. Clearing here would leave a rejected file
            // showing "No file chosen" beside the error explaining why.
            spawn_local(send_file(Rc::clone(&app), file));
        });
    }
}

/// Read the chosen file and push it over the channel in chunks, pausing
/// whenever the send queue gets long. Runs as a task so the UI stays alive,
/// and never holds an `App` borrow across an await.
async fn send_file(app: Shared, file: web_sys::File) {
    /// Above this many bytes queued, stop feeding the channel and let the
    /// network drain. Without this a large file grows the queue until the
    /// connection dies.
    const HIGH_WATER: u32 = 1 << 20;

    let name = sanitise_name(&file.name());
    let mime = file.type_();

    if !is_previewable(&mime) {
        return set_text("transfer-error", "Only images and videos can be sent.");
    }
    if file.size() as u64 > MAX_FILE_BYTES {
        return set_text(
            "transfer-error",
            &format!(
                "That file is {} — the limit is {}.",
                human_size(file.size() as u64),
                human_size(MAX_FILE_BYTES)
            ),
        );
    }
    // Accepted, so the selection has served its purpose. The `File` handle is
    // already ours and stays valid after the input is cleared.
    input_by_id("file-input").set_value("");
    set_text("transfer-error", "");
    set_text("transfer", &format!("Sending {name}…"));

    let size = file.size() as u64;
    let (peer, id) = {
        let mut a = app.borrow_mut();
        a.next_file_id += 1;
        a.sending_file = true;
        let id = a.next_file_id;
        a.send(&Msg::FileStart {
            id,
            name: name.clone(),
            mime: mime.clone(),
            size,
        });
        (Rc::clone(&a.peer), id)
    };

    let mut sent: u64 = 0;
    let mut last_percent = u8::MAX;

    while sent < size {
        let end = (sent + CHUNK_BYTES as u64).min(size);

        // One slice at a time, never `array_buffer()` on the whole file: that
        // would pull every byte into wasm memory, which a multi-gigabyte file
        // cannot fit in. The f64 overload is required because the i32 one
        // cannot express an offset past 2 GiB.
        let Ok(slice) = file.slice_with_f64_and_f64(sent as f64, end as f64) else {
            return abandon(&app, id, "That file could not be read.");
        };
        let Ok(buffer) = JsFuture::from(slice.array_buffer()).await else {
            return abandon(&app, id, "That file could not be read.");
        };
        let data = js_sys::Uint8Array::new(&buffer).to_vec();

        while peer.buffered_amount() > HIGH_WATER {
            if !peer.is_open() {
                let mut a = app.borrow_mut();
                a.sending_file = false;
                a.log_system("The connection closed part-way through a file.");
                drop(a);
                return set_text("transfer", "");
            }
            sleep_ms(25).await;
        }

        app.borrow_mut().send(&Msg::FileChunk { id, data });
        sent = end;

        // A 4 GiB file is ~147,000 chunks. Writing the DOM on each one would
        // cost more than the transfer.
        let percent = (sent.saturating_mul(100) / size.max(1)).min(100) as u8;
        if percent != last_percent {
            last_percent = percent;
            set_text("transfer", &format!("Sending {name} — {percent}%"));
        }
    }

    {
        let mut a = app.borrow_mut();
        a.send(&Msg::FileEnd { id });
        a.sending_file = false;

        // A File is already a Blob, so the sender's own preview costs nothing
        // and the log reads the same on both screens.
        let me = a.role.as_str();
        if a.append_media(me, &name, &mime, &file).is_err() {
            a.log_system("Sent, but your own browser would not preview it.");
        }
    }
    set_text("transfer", "");
}

/// Give up on a transfer, telling the peer so it drops what it is holding
/// rather than waiting for bytes that will never arrive.
fn abandon(app: &Shared, id: u32, why: &str) {
    {
        let mut a = app.borrow_mut();
        a.send(&Msg::FileAbort {
            id,
            reason: "the sender could not read the file".into(),
        });
        a.sending_file = false;
    }
    set_text("transfer", "");
    set_text("transfer-error", why);
}

/// The animation callback holds a handle to itself so it can re-arm each frame.
type FrameLoop = Rc<RefCell<Option<Closure<dyn FnMut(f64)>>>>;

fn start_frames(app: &Shared) {
    let holder: FrameLoop = Rc::new(RefCell::new(None));
    let next = Rc::clone(&holder);
    let app = Rc::clone(app);

    *holder.borrow_mut() = Some(Closure::new(move |_timestamp: f64| {
        // Re-arm first. If `frame` panics, the loop must still survive:
        // re-arming afterwards means one bad frame freezes the page for the
        // rest of the session, with no visible error to explain it.
        if let Some(callback) = next.borrow().as_ref() {
            request_frame(callback);
        }
        app.borrow_mut().frame(now_seconds());
    }));

    // Kick the loop off, then let `holder` go. The closure keeps itself alive
    // through `next`, which is deliberate: the loop runs for the page's life.
    {
        let first = holder.borrow();
        if let Some(callback) = first.as_ref() {
            request_frame(callback);
        }
    }
}

fn request_frame(callback: &Closure<dyn FnMut(f64)>) {
    if let Some(window) = web_sys::window() {
        let _ = window.request_animation_frame(callback.as_ref().unchecked_ref());
    }
}
