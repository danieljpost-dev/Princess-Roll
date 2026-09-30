//! Success and failure stings, synthesised rather than sampled.
//!
//! Two oscillators and an envelope cost a few hundred bytes and carry no
//! licensing questions, which matters for a public repo. The context is built
//! lazily on the first user gesture, because browsers refuse to start audio
//! before one.

use wasm_bindgen::JsValue;
use web_sys::{AudioContext, BiquadFilterType, GainNode, OscillatorType};

pub struct Sfx {
    context: Option<AudioContext>,
    /// Everything routes through here, so the level is set in one place
    /// rather than threaded through every note of every sound.
    master: Option<GainNode>,
    /// 0.0 to 1.0.
    volume: f32,
}

impl Sfx {
    pub fn new(volume: f32) -> Self {
        Sfx {
            context: None,
            master: None,
            volume: volume.clamp(0.0, 1.0),
        }
    }

    pub fn set_volume(&mut self, volume: f32) {
        self.volume = volume.clamp(0.0, 1.0);
        if let Some(master) = &self.master {
            master.gain().set_value(self.volume);
        }
    }

    pub fn muted(&self) -> bool {
        0.0 == self.volume
    }

    /// Browsers suspend audio contexts created outside a gesture, so this both
    /// creates and resumes. Audio being unavailable is not worth interrupting
    /// anyone over — the dice still roll in silence.
    ///
    /// Returns owned handles rather than references: a borrow of `self` held
    /// while a sound is built would stop the caller touching anything else.
    fn ready(&mut self) -> Option<(AudioContext, GainNode)> {
        if self.context.is_none() {
            let context = AudioContext::new().ok()?;
            let master = context.create_gain().ok()?;
            master.gain().set_value(self.volume);
            master.connect_with_audio_node(&context.destination()).ok()?;

            self.master = Some(master);
            self.context = Some(context);
        }

        let context = self.context.clone()?;
        if web_sys::AudioContextState::Suspended == context.state() {
            let _ = context.resume();
        }
        Some((context, self.master.clone()?))
    }

    /// Call from any click handler to unblock audio before it is first needed.
    pub fn unlock(&mut self) {
        if self.muted() {
            return;
        }
        let _ = self.ready();
    }

    pub fn success(&mut self) {
        self.play(fanfare);
    }

    pub fn failure(&mut self) {
        self.play(sad_trumpet);
    }

    /// A summons, not a verdict — played when a challenge lands, and as a
    /// preview when the level is changed.
    pub fn alert(&mut self) {
        self.play(chime);
    }

    /// Fires on every chat message, so it is kept short and quiet.
    pub fn blip(&mut self) {
        self.play(blip);
    }

    /// Muted means no oscillators are scheduled at all, rather than scheduled
    /// into a silent gain.
    fn play(&mut self, sound: fn(&AudioContext, &GainNode) -> Result<(), JsValue>) {
        if self.muted() {
            return;
        }
        if let Some((context, out)) = self.ready() {
            let _ = sound(&context, &out);
        }
    }
}

/// An envelope shaped for a short, bright note.
fn envelope(
    context: &AudioContext,
    start: f64,
    duration: f64,
    peak: f32,
) -> Result<GainNode, JsValue> {
    let gain = context.create_gain()?;
    let attack = (duration * 0.12).min(0.03);
    gain.gain().set_value_at_time(0.0001, start)?;
    gain.gain()
        .linear_ramp_to_value_at_time(peak, start + attack)?;
    // Exponential decay cannot reach zero, hence the small floor.
    gain.gain()
        .exponential_ramp_to_value_at_time(0.0001, start + duration)?;
    Ok(gain)
}

/// Rising major arpeggio landing on the octave: the "ta-da".
fn fanfare(context: &AudioContext, out: &GainNode) -> Result<(), JsValue> {
    let now = context.current_time();
    // C5, E5, G5, then C6 held long.
    let notes: [(f32, f64, f64); 4] = [
        (523.25, 0.00, 0.16),
        (659.25, 0.09, 0.16),
        (783.99, 0.18, 0.18),
        (1046.50, 0.30, 0.85),
    ];

    for (frequency, offset, duration) in notes {
        let start = now + offset;

        // A triangle carries the note; a quiet square an octave up gives it
        // the brassy edge that reads as celebratory.
        for (wave, detune, level) in [
            (OscillatorType::Triangle, 1.0, 0.30),
            (OscillatorType::Square, 2.0, 0.055),
        ] {
            let osc = context.create_oscillator()?;
            osc.set_type(wave);
            osc.frequency()
                .set_value_at_time(frequency * detune, start)?;

            let gain = envelope(context, start, duration, level)?;
            osc.connect_with_audio_node(&gain)?;
            gain.connect_with_audio_node(out)?;

            osc.start_with_when(start)?;
            osc.stop_with_when(start + duration + 0.05)?;
        }
    }
    Ok(())
}

/// Two rising bell tones, struck twice. Kept deliberately unlike the win and
/// lose stings: those report a result, this one asks for attention.
fn chime(context: &AudioContext, out: &GainNode) -> Result<(), JsValue> {
    let now = context.current_time();

    // B5 then E6, struck again after a short gap so it reads as a summons
    // rather than a notification blip.
    let strikes: [(f32, f64); 4] = [
        (987.77, 0.00),
        (1318.51, 0.17),
        (987.77, 0.52),
        (1318.51, 0.69),
    ];

    for (frequency, offset) in strikes {
        let start = now + offset;

        // A sine fundamental plus a quiet partial a twelfth above gives the
        // metallic ring of a struck bell without needing a sample.
        for (ratio, level) in [(1.0, 0.26), (3.0, 0.05)] {
            let osc = context.create_oscillator()?;
            osc.set_type(OscillatorType::Sine);
            osc.frequency().set_value_at_time(frequency * ratio, start)?;

            let gain = envelope(context, start, 0.55, level)?;
            osc.connect_with_audio_node(&gain)?;
            gain.connect_with_audio_node(out)?;

            osc.start_with_when(start)?;
            osc.stop_with_when(start + 0.6)?;
        }
    }
    Ok(())
}

/// One short pip. Quieter and briefer than anything else here, because it
/// plays on every message rather than at a moment that matters.
fn blip(context: &AudioContext, out: &GainNode) -> Result<(), JsValue> {
    let start = context.current_time();
    const DURATION: f64 = 0.07;

    let osc = context.create_oscillator()?;
    osc.set_type(OscillatorType::Sine);
    osc.frequency().set_value_at_time(1174.66, start)?;

    // A slight downward slide stops it sounding like an alarm.
    osc.frequency()
        .exponential_ramp_to_value_at_time(880.0, start + DURATION)?;

    let gain = envelope(context, start, DURATION, 0.13)?;
    osc.connect_with_audio_node(&gain)?;
    gain.connect_with_audio_node(out)?;

    osc.start_with_when(start)?;
    osc.stop_with_when(start + DURATION + 0.02)?;
    Ok(())
}

/// The descending "wah-wah-wah-waaah", with the last note bending flat.
fn sad_trumpet(context: &AudioContext, out: &GainNode) -> Result<(), JsValue> {
    let now = context.current_time();
    // Three clipped notes walking down, then a long one that sags.
    let notes: [(f32, f32, f64, f64); 4] = [
        (311.13, 311.13, 0.00, 0.20), // E♭4
        (293.66, 293.66, 0.22, 0.20), // D4
        (277.18, 277.18, 0.44, 0.20), // C#4
        (261.63, 196.00, 0.66, 1.10), // C4 sliding down to G3
    ];

    for (from, to, offset, duration) in notes {
        let start = now + offset;

        let osc = context.create_oscillator()?;
        osc.set_type(OscillatorType::Sawtooth);
        osc.frequency().set_value_at_time(from, start)?;
        if from != to {
            // The sag starts a little after the note does, so the pitch is
            // established before it gives up.
            osc.frequency()
                .set_value_at_time(from, start + duration * 0.35)?;
            osc.frequency()
                .linear_ramp_to_value_at_time(to, start + duration)?;
        }

        // Rolling off the top turns a buzzy sawtooth into something horn-like.
        let filter = context.create_biquad_filter()?;
        filter.set_type(BiquadFilterType::Lowpass);
        filter.frequency().set_value_at_time(1400.0, start)?;
        filter
            .frequency()
            .linear_ramp_to_value_at_time(700.0, start + duration)?;
        filter.q().set_value_at_time(4.0, start)?;

        let gain = envelope(context, start, duration, 0.26)?;

        osc.connect_with_audio_node(&filter)?;
        filter.connect_with_audio_node(&gain)?;
        gain.connect_with_audio_node(out)?;

        osc.start_with_when(start)?;
        osc.stop_with_when(start + duration + 0.05)?;
    }
    Ok(())
}
