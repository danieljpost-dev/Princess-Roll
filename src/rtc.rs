//! The direct browser-to-browser link.
//!
//! Vanilla ICE, not trickle: the offer is only handed over once candidate
//! gathering has finished, so the whole connection description fits in one
//! string you can paste. That is what makes a signalling server unnecessary.
//!
//! Every method takes `&self`, with mutation kept behind `RefCell`s that are
//! never borrowed across an `await`. That is deliberate — holding a borrow
//! across a suspension point is how an app like this earns a `BorrowMutError`
//! the first time a message arrives mid-handshake.

use js_sys::Uint8Array;
use std::cell::RefCell;
use std::rc::Rc;
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::JsFuture;
use web_sys::{
    MessageEvent, RtcConfiguration, RtcDataChannel, RtcDataChannelEvent, RtcDataChannelState,
    RtcDataChannelType, RtcIceGatheringState, RtcPeerConnection, RtcSdpType,
    RtcSessionDescriptionInit,
};

/// Public STUN only. A TURN relay would hide the peers' addresses from each
/// other, but it would also mean running a server, which this design does not.
const STUN_SERVERS: [&str; 3] = [
    "stun:stun.l.google.com:19302",
    "stun:stun1.l.google.com:19302",
    "stun:stun.cloudflare.com:3478",
];

/// If gathering stalls behind a firewall, stop waiting and use whatever
/// candidates we have — often enough to connect, and better than hanging.
const GATHER_TIMEOUT_MS: i32 = 6000;

/// A JS callback the Rust side must keep alive. Dropping one of these while the
/// browser still holds the function pointer is a use-after-free.
type Stored<F> = RefCell<Option<Closure<F>>>;

/// The channel callbacks, shared so that whoever ends up holding the channel
/// can attach them — including the `ondatachannel` event, which fires long
/// after `listen` on the answering side.
#[derive(Default)]
struct Handlers {
    on_open: Stored<dyn FnMut()>,
    on_message: Stored<dyn FnMut(MessageEvent)>,
    on_close: Stored<dyn FnMut()>,
}

impl Handlers {
    fn attach(&self, channel: &RtcDataChannel) {
        if let Some(open) = self.on_open.borrow().as_ref() {
            channel.set_onopen(Some(open.as_ref().unchecked_ref()));
        }
        if let Some(message) = self.on_message.borrow().as_ref() {
            channel.set_onmessage(Some(message.as_ref().unchecked_ref()));
        }
        if let Some(close) = self.on_close.borrow().as_ref() {
            channel.set_onclose(Some(close.as_ref().unchecked_ref()));
        }

        // A channel can already be open by the time we get our hands on it, in
        // which case `onopen` has been and gone. Fire it ourselves rather than
        // wait for an event that will never come.
        if RtcDataChannelState::Open == channel.ready_state() {
            if let Some(open) = self.on_open.borrow().as_ref() {
                let f: &js_sys::Function = open.as_ref().unchecked_ref();
                let _ = f.call0(&JsValue::NULL);
            }
        }
    }
}

pub struct Peer {
    pc: RtcPeerConnection,
    channel: Rc<RefCell<Option<RtcDataChannel>>>,
    handlers: Rc<Handlers>,
    on_datachannel: Stored<dyn FnMut(RtcDataChannelEvent)>,
}

impl Peer {
    pub fn new() -> Result<Peer, JsValue> {
        let ice_servers = js_sys::Array::new();
        for url in STUN_SERVERS {
            let server = js_sys::Object::new();
            js_sys::Reflect::set(&server, &"urls".into(), &url.into())?;
            ice_servers.push(&server);
        }

        let config = RtcConfiguration::new();
        config.set_ice_servers(&ice_servers);

        Ok(Peer {
            pc: RtcPeerConnection::new_with_configuration(&config)?,
            channel: Rc::new(RefCell::new(None)),
            handlers: Rc::new(Handlers::default()),
            on_datachannel: RefCell::new(None),
        })
    }

    /// Daddy's side: open the channel, describe ourselves, and wait until the
    /// description is complete enough to hand over in one piece.
    pub async fn create_invite(&self) -> Result<String, JsValue> {
        let channel = self.pc.create_data_channel("princess-roll");
        channel.set_binary_type(RtcDataChannelType::Arraybuffer);
        self.handlers.attach(&channel);
        *self.channel.borrow_mut() = Some(channel);

        let offer = JsFuture::from(self.pc.create_offer()).await?;
        let sdp = sdp_of(&offer)?;

        let description = RtcSessionDescriptionInit::new(RtcSdpType::Offer);
        description.set_sdp(&sdp);
        JsFuture::from(self.pc.set_local_description(&description)).await?;

        self.await_ice_gathering().await?;
        self.local_sdp()
    }

    /// Princess's side: take his description and produce ours.
    ///
    /// Her channel does not exist yet — it arrives later, from his end, as an
    /// `ondatachannel` event. The handler must therefore attach the callbacks
    /// itself; waiting for `listen` to do it would mean waiting forever.
    pub async fn accept_invite(&self, remote_sdp: &str) -> Result<String, JsValue> {
        let channel_slot = Rc::clone(&self.channel);
        let handlers = Rc::clone(&self.handlers);

        let handler =
            Closure::<dyn FnMut(RtcDataChannelEvent)>::new(move |event: RtcDataChannelEvent| {
                let channel = event.channel();
                channel.set_binary_type(RtcDataChannelType::Arraybuffer);
                handlers.attach(&channel);
                *channel_slot.borrow_mut() = Some(channel);
            });
        self.pc
            .set_ondatachannel(Some(handler.as_ref().unchecked_ref()));
        *self.on_datachannel.borrow_mut() = Some(handler);

        let offer = RtcSessionDescriptionInit::new(RtcSdpType::Offer);
        offer.set_sdp(remote_sdp);
        JsFuture::from(self.pc.set_remote_description(&offer)).await?;

        let answer = JsFuture::from(self.pc.create_answer()).await?;
        let sdp = sdp_of(&answer)?;

        let description = RtcSessionDescriptionInit::new(RtcSdpType::Answer);
        description.set_sdp(&sdp);
        JsFuture::from(self.pc.set_local_description(&description)).await?;

        self.await_ice_gathering().await?;
        self.local_sdp()
    }

    /// Daddy's side again: her reply completes the handshake.
    pub async fn accept_reply(&self, remote_sdp: &str) -> Result<(), JsValue> {
        let answer = RtcSessionDescriptionInit::new(RtcSdpType::Answer);
        answer.set_sdp(remote_sdp);
        JsFuture::from(self.pc.set_remote_description(&answer)).await?;
        Ok(())
    }

    fn local_sdp(&self) -> Result<String, JsValue> {
        self.pc
            .local_description()
            .map(|d| d.sdp())
            .ok_or_else(|| JsValue::from_str("the browser produced no local description"))
    }

    /// Resolves when the browser says gathering is complete, or when the
    /// timeout fires — whichever comes first.
    async fn await_ice_gathering(&self) -> Result<(), JsValue> {
        if RtcIceGatheringState::Complete == self.pc.ice_gathering_state() {
            return Ok(());
        }

        let pc = self.pc.clone();
        let promise = js_sys::Promise::new(&mut |resolve, _reject| {
            let settled = Rc::new(RefCell::new(false));

            let finish = {
                let settled = Rc::clone(&settled);
                let resolve = resolve.clone();
                move || {
                    // Read and release before resolving: the continuation must
                    // never find this cell still borrowed.
                    let already = *settled.borrow();
                    if !already {
                        *settled.borrow_mut() = true;
                        let _ = resolve.call0(&JsValue::NULL);
                    }
                }
            };

            let on_change = {
                let pc = pc.clone();
                let finish = finish.clone();
                Closure::<dyn FnMut()>::new(move || {
                    if RtcIceGatheringState::Complete == pc.ice_gathering_state() {
                        finish();
                    }
                })
            };
            pc.set_onicegatheringstatechange(Some(on_change.as_ref().unchecked_ref()));

            let on_timeout = Closure::<dyn FnMut()>::new(finish);
            if let Some(window) = web_sys::window() {
                let _ = window.set_timeout_with_callback_and_timeout_and_arguments_0(
                    on_timeout.as_ref().unchecked_ref(),
                    GATHER_TIMEOUT_MS,
                );
            }

            // Both closures must outlive this scope. The peer connection lives
            // for the whole page, so this is a bounded, one-time cost.
            on_change.forget();
            on_timeout.forget();
        });

        JsFuture::from(promise).await?;
        self.pc.set_onicegatheringstatechange(None);
        Ok(())
    }

    /// Register the channel callbacks. Safe to call whether or not the channel
    /// exists yet: if it does they are attached now, and if it does not the
    /// `ondatachannel` handler attaches them the moment it arrives.
    pub fn listen(
        &self,
        on_open: impl FnMut() + 'static,
        mut on_message: impl FnMut(Vec<u8>) + 'static,
        on_close: impl FnMut() + 'static,
    ) {
        *self.handlers.on_open.borrow_mut() = Some(Closure::<dyn FnMut()>::new(on_open));
        *self.handlers.on_close.borrow_mut() = Some(Closure::<dyn FnMut()>::new(on_close));
        *self.handlers.on_message.borrow_mut() = Some(Closure::<dyn FnMut(MessageEvent)>::new(
            move |event: MessageEvent| {
                let data = event.data();
                if let Some(buffer) = data.dyn_ref::<js_sys::ArrayBuffer>() {
                    on_message(Uint8Array::new(buffer).to_vec());
                }
            },
        ));

        let channel = self.channel.borrow();
        if let Some(channel) = channel.as_ref() {
            self.handlers.attach(channel);
        }
    }

    pub fn is_open(&self) -> bool {
        self.channel
            .borrow()
            .as_ref()
            .is_some_and(|c| RtcDataChannelState::Open == c.ready_state())
    }

    /// Bytes queued in the channel but not yet on the wire. A file transfer
    /// must watch this: pushing chunks in faster than the network drains them
    /// grows the queue without bound and eventually kills the connection.
    pub fn buffered_amount(&self) -> u32 {
        self.channel
            .borrow()
            .as_ref()
            .map_or(0, |channel| channel.buffered_amount())
    }

    pub fn send(&self, payload: &[u8]) -> Result<(), JsValue> {
        match self.channel.borrow().as_ref() {
            Some(channel) => channel.send_with_u8_array(payload),
            None => Err(JsValue::from_str("the connection is not open yet")),
        }
    }
}

fn sdp_of(description: &JsValue) -> Result<String, JsValue> {
    js_sys::Reflect::get(description, &"sdp".into())?
        .as_string()
        .ok_or_else(|| JsValue::from_str("the browser returned a description with no SDP"))
}
