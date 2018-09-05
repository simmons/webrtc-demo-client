extern crate futures;
extern crate hex;
extern crate openssl;
extern crate serde;
extern crate serde_json;
#[macro_use]
extern crate serde_derive;
extern crate bytes;
extern crate foreign_types;
extern crate get_if_addrs;
extern crate libc;
extern crate openssl_sys;
extern crate rand;
extern crate tokio;
extern crate tokio_codec;
extern crate tokio_openssl;
extern crate tokio_tungstenite;
extern crate tungstenite;
extern crate url;
#[macro_use]
extern crate log;
extern crate crc;
extern crate env_logger;
extern crate tokio_core;
extern crate tokio_timer;
extern crate webrtc_sctp;

use std::io;
use std::net::SocketAddr;

use futures::{Future, Sink, Stream};
use tungstenite::Message;

mod crypto;
mod dtls;
mod error;
mod ice;
mod peer;
mod sdp;
mod stun;
mod udp;
mod util;
mod websocket;

use ice::{Candidate, CandidateType, Ice, Transport};
use peer::PeerConnection;
use sdp::SimpleSession;
use websocket::{ClientMessage, RelayEnvelope, RelayPayload};

static WS_URL: &str = "ws://127.0.0.1:8080/ws";

fn main() {
    // Initialize the logging system, applying a default RUST_LOG if it is not already set.
    if let Err(_) = ::std::env::var("RUST_LOG") {
        ::std::env::set_var("RUST_LOG", "webrtc_demo_client=info,webrtc_sctp=trace");
    }
    env_logger::init();

    // Generate a new private key and self-signed certificate for this session.
    let identity = crypto::Identity::generate().unwrap();
    // Generate a new ICE context for this session.
    let mut ice = Ice::new();

    // Use tokio_core for compatibility with the current SCTP code which expects an old-style
    // single-threaded reactor.
    // TODO: Use new tokio API with multi-threaded reactor.
    use tokio_core::reactor::Core;
    let mut core = Core::new().unwrap();
    let handle = core.handle();

    let url = url::Url::parse(WS_URL).unwrap();
    let client = tokio_tungstenite::connect_async(url)
        .and_then(move |(ws_stream, _)| {
            let (mut sink, stream) = ws_stream.split();
            stream.for_each(move |message| {
                match message {
                    Message::Text(m) => {
                        let message = websocket::parse_message(&m);
                        match message {
                            ClientMessage::Relay(r) => {
                                let peer_name = r.name.clone();
                                let message = match RelayEnvelope::unpack(&r) {
                                    Ok(m) => m,
                                    Err(e) => panic!("error: {}", e),
                                };
                                match message.payload {
                                    RelayPayload::Sdp(ref sdp) => {
                                        if sdp.type_ != "offer" {
                                            panic!("received non-offer SDP");
                                        }
                                        let session: SimpleSession = sdp.sdp.parse().unwrap();
                                        info!("SDP recv:\n{}", session.to_string());
                                        let answer = session.answer(&identity.fingerprint, &mut ice);
                                        info!("SDP send:\n{}", answer.to_string());
                                        let msg = Message::text(websocket::encode_answer(&answer, &message, &peer_name).unwrap());
                                        // TODO: this returns a future that needs to be driven.
                                        sink.start_send(msg).unwrap();
                                    }
                                    RelayPayload::Ice(ice_msg) => {
                                        let candidate: Candidate = ice_msg.candidate.parse().unwrap();
                                        info!("ICE: recv candidate: {:?}", candidate);

                                        // HACK: For this demo, we're only looking at "host" type
                                        // candidates -- not the server-reflexive candidates that
                                        // would be needed for NAT traversal.
                                        if candidate.type_ == CandidateType::Host && candidate.transport == Transport::UDP {
                                            if let SocketAddr::V4(s) = candidate.address {
                                                info!("Peer IPv4 address: {}", candidate.address);

                                                // HACK: For this same-host demonstration, we can
                                                // just look for the peer IP that matches our IP.
                                                if s.ip() == &util::get_local_address() {
                                                    ice.candidate = Some(candidate);
                                                    let peer = PeerConnection::new(handle.clone(), identity.clone(), ice.clone());

                                                    // Provide our ICE candidate to the peer
                                                    let local_candidate = Candidate {
                                                        foundation: "1".to_string(),
                                                        transport: Transport::UDP,
                                                        address: peer.local_address,
                                                        type_: CandidateType::Host,
                                                        username: ice.username.clone(),
                                                    };
                                                    let msg = Message::text(websocket::encode_candidate(&local_candidate, &ice_msg.sdp_mid, &peer_name).unwrap());
                                                    // TODO: this returns a future that needs to be driven.
                                                    sink.start_send(msg).unwrap();

                                                    handle.spawn(peer.map_err(|e| { error!("peer connection error: {}", e); () }));
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                            _ => {}
                        }
                    }
                    _ => {
                        warn!("Unsupported WS message received: {:?}", message);
                    }
                };

                Ok(())
            })
        }).map_err(|e| {
            error!("Error connecting to websocket: {}", e);
            io::Error::new(io::ErrorKind::Other, e)
        });

    core.run(client.map_err(|_e| ())).unwrap();
    //tokio::runtime::run(client.map_err(|_e| ()));
}
