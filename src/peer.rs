use std::io;
use std::net::SocketAddr;

use futures::{Async, AsyncSink, Future, Poll, Sink, StartSend, Stream};
use tokio_codec::{self, Decoder};
use udp::{UdpMuxSet, UdpMuxSocket, UdpStream};

use bytes::Bytes;
use crypto::Identity;
use dtls;
use error::DemoError;
use ice::Ice;
use stun::StunStream;
use tokio_openssl::SslStream;

use tokio_codec::{BytesCodec, Framed};
use webrtc_sctp::stack::lowerlayer::{LowerLayerPacket, LowerLayerProtocol};
use webrtc_sctp::stack::SctpStack;

use tokio_core::reactor::Handle;

static GREETING: &str = "Greetings from the magical land of Rust!";
static FUN_FACTS: &[&str] = &[
    "I'm told I have many excellent traits.",
    "Fun fact: If you printed the entire source code of the Rust compiler and placed the pages one after the other, people would think you're very strange.",
    "I find your Debug implementation to be rather... derivative.",
    "Rust programmers always return what they borrow.",
    "I have mutated the RefCell<Deal>.  Pray I don't mutate it any further.",
    "Abstractions want to be zero-cost.",
    "There's no place like IpAddr::V4(Ipv4Addr::new(127,0,0,1)).",
    "Good artists copy.  Great artists reference count.",
    "I see an Ok(Async::Ready(Self::Item)) in your Future.",
];
const FUN_INITIAL_INTERVAL: u64 = 30;
const FUN_PERIODIC_INTERVAL: u64 = 15;

pub struct PeerConnection {
    socket: UdpMuxSocket,
    pub local_address: SocketAddr,
    stun_stream: StunStream,
}

impl PeerConnection {
    // TODO: The browser may insist on us doing the right thing and sending our own ICE candidate
    // over the signalling channel (websocket).  If this is the case, we can do this in one of two
    // ways:
    // 1. provide an mpsc or oneshot here to send websocket messages.
    // 2. since the UDP socket is open for business at the end of new(), simply send the candidate
    //    from the caller after new() is called.
    pub fn new(handle: Handle, identity: Identity, ice: Ice) -> PeerConnection {
        let peer = ice.candidate.clone().unwrap().address;
        let UdpMuxSet { socket, stun, dtls } = UdpMuxSocket::connect(&peer).unwrap();

        let local_address = socket.local_addr().unwrap();
        info!("Local interface address: {}", local_address);

        // STUN
        let stun_stream = StunStream::new(stun, ice.clone());

        // DTLS
        let dtls_future = dtls::connect(dtls, identity.clone()).unwrap();

        // Process WebRTC-DC protocol here
        let peer_engine = dtls_future
            .and_then(move |dtls_stream| {
                // Convert the DTLS AsyncRead+AsyncWrite to Stream+Sink.
                let dtls_stream = tokio_codec::BytesCodec::new().framed(dtls_stream);
                // Build our SCTP lower-layer protocol based on DTLS.
                let lower_layer =
                    DtlsLowerLayer::new(dtls_stream, local_address.clone(), peer.clone());
                // Initialize SCTP
                let sctp_stack = SctpStack::new_with_lower_layer(Box::new(lower_layer));

                // Handle the top layer in a thread using the SCTP synchronous API, for simplicity.
                use std::thread;
                let mut sctp_handle = sctp_stack.handle();
                thread::spawn(move || {
                    let mut listener = sctp_handle.listen(5000).unwrap();
                    let mut association = listener.accept();

                    // See:
                    // https://tools.ietf.org/html/draft-ietf-rtcweb-data-channel-13#section-8
                    const PPID_DCEP: u32 = 50;
                    const PPID_STRING: u32 = 51;

                    // See:
                    // https://tools.ietf.org/html/draft-ietf-rtcweb-data-protocol-09#section-5.1
                    static DATA_CHANNEL_OPEN: &[u8] = &[
                        // TODO: serialize/deserialize DCEP structures.
                        // This is a DATA_CHANNEL_OPEN message with label "chat".
                        0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00,
                        0x63, 0x68, 0x61, 0x74,
                    ];

                    // A convenience function for send
                    use webrtc_sctp::error::SctpResult;
                    use webrtc_sctp::stack::sync::AssociationHandle;
                    use webrtc_sctp::UserMessage;
                    fn send(
                        association: &mut AssociationHandle,
                        ppid: u32,
                        buffer: &[u8],
                    ) -> SctpResult<()> {
                        use webrtc_sctp::packet::SSN;
                        use webrtc_sctp::packet::TSN;
                        let message = UserMessage {
                            tsn: TSN::new(0),
                            unordered: false,
                            stream_id: 1,
                            ssn: SSN::new(0),
                            payload_protocol_id: ppid,
                            buffer: buffer.to_vec(),
                        };
                        association.send(message)
                    }

                    send(&mut association, PPID_DCEP, DATA_CHANNEL_OPEN).unwrap();
                    send(&mut association, PPID_STRING, GREETING.as_bytes()).unwrap();

                    let mut association_echo = association.clone();
                    thread::spawn(move || {
                        loop {
                            let msg = match association_echo.recv() {
                                Ok(Some(message)) => message,
                                Ok(None) => {
                                    info!("Association closed.");
                                    break;
                                }
                                Err(e) => {
                                    error!("Association error: {}.", e);
                                    break;
                                }
                            };

                            if msg.buffer.contains(&b'\x00') {
                                // Hack to skip past the WebRTC-DC header
                                continue;
                            }
                            let reply =
                                format!("You said: \"{}\"", String::from_utf8_lossy(&msg.buffer));
                            send(&mut association_echo, PPID_STRING, reply.as_bytes()).unwrap();
                        }
                    });

                    let mut association_fun = association.clone();
                    thread::spawn(move || {
                        let mut i: usize = 0;
                        thread::sleep(::std::time::Duration::from_secs(FUN_INITIAL_INTERVAL));
                        loop {
                            let msg = FUN_FACTS[i];
                            i += 1;
                            if i == FUN_FACTS.len() {
                                i = 0;
                            }
                            send(&mut association_fun, PPID_STRING, msg.as_bytes()).unwrap();
                            thread::sleep(::std::time::Duration::from_secs(FUN_PERIODIC_INTERVAL));
                        }
                    });
                });

                sctp_stack
            }).map_err(|error| {
                error!("client error: {:?}", error);
            });

        // BAND-AID: Delay TLS handshake one second
        use std::time::Duration;
        use std::time::Instant;
        use tokio_timer::Delay;
        let client = Delay::new(Instant::now() + Duration::new(1, 0))
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))
            .map_err(|_| ())
            .map(|_| ())
            .and_then(|_| peer_engine);
        handle.spawn(client);

        PeerConnection {
            socket,
            local_address,
            stun_stream,
        }
    }
}

impl Future for PeerConnection {
    type Item = ();
    type Error = DemoError;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        // Poll the mux socket to process any muxing/demuxing
        loop {
            match self.socket.poll()? {
                Async::Ready(Some(())) => {}
                Async::Ready(None) => return Ok(Async::Ready(())),
                Async::NotReady => break,
            }
        }

        // Poll the STUN stream
        loop {
            match self.stun_stream.poll()? {
                Async::Ready(Some(e)) => {
                    // event received
                    info!("STUN event: {:?}", e);
                }
                Async::Ready(None) => return Ok(Async::Ready(())),
                Async::NotReady => break,
            }
        }

        Ok(Async::NotReady)
    }
}

struct DtlsLowerLayer {
    dtls: Framed<SslStream<UdpStream>, BytesCodec>,
    local_address: SocketAddr,
    peer_address: SocketAddr,
}

impl DtlsLowerLayer {
    pub fn new(
        dtls: Framed<SslStream<UdpStream>, BytesCodec>,
        local_address: SocketAddr,
        peer_address: SocketAddr,
    ) -> DtlsLowerLayer {
        DtlsLowerLayer {
            dtls,
            local_address,
            peer_address,
        }
    }
}

impl Stream for DtlsLowerLayer {
    type Item = LowerLayerPacket;
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Option<LowerLayerPacket>, io::Error> {
        match self.dtls.poll()? {
            Async::Ready(Some(bytes)) => {
                trace!("INCOMING DATAGRAM:\n{}", ::util::Hex(&bytes));
                // BytesMut => LowerLayerPacket
                let mut buffer: [u8; 1500] = [0; 1500];
                buffer[..bytes.len()].copy_from_slice(&bytes);
                Ok(Async::Ready(Some(LowerLayerPacket {
                    buffer: buffer,
                    length: bytes.len(),
                    address: self.peer_address.clone(),
                })))
            }
            Async::Ready(None) => return Ok(Async::Ready(None)),
            Async::NotReady => return Ok(Async::NotReady),
        }
    }
}

impl Sink for DtlsLowerLayer {
    type SinkItem = LowerLayerPacket;
    type SinkError = io::Error;

    fn start_send(
        &mut self,
        packet: LowerLayerPacket,
    ) -> StartSend<Self::SinkItem, Self::SinkError> {
        let mut bytes = Bytes::with_capacity(packet.length);
        bytes.extend_from_slice(&packet.buffer[0..packet.length]);

        match self.dtls.start_send(bytes)? {
            AsyncSink::Ready => {
                trace!(
                    "OUTGOING DATAGRAM:\n{}",
                    ::util::Hex(&packet.buffer[0..packet.length])
                );
                self.dtls.poll_complete().unwrap(); // TODO: result?
                Ok(AsyncSink::Ready)
            }
            AsyncSink::NotReady(_) => Ok(AsyncSink::NotReady(packet)),
        }
    }
    fn poll_complete(&mut self) -> Poll<(), Self::SinkError> {
        Ok(Async::Ready(()))
    }
}

impl LowerLayerProtocol for DtlsLowerLayer {
    fn address(&self) -> SocketAddr {
        self.local_address
    }
}
