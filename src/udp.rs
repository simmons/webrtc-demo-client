//! This module provides practical tools for using UDP in Tokio.  The `UdpMuxSocket` struct actually
//! owns a UDP server socket, and dispatches to child `UdpStream` pseudo-sockets as needed
//! according to the peer address and port number.

use std::io;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use bytes::Bytes;
use futures::sync::mpsc;
use futures::{Async, AsyncSink, Poll, Sink, StartSend, Stream};
use tokio;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::UdpSocket;

// A typical MTU (including IP and UDP headers) is 1500, but we don't actually address MTU concerns
// in this code.
const MAX_DATAGRAM: usize = 2048;

// We can buffer this many datagrams in the server for each child.
const UDP_STREAM_BUFFER_DATAGRAMS: usize = 8;

/// Return the address used to bind to all interfaces (INADDR_ANY or IN6ADDR_ANY) that is
/// appropriate for communicating with the provided peer address.
fn global_bind_address(peer_address: &SocketAddr) -> SocketAddr {
    #[inline]
    fn inaddr_any() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0))
    }

    #[inline]
    fn in6addr_any() -> IpAddr {
        IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0))
    }

    match peer_address {
        SocketAddr::V4(_) => SocketAddr::new(inaddr_any(), 0),
        SocketAddr::V6(_) => SocketAddr::new(in6addr_any(), 0),
    }
}

/// Bundle a mux socket with its constituent demuxed streams.  It is expected that the caller will
/// destructure this and move the streams around as needed.
pub struct UdpMuxSet {
    pub socket: UdpMuxSocket,
    pub stun: UdpStream,
    pub dtls: UdpStream,
}

/// A `UdpMuxSocket` (de-)multiplexes a single UDP socket to allow multiple protocols to be handled by
/// distinct streams/sinks, as determined by the leading byte of the payload.
pub struct UdpMuxSocket {
    socket: UdpSocket,
    stun_child: UdpChild,
    dtls_child: UdpChild,
    incoming_datagram: Option<Bytes>,
    #[allow(dead_code)]
    peer: SocketAddr,
}

impl UdpMuxSocket {
    /// Create a new `UdpMuxSocket` that is "connected" to the specified peer.
    pub fn connect(peer_address: &SocketAddr) -> Result<UdpMuxSet, tokio::io::Error> {
        info!("Creating UDP socket: {:?}", peer_address);

        let bind_address = global_bind_address(peer_address);
        let socket = UdpSocket::bind(&bind_address)?;
        socket.connect(peer_address)?;

        let (stun_child, stun_stream) = Self::create_child(peer_address);
        let (dtls_child, dtls_stream) = Self::create_child(peer_address);
        // TODO: Do something with streams!

        let mux_socket = UdpMuxSocket {
            socket,
            stun_child,
            dtls_child,
            incoming_datagram: None,
            peer: peer_address.clone(),
        };
        Ok(UdpMuxSet {
            socket: mux_socket,
            stun: stun_stream,
            dtls: dtls_stream,
        })
    }

    fn create_child(peer: &SocketAddr) -> (UdpChild, UdpStream) {
        let (incoming_tx, incoming_rx) = mpsc::channel(UDP_STREAM_BUFFER_DATAGRAMS);
        let (outgoing_tx, outgoing_rx) = mpsc::channel(UDP_STREAM_BUFFER_DATAGRAMS);
        let stream = UdpStream {
            outgoing_tx,
            incoming_rx,
            peer: peer.clone(),
        };
        let child = UdpChild {
            incoming_tx,
            outgoing_rx,
            outgoing_datagram: None,
        };
        (child, stream)
    }

    pub fn local_addr(&self) -> Result<SocketAddr, tokio::io::Error> {
        self.socket.local_addr()
    }
}

// TODO: This could be just a future instead of a stream, ever since we changed it to yield ().

impl Stream for UdpMuxSocket {
    type Item = ();
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Option<()>, io::Error> {
        // Process outgoing datagrams for each child
        'outer: for child in [&mut self.stun_child, &mut self.dtls_child].iter_mut() {
            // Process any pending datagrams first.
            if let Some(datagram) = child.outgoing_datagram.take() {
                match self.socket.poll_send(&datagram) {
                    Ok(Async::Ready(_)) => {}
                    Ok(Async::NotReady) => {
                        // Try again later.
                        child.outgoing_datagram = Some(datagram);
                        break;
                    }
                    Err(e) => {
                        error!("Error sending to socket: {:?}", e);
                    }
                }
            }

            // Pull datagrams from the outgoing queue to send.
            loop {
                match child.outgoing_rx.poll() {
                    Ok(Async::Ready(Some(datagram))) => {
                        match self.socket.poll_send(&datagram) {
                            Ok(Async::Ready(_)) => {}
                            Ok(Async::NotReady) => {
                                // Try again later.
                                child.outgoing_datagram = Some(datagram);
                                break 'outer;
                            }
                            Err(e) => {
                                error!("Error sending to socket: {:?}", e);
                            }
                        }
                    }
                    Ok(Async::Ready(None)) => {
                        continue 'outer;
                    }
                    Ok(Async::NotReady) => break,
                    Err(e) => {
                        error!("Error dequeueing outgoing datagram: {:?}", e);
                        break 'outer;
                    }
                };
            }
        }

        // Process any incoming datagrams and dispatch to child streams according the first byte of
        // the payload, which serves as a discriminator. (See: RFC 7983)
        let mut buffer: [u8; MAX_DATAGRAM] = [0; MAX_DATAGRAM];
        loop {
            // Fetch the next datagram to process -- either a previously parked incoming datagram,
            // or the next polled datagram from the stream (if available).
            let payload = match self.incoming_datagram.take() {
                Some(datagram) => datagram,
                None => match self.socket.poll_recv(&mut buffer) {
                    Ok(Async::Ready(nbytes)) => {
                        let payload: Bytes = buffer[0..nbytes].into();
                        payload
                    }
                    Ok(Async::NotReady) => return Ok(Async::NotReady),
                    Err(e) => {
                        error!("UdpMuxSocket: error: {:?}", e);
                        return Err(e);
                    }
                },
            };

            // We use the first byte of payload as a discriminator.
            let discriminator = match payload.get(0) {
                Some(d) => d.clone(),
                None => {
                    warn!("Zero-byte payload received -- dropping.");
                    continue;
                }
            };

            {
                // See RFC 7983
                let child = match discriminator {
                    0..=3 => &mut self.stun_child,
                    20..=63 => &mut self.dtls_child,
                    _ => {
                        warn!(
                            "Unrecognized payload discriminator ({}) -- dropping.",
                            discriminator
                        );
                        continue;
                    }
                };

                // Dispatch the incoming datagram to the stream.
                debug!("dispatching {} bytes of payload.", payload.len());
                trace!("Payload:\n{}", ::util::hex(&payload));
                match child.incoming_tx.try_send(payload) {
                    Ok(()) => {}
                    Err(e) => {
                        if e.is_full() {
                            // Park the incoming datagram until we can send it.
                            self.incoming_datagram = Some(e.into_inner());
                            // Don't process any more incoming datagrams until the parked datagram
                            // is processed.  (Otherwise we might drop our parked datagram if
                            // another incoming datagram needs parking.)  This does mean that one
                            // stream that is slow to process can block all the others.
                            return Ok(Async::NotReady);
                        } else {
                            error!("Error: Can't send to child stream: {:?}", e);
                        }
                    }
                };
            }
        }
    }
}

/// This is the private child, owned by the `UdpMuxSocket`, used for communicating with the
/// `UdpStream` supplied to the caller.
struct UdpChild {
    incoming_tx: mpsc::Sender<Bytes>,
    outgoing_rx: mpsc::Receiver<Bytes>,
    outgoing_datagram: Option<Bytes>,
}

/// Provide a virtual UDP socket which communicates with a single peer via the UdpMuxSocket.
pub struct UdpStream {
    outgoing_tx: mpsc::Sender<Bytes>,
    incoming_rx: mpsc::Receiver<Bytes>,
    pub peer: SocketAddr,
}

impl Stream for UdpStream {
    type Item = Bytes;
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Option<Bytes>, io::Error> {
        let payload = match self.incoming_rx.poll() {
            Ok(Async::Ready(Some(t))) => t,
            Ok(Async::Ready(None)) => {
                info!("Socket closing.");
                return Ok(Async::Ready(None));
            }
            Ok(Async::NotReady) => return Ok(Async::NotReady),
            Err(e) => {
                error!("Error receiving incoming datagram: {:?}", e);
                return Ok(Async::NotReady);
            }
        };

        debug!("received payload: {} bytes", payload.len());

        Ok(Async::Ready(Some(payload)))
    }
}

impl Sink for UdpStream {
    type SinkItem = Bytes;
    type SinkError = io::Error;

    fn start_send(&mut self, payload: Bytes) -> StartSend<Self::SinkItem, Self::SinkError> {
        self.outgoing_tx.start_send(payload)
            // An error usually means the receiver is dropped; i.e. socket is closed.
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))
    }

    fn poll_complete(&mut self) -> Poll<(), Self::SinkError> {
        self.outgoing_tx
            .poll_complete()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))
    }
}

impl Read for UdpStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self.poll() {
            Ok(Async::Ready(Some(msg))) => {
                let nbytes = msg.len();
                if nbytes > buf.len() {
                    return Err(io::Error::new(io::ErrorKind::Other, "buffer overrun"));
                }
                buf[..nbytes].copy_from_slice(&msg[..]);
                Ok(nbytes)
            }
            Ok(Async::Ready(None)) => Ok(0),
            Ok(Async::NotReady) => Err(io::Error::new(io::ErrorKind::WouldBlock, "")),
            Err(e) => Err(e),
        }
    }
}

impl AsyncRead for UdpStream {}

impl Write for UdpStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self.start_send(buf.into()) {
            Ok(AsyncSink::Ready) => Ok(buf.len()),
            Ok(AsyncSink::NotReady(_)) => Err(io::Error::new(io::ErrorKind::WouldBlock, "")),
            Err(e) => Err(e),
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl AsyncWrite for UdpStream {
    fn shutdown(&mut self) -> Result<Async<()>, tokio::io::Error> {
        Ok(Async::Ready(()))
    }
}
