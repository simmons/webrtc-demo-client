webrtc-demo-client: A demonstration Rust WebRTC client
======================================================================

DISCLAIMER
----------------------------------------

This is messy, ugly, hastily written code that is nowhere near my usual
standards, even for experiments.  This code was written in such a way to
answer one question as quickly as possible:  Is the work-in-progress
`webrtc-sctp` crate in its current state sufficient to demonstrate
WebRTC data channel interoperability with a web browser, even though it
lacks critical functionality and the required SCTP extensions?  I
arrived at the answer (yes -- though perhaps barely!) by stringing
together the barest possible implementations of the other required
WebRTC puzzle pieces (SDP parsing, ICE, STUN) and associated plumbing.

There are a number of hacks and shortcuts taken:

1. The client, server, and peer web browser are expected run on the same
   host.
    * No external STUN servers are queried for this client's
      server-reflexive address, and only "host" ICE candidates are
      regarded.
    * The client only considers the first non-loopback IPv4 address as
      its sole ICE candidate.
    * The client only considers peer ICE candidates that match the above
      IP address exactly.  (Due to this and the above, I'd not recommend
      performing this demo on a machine with multiple non-loopback IPv4
      addresses configured.  In other words, don't have a VPN running.)
2. The DTLS Client Hello is not sent immediately after an ICE
   resolution; the demo instead delays one second and then tries to
   initiate DTLS.  (The delay is noticeable in the demo.)
3. The client doesn't verify the certificate fingerprint of the peer.
4. There are lots of `unwrap()`'s. If anything goes wrong in the
   slightest way, the demo panics.

How to run the demo
----------------------------------------

NOTE: At this time, I've only tested this demo on Mac OS 10.11.6.  I don't know
of any particular problems that would arise on other operating systems, but I
suppose there's a possibility that some dependencies (e.g. `openssl` and
`get_if_addrs`) might not work as I expect.

Three crates need to be cloned from GitHub:

1. [`webrtc-demo-client`](https://github.com/simmons/webrtc-demo-client)
   -- This client crate.
2. [`webrtc-demo-server`](https://github.com/simmons/webrtc-demo-server)
   -- This is a simple "Hello, World" WebRTC data channel demonstration.
   This web server communicates with clients via WebSocket, and
   maintains a roster of connected clients.  Use the `demo` branch.
3. [`webrtc-sctp`](https://github.com/simmons/webrtc-sctp) -- This is
   the SCTP implementation which is being demonstrated.  Use the `demo`
   branch.

Set up the repositories:

```
$ mkdir work
$ cd work
$ git clone git@github.com:simmons/webrtc-demo-client.git
$ git clone git@github.com:simmons/webrtc-demo-server.git
$ git clone git@github.com:simmons/webrtc-sctp.git
$ ( cd webrtc-demo-server && git checkout demo )
$ ( cd webrtc-sctp && git checkout demo )
```

Run the server:

```
$ cd webrtc-demo-server
$ cargo run
```

Go to http://localhost:8080/ in your web browser.  (I've tested Chrome and
Firefox.)  You should see the roster with only your web browser listed.

From another terminal, run the client:

```
$ cd webrtc-demo-client
$ cargo run
```

You should see the Rust client now listed in the roster, with a "Chat" button.
Click the Chat button to start the WebRTC data channel.


License
----------------------------------------

This crate is distributed under the terms of both the MIT license and
the Apache License (Version 2.0).  See LICENSE-MIT and LICENSE-APACHE
for details.

#### Contributing

Unless you explicitly state otherwise, any contribution you
intentionally submit for inclusion in the work, as defined in the
Apache-2.0 license, shall be dual-licensed as above, without any
additional terms or conditions.
