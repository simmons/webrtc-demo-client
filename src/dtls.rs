use std::io;

use futures;
use futures::Future;
use openssl::ssl::{SslConnector, SslMethod, SslVerifyMode};
use tokio_openssl::{SslConnectorExt, SslStream};

use crypto::Identity;
use udp::UdpStream;

/// When in client mode, we provide this domain name to OpenSSL for the purposes of verifying the
/// domain name embedded in the server certificate.  (Since we don't actually verify the
/// certificate, this isn't actually used for anything.)
static SERVER_DOMAIN: &'static str = "server";

/// Provision an `SslConnector` for clients.
fn ssl_connector(identity: Identity) -> Result<SslConnector, io::Error> {
    let mut connector_builder = SslConnector::builder(SslMethod::dtls())?;
    // Disable certificate checking, since it's not practical to make users deal with public key
    // infrastructure just to see this example code work.
    // OMG DON'T EVER DO THIS IN PRODUCTION CODE!  CUT-AND-PASTE ENTHUSIASTS BE WARNED!
    // Certificate verification is critical to avoid man-in-the-middle attacks!
    connector_builder.set_verify(SslVerifyMode::NONE);

    // This does not appear to have any effect.  Wireshark still reports "DTLSv1.0".
    use openssl::ssl::SslOptions;
    let mut options = connector_builder.options();
    options.set(SslOptions::NO_DTLSV1, true);
    connector_builder.set_options(options);

    // Set the client certificate
    connector_builder.set_certificate(&identity.certificate)?;
    connector_builder.set_private_key(&identity.private_key)?;
    connector_builder.check_private_key()?;

    let connector = connector_builder.build();
    Ok(connector)
}

/// Run as a client by connecting to the peer, performing the DTLS handshake, and forwarding
/// to/from standard output/input.
pub fn connect(
    stream: UdpStream,
    identity: Identity,
) -> Result<impl Future<Item = SslStream<UdpStream>, Error = io::Error>, io::Error> {
    let connector = ssl_connector(identity)?;
    let domain = SERVER_DOMAIN;

    let client = futures::future::ok(()).and_then(move |_| {
        connector
            .connect_async(&domain, stream)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))
    });
    Ok(client)
}
