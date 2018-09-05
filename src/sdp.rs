//! A very minimally viable SDP parser/generator for WebRTC.

use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::str::FromStr;

use hex;

use error::DemoError;
use ice::{Ice, IcePeer};

#[derive(Debug)]
pub struct Origin {
    pub username: String,
    pub session_id: u64,
    pub session_version: u64,
    pub address: IpAddr,
}

#[derive(Debug)]
pub enum SetupRole {
    Active,
    Passive,
    Actpass,
    Holdconn,
}

#[derive(Debug)]
pub struct SctpMap {
    // "a=sctpmap:5000 webrtc-datachannel 256"
    port: u16, // maps to the port number in the m-line
    application: String,
    streams: u16,
}

#[derive(Debug)]
pub enum Attribute {
    Fingerprint(Vec<u8>),
    SctpMap(SctpMap),
    Setup(SetupRole),
    Mid(String),
    IceUsername(String),
    IcePassword(String),
    Unknown(String, Option<String>),
}

#[derive(Debug)]
pub struct MediaDescription {
    media: String,
    port: u16,
    protocol: String,
    format: Vec<String>,
    attributes: Vec<Attribute>,
}

#[derive(Debug)]
pub struct SessionDescription {
    pub origin: Origin,
    pub attributes: Vec<Attribute>,
    pub media_descriptions: Vec<MediaDescription>,
}

impl FromStr for SessionDescription {
    type Err = DemoError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut origin: Option<Origin> = None;
        let mut attributes = vec![];
        let mut media_descriptions: Vec<MediaDescription> = vec![];
        for line in s.lines() {
            let mut parts = line.splitn(2, '=');
            let mut sdp_type = parts
                .next()
                .filter(|k| k.len() == 1)
                .map(|s| s.chars().next().unwrap())
                .ok_or("cannot parse sdp type")?;
            let mut sdp_value = parts.next().ok_or("cannot parse sdp value")?;
            match sdp_type {
                'v' => if sdp_value != "0" {
                    return Err("unsupported SDP version".into());
                },
                'o' => origin = Some(sdp_value.parse()?),
                'a' => match media_descriptions.last_mut() {
                    Some(md) => md.attributes.push(sdp_value.parse()?),
                    None => attributes.push(sdp_value.parse()?),
                },
                'm' => media_descriptions.push(sdp_value.parse()?),
                _ => {} // Ignore other lines for now.
            };
        }

        Ok(SessionDescription {
            origin: origin.unwrap(),
            attributes,
            media_descriptions,
        })
    }
}

impl ToString for SessionDescription {
    fn to_string(&self) -> String {
        let mut v = vec![];
        v.push(format!("v=0"));
        v.push(format!("o={}", self.origin.to_string()));
        v.push(format!("s=-"));
        v.push(format!("t=0 0"));
        for attribute in self.attributes.iter() {
            v.push(format!("a={}", attribute.to_string()));
        }
        for media_description in self.media_descriptions.iter() {
            v.push(format!("m={}", media_description.to_string()));
            v.push(format!("c=IN IP4 0.0.0.0"));
            for attribute in media_description.attributes.iter() {
                v.push(format!("a={}", attribute.to_string()));
            }
        }

        let mut s = v.join("\r\n");
        s.push_str("\r\n");
        s
    }
}

impl FromStr for Origin {
    type Err = DemoError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut split = s.split_whitespace();
        Ok(Origin {
            username: split.next().ok_or("bad origin")?.to_string(),
            session_id: split
                .next()
                .ok_or("bad origin")?
                .parse()
                .map_err(|e| format!("cannot parse session id: {}", e))?,
            session_version: split
                .next()
                .ok_or("bad origin")?
                .parse()
                .map_err(|e| format!("cannot parse session version: {}", e))?,
            address: {
                split
                    .next()
                    .filter(|nt| nt == &"IN")
                    .ok_or("origin bad net type")?;
                let address_type = split.next().ok_or("origin missing addr type")?;
                let address = split.next().ok_or("origin missing address")?;
                match address_type {
                    "IP4" => IpAddr::V4(address.parse()?),
                    "IP6" => IpAddr::V6(address.parse()?),
                    at => return Err(format!("cannot parse addr type: {:?}", at).into()),
                }
            },
        })
    }
}

impl ToString for Origin {
    fn to_string(&self) -> String {
        format!(
            "{} {} {} IN {} {}",
            self.username,
            self.session_id,
            self.session_version,
            match self.address {
                IpAddr::V4(_) => "IP4",
                IpAddr::V6(_) => "IP6",
            },
            self.address
        )
    }
}

impl FromStr for Attribute {
    type Err = DemoError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut parts = s.splitn(2, ':');
        let name = parts.next().ok_or("missing attribute name")?;
        let value = parts.next();
        Ok(match name {
            "fingerprint" => {
                let value = value.ok_or("missing fingerprint hash")?;
                let mut split = value.split_whitespace();
                split
                    .next()
                    .filter(|h| h == &"sha-256")
                    .ok_or("unsupported or missing hash type")?;
                let hash = hex::decode(
                    split
                        .next()
                        .ok_or("missing hash")?
                        .chars()
                        .filter(|c| *c != ':')
                        .collect::<String>(),
                ).map_err(|_| "error hex-decoding hash")?;
                Attribute::Fingerprint(hash)
            }
            "sctpmap" => {
                Attribute::SctpMap(value.map(|s| s.parse()).ok_or("missing sctpmap value")??)
            }
            "setup" => Attribute::Setup(value.map(|s| s.parse()).ok_or("missing setup value")??),
            "mid" => Attribute::Mid(value.map(|s| s.to_string()).ok_or("missing mid value")?),
            "ice-ufrag" => {
                Attribute::IceUsername(value.map(|s| s.to_string()).ok_or("missing mid value")?)
            }
            "ice-pwd" => {
                Attribute::IcePassword(value.map(|s| s.to_string()).ok_or("missing mid value")?)
            }
            _ => Attribute::Unknown(name.to_string(), value.map(|s| s.to_string())),
        })
    }
}

impl ToString for Attribute {
    fn to_string(&self) -> String {
        match self {
            Attribute::Fingerprint(f) => format!(
                "fingerprint:sha-256 {}",
                f.iter()
                    .map(|b| format!("{:02X}", b))
                    .collect::<Vec<String>>()
                    .join(":")
            ),
            Attribute::SctpMap(sm) => format!("sctpmap:{}", sm.to_string()),
            Attribute::Setup(s) => format!("setup:{}", s.to_string()),
            Attribute::Mid(s) => format!("mid:{}", s.to_string()),
            Attribute::IceUsername(s) => format!("ice-ufrag:{}", s.to_string()),
            Attribute::IcePassword(s) => format!("ice-pwd:{}", s.to_string()),
            Attribute::Unknown(n, v) => match v {
                Some(v) => format!("{}:{}", n, v),
                None => format!("{}", n),
            },
        }
    }
}

impl FromStr for MediaDescription {
    type Err = DemoError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut split = s.split_whitespace();
        Ok(MediaDescription {
            media: split.next().ok_or("bad media description")?.to_string(),
            port: split
                .next()
                .ok_or("missing port in media description")?
                .parse()
                .map_err(|_| "cannot parse media desc port number")?,
            protocol: split
                .next()
                .ok_or("no protocol in media description")?
                .to_string(),
            format: split.map(|s| s.to_string()).collect(),
            attributes: vec![],
        })
    }
}

impl ToString for MediaDescription {
    fn to_string(&self) -> String {
        format!(
            "{} {} {} {}",
            self.media,
            self.port,
            self.protocol,
            self.format.join(" ")
        )
    }
}

impl FromStr for SctpMap {
    type Err = DemoError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut split = s.split_whitespace();
        Ok(SctpMap {
            port: split
                .next()
                .ok_or("sctpmap: no port")?
                .parse()
                .map_err(|_| "sctpmap: cannot parse port number")?,
            application: split.next().ok_or("sctpmap: no app")?.to_string(),
            streams: split
                .next()
                .ok_or("sctpmap: no streams")?
                .parse()
                .map_err(|_| "sctpmap: cannot parse stream number")?,
        })
    }
}

impl ToString for SctpMap {
    fn to_string(&self) -> String {
        format!("{} {} {}", self.port, self.application, self.streams)
    }
}

impl FromStr for SetupRole {
    type Err = DemoError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "active" => SetupRole::Active,
            "passive" => SetupRole::Passive,
            "actpass" => SetupRole::Actpass,
            "holdconn" => SetupRole::Holdconn,
            _ => return Err("cannot parse setup role".into()),
        })
    }
}

impl ToString for SetupRole {
    fn to_string(&self) -> String {
        match self {
            SetupRole::Active => "active",
            SetupRole::Passive => "passive",
            SetupRole::Actpass => "actpass",
            SetupRole::Holdconn => "holdconn",
        }.to_string()
    }
}

//////////////////////////////////////////////////////////////////////

use std::iter::Chain;
use std::slice::Iter;

use rand;

#[derive(Debug)]
pub struct SimpleSession {
    inner: SessionDescription,
}

impl SimpleSession {
    fn media(&self) -> &MediaDescription {
        self.inner.media_descriptions.first().unwrap()
    }
    #[allow(dead_code)]
    fn attrs(&self) -> Chain<Iter<Attribute>, Iter<Attribute>> {
        self.inner
            .media_descriptions
            .first()
            .unwrap()
            .attributes
            .iter()
            .chain(self.inner.attributes.iter())
    }
    #[allow(dead_code)]
    fn fingerprint(&self) -> &[u8] {
        for attribute in self.attrs() {
            if let Attribute::Fingerprint(f) = attribute {
                return &f;
            }
        }
        panic!("no fingerprint");
    }
    #[allow(dead_code)]
    fn sctp_map(&self) -> &SctpMap {
        for attribute in self.attrs() {
            if let Attribute::SctpMap(ref sm) = attribute {
                return sm;
            }
        }
        panic!("no sctp map");
    }
    #[allow(dead_code)]
    fn setup(&self) -> &SetupRole {
        for attribute in self.attrs() {
            if let Attribute::Setup(ref sr) = attribute {
                return sr;
            }
        }
        panic!("no setup role");
    }
    fn mid(&self) -> &str {
        for attribute in self.media().attributes.iter() {
            if let Attribute::Mid(mid) = attribute {
                return mid;
            }
        }
        panic!("no mid");
    }

    // Generate an SDP answer
    pub fn answer(&self, fingerprint: &[u8], ice: &mut Ice) -> SimpleSession {
        // Record the offer's ICE username/password.
        // (This probably isn't the best place to do this.)
        let mut peer_username: Option<String> = None;
        let mut peer_password: Option<String> = None;
        for attribute in self
            .inner
            .media_descriptions
            .first()
            .unwrap()
            .attributes
            .iter()
        {
            match attribute {
                Attribute::IceUsername(u) => peer_username = Some(u.to_string()),
                Attribute::IcePassword(p) => peer_password = Some(p.to_string()),
                _ => {}
            }
        }
        match (peer_username, peer_password) {
            (Some(u), Some(p)) => {
                ice.peer = Some(IcePeer {
                    username: u,
                    password: p,
                });
            }
            _ => {}
        }

        // As per the standard, we advertise the discard port in SDP since we will be negotiating
        // the actual port via ICE.
        const DISCARD_PORT: u16 = 9;
        const SCTP_PORT: u16 = 5000;
        static PROTOCOL: &str = "DTLS/SCTP";
        // Use the IPv4 localhost address in SDP.  The actual address will be negotiated via ICE.
        let address = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));

        // Find the media id from the offer
        let mid = self.mid();

        // Workaround for Firefox:
        // "Firefox only allows up to 2**62-1"
        // https://github.com/nickdesaulniers/node-rtc-peer-connection/issues/25
        let session_id = rand::random::<u64>() & 0x3fffffff_ffffffff;

        let session = SessionDescription {
            origin: Origin {
                username: "-".to_string(),
                session_id,
                session_version: 2,
                address: address,
            },
            attributes: vec![
                // We reflect the mid used in the offer.
                Attribute::Unknown("group".to_string(), Some(format!("BUNDLE {}", mid))),
                Attribute::Unknown("msid-semantic".to_string(), Some("WMS *".to_string())),
            ],
            media_descriptions: vec![MediaDescription {
                media: "application".to_string(),
                port: DISCARD_PORT, // discard port -- use ICE for port number.
                protocol: PROTOCOL.to_string(),
                format: vec![SCTP_PORT.to_string()],
                attributes: vec![
                    Attribute::IceUsername(ice.username.clone()),
                    Attribute::IcePassword(ice.password.clone()),
                    Attribute::Unknown("ice-options".to_string(), Some("trickle".to_string())),
                    Attribute::Fingerprint(fingerprint.to_vec()),
                    Attribute::Setup(SetupRole::Active),
                    // Reflect the mid used in the offer.
                    Attribute::Mid(mid.to_string()),
                    Attribute::SctpMap(SctpMap {
                        port: SCTP_PORT,
                        application: "webrtc-datachannel".to_string(),
                        streams: 1024,
                    }),
                ],
            }],
        };
        SimpleSession { inner: session }
    }
}

impl FromStr for SimpleSession {
    type Err = DemoError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let sd: SessionDescription = s.parse()?;
        let ss = SimpleSession { inner: sd };
        if ss.inner.media_descriptions.len() != 1 {
            return Err("Invalid number of media descriptions".into());
        }

        let mut has_fingerprint = false;
        let mut has_sctpmap = false;
        let mut has_setup = false;
        for attribute in ss
            .inner
            .media_descriptions
            .first()
            .unwrap()
            .attributes
            .iter()
        {
            match attribute {
                Attribute::Fingerprint(_) => has_fingerprint = true,
                Attribute::SctpMap(_) => has_sctpmap = true,
                Attribute::Setup(_) => has_setup = true,
                _ => {}
            }
        }
        for attribute in ss.inner.attributes.iter() {
            match attribute {
                Attribute::Fingerprint(_) => has_fingerprint = true,
                Attribute::SctpMap(_) => has_sctpmap = true,
                Attribute::Setup(_) => has_setup = true,
                _ => {}
            }
        }
        if !has_fingerprint || !has_sctpmap || !has_setup {
            return Err("missing critical attribute(s)".into());
        }

        Ok(ss)
    }
}

impl ToString for SimpleSession {
    fn to_string(&self) -> String {
        self.inner.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Firefox offer
    static SDP1: &str = "v=0\r\no=mozilla...THIS_IS_SDPARTA-62.0 305778100508406010 0 IN IP4 0.0.0.0\r\ns=-\r\nt=0 0\r\na=sendrecv\r\na=fingerprint:sha-256 BA:B2:2E:A4:76:BA:C4:A2:8A:1F:65:40:46:E0:8F:D0:71:45:2B:5B:66:D6:FE:92:C8:F5:52:FA:E2:7B:75:26\r\na=group:BUNDLE sdparta_0\r\na=ice-options:trickle\r\na=msid-semantic:WMS *\r\nm=application 9 DTLS/SCTP 5000\r\nc=IN IP4 0.0.0.0\r\na=sendrecv\r\na=ice-pwd:0c983e9d4b327c3e03b2307929f05437\r\na=ice-ufrag:1db47d87\r\na=mid:sdparta_0\r\na=sctpmap:5000 webrtc-datachannel 256\r\na=setup:actpass\r\na=max-message-size:1073741823\r\n";

    #[test]
    fn test_sdp() {
        let sd: SessionDescription = SDP1.parse().unwrap();
        println!("sdp: {:?}", sd);
        // TODO: verify fields
        println!("sdp rendered:\n{}", sd.to_string());
    }

    #[test]
    fn test_simple_session() {
        let ss: SimpleSession = SDP1.parse().unwrap();
        println!("ss: {:?}", ss);
        // TODO: verify fields
    }

    #[test]
    fn test_hex() {
        use hex;
        static HEX: &str = "BA:B2:2E:A4:76:BA:C4:A2:8A:1F:65:40:46:E0:8F:D0:71:45:2B:5B:66:D6:FE:92:C8:F5:52:FA:E2:7B:75:26";
        let bytes = hex::decode(HEX.chars().filter(|c| *c != ':').collect::<String>()).unwrap();
        println!("bytes: {:?}", bytes);
    }

    #[test]
    fn test_answer() {
        let identity = ::crypto::Identity::generate().unwrap();
        let mut ice = Ice::new();
        let ss: SimpleSession = SDP1.parse().unwrap();
        let answer = ss.answer(&identity.fingerprint, &mut ice);
        println!("answer:\n{}", answer.to_string());
    }
}
