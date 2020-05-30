use std::net::SocketAddr;
use std::str::FromStr;

use hex;
use rand::{self, RngCore};

use error::DemoError;
use util;

#[derive(Clone)]
pub struct IcePeer {
    pub username: String,
    pub password: String,
}

#[derive(Clone)]
pub struct Ice {
    pub username: String,
    pub password: String,
    pub candidate: Option<Candidate>,
    pub peer: Option<IcePeer>,
}

impl Ice {
    pub fn new() -> Ice {
        let mut username_bytes: Vec<u8> = vec![0; 4];
        let mut password_bytes: Vec<u8> = vec![0; 16];
        rand::thread_rng().fill_bytes(&mut username_bytes);
        rand::thread_rng().fill_bytes(&mut password_bytes);
        Ice {
            username: hex::encode(username_bytes),
            password: hex::encode(password_bytes),
            candidate: None,
            peer: None,
        }
    }
}

#[derive(Clone, Debug)]
pub struct Candidate {
    pub foundation: String,
    pub transport: Transport,
    pub address: SocketAddr,
    pub type_: CandidateType,
    pub username: String,
}

impl FromStr for Candidate {
    type Err = DemoError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        static PREFIX: &str = "candidate:";
        if !s.starts_with(PREFIX) {
            return Err("no candidate prefix".into());
        }
        let s = &s[PREFIX.len()..];
        let mut split = s.split_whitespace();
        let foundation = split.next().ok_or("bad foundation")?.to_string();
        split
            .next()
            .filter(|s| s == &"1")
            .ok_or("bad component id")?;
        let transport = split
            .next()
            .ok_or("bad transport")?
            .parse()
            .map_err(|_| "cannot parse transport")?;
        split.next(); // priority
        let ip = split.next().ok_or("bad ip")?;
        let port = split.next().ok_or("bad port")?;
        let address = SocketAddr::new(
            // TODO: detect ".local" domains and perform mDNS lookups
            ip.parse().unwrap_or(util::get_local_address().into()),
            port.parse().map_err(|_| "cannot parse port number")?,
        );
        split.next().filter(|s| s == &"typ").ok_or("no typ")?;
        let type_ = split
            .next()
            .ok_or("no type")?
            .parse()
            .map_err(|_| "bad type")?;
        // ignore rest

        Ok(Candidate {
            foundation,
            transport,
            address,
            type_,
            username: String::new(),
        })
    }
}

impl ToString for Candidate {
    fn to_string(&self) -> String {
        format!(
            "candidate:{} 1 {} 2113937151 {} {} typ {} generation 0 ufrag {} network-cost 50",
            self.foundation,
            self.transport.to_string(),
            self.address.ip(),
            self.address.port(),
            self.type_.to_string(),
            self.username
        )
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum Transport {
    UDP,
    TCP,
}

impl FromStr for Transport {
    type Err = DemoError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "udp" => Transport::UDP,
            "UDP" => Transport::UDP,
            "tcp" => Transport::TCP,
            "TCP" => Transport::TCP,
            t => return Err(format!("bad transport: {:?}", t).into()),
        })
    }
}

impl ToString for Transport {
    fn to_string(&self) -> String {
        match self {
            Transport::UDP => "udp",
            Transport::TCP => "tcp",
        }.to_string()
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum CandidateType {
    Host,
    ServerReflexive,
    PeerReflexive,
    Relay,
}

impl FromStr for CandidateType {
    type Err = DemoError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "host" => CandidateType::Host,
            "srflx" => CandidateType::ServerReflexive,
            "prflx" => CandidateType::PeerReflexive,
            "relay" => CandidateType::Relay,
            _ => return Err("bad candidate type".into()),
        })
    }
}

impl ToString for CandidateType {
    fn to_string(&self) -> String {
        match self {
            CandidateType::Host => "host",
            CandidateType::ServerReflexive => "srflx",
            CandidateType::PeerReflexive => "prflx",
            CandidateType::Relay => "relay",
        }.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // candidate examples
    static CANDIDATE1: &str = "candidate:1559184509 1 udp 2113937151 192.168.74.16 53377 typ host generation 0 ufrag eHA1 network-cost 50";
    static CANDIDATE2: &str = "candidate:2933284416 1 udp 2113939711 2601:280:5a80:1600:7c91:82e6:d1b8:8e14 53378 typ host generation 0 ufrag eHA1 network-cost 50";
    static CANDIDATE3: &str = "candidate:842163049 1 udp 1677729535 67.161.192.48 53377 typ srflx raddr 192.168.74.16 rport 53377 generation 0 ufrag eHA1 network-cost 50";
    static CANDIDATE4: &str = "candidate:4231669940 1 udp 1677732095 2601:280:5a80:1600:7874:79a8:e1b1:ab05 53378 typ srflx raddr 2601:280:5a80:1600:7c91:82e6:d1b8:8e14 rport 53378 generation 0 ufrag eHA1 network-cost 50";
    static CANDIDATE5: &str = "candidate:0 1 UDP 2122187007 617f2e0c-f25f-4595-8143-9dd5eb1d85e5.local 42950 typ host";
    static CANDIDATE6: &str = "candidate:6 1 TCP 2105458943 617f2e0c-f25f-4595-8143-9dd5eb1d85e5.local 9 typ host tcptype active";

    #[test]
    fn test_sdp() {
        let candidate_strings = &[CANDIDATE1, CANDIDATE2, CANDIDATE3, CANDIDATE4, CANDIDATE5, CANDIDATE6];
        for candidate_string in candidate_strings {
            let candidate: Candidate = candidate_string.parse().unwrap();
            let s = candidate.to_string();
            let _c: Candidate = s.parse().unwrap();
        }
    }
}
