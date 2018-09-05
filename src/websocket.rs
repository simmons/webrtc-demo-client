//! The client-server protocol supports two messages types: Roster (for the server to supply the
//! client's assigned name and list of connected users), and Relay (for the client to send and
//! receive messages to/from other clients, as relayed by the server).
//!
//! A Relay client-server message contains a server-opaque "json" field that the server blindly
//! relays to the recipient.  From a client perspective, however, relay messages are more layered.
//! The "json" field contains a serialized RelayEnvelope structure which contains certain metadata
//! (serial number, whether this message is a reply or not, etc.), and a payload (SdpMessage or
//! IceMessage) which contains the actual data being communicated.
//!
//! In other words:
//!
//! ClientMessage::Relay(Relay {...})
//!  - name
//!  - RelayEnvelope (serialized as json)
//!    - serial, reply, type
//!    - RelayPayload::Sdp(SdpMessage {...}) or RelayPayload::Ice(IceMessage {...})
//!
//! (Yes, there are a lot of opportunities for making this cleaner.)

use serde_json;

use error::DemoError;
use ice;

////////////////////////////////////////////////////////////////////////
// client-server messages
////////////////////////////////////////////////////////////////////////

#[derive(Serialize, Deserialize, Debug)]
pub struct RosterClient {
    pub name: String,
    pub peer: Option<String>,
    pub user_agent: Option<String>,
}

/// Messages of this type will be used to inform clients of their name and the other clients
/// currently connected.
#[derive(Serialize, Deserialize, Debug)]
pub struct Roster {
    pub name: String,
    pub clients: Vec<RosterClient>,
}

/// Messages of this type will be relayed between clients.
#[derive(Serialize, Deserialize, Debug)]
pub struct Relay {
    pub name: String,
    pub json: String,
}

/// Encapsulate all possible messages between the client and server.
#[derive(Serialize, Deserialize, Debug)]
pub enum ClientMessage {
    Relay(Relay),
    Roster(Roster),
}

////////////////////////////////////////////////////////////////////////
// client-client messages
////////////////////////////////////////////////////////////////////////

#[derive(Serialize, Deserialize, Debug)]
pub struct SdpMessage {
    #[serde(rename = "type")]
    pub type_: String,
    pub sdp: String,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct IceMessage {
    pub candidate: String,
    pub sdp_mid: String,
    pub sdp_m_line_index: u64,
}

pub enum RelayPayload {
    Sdp(SdpMessage),
    Ice(IceMessage),
}

pub struct RelayEnvelope {
    pub serial: u64,
    pub reply: bool,
    pub payload: RelayPayload,
}

impl RelayEnvelope {
    pub fn unpack(relay: &Relay) -> Result<RelayEnvelope, DemoError> {
        let json: serde_json::Value = serde_json::from_str(&relay.json)?;
        let serial = json["serial"].as_u64().ok_or("bad serial")?;
        let reply = json["reply"].as_bool().ok_or("bad reply")?;
        let type_ = json["type"].as_str().ok_or("bad type")?;
        let payload = match type_ {
            "sdp" => RelayPayload::Sdp(serde_json::from_value(json["payload"].clone())?),
            "ice" => RelayPayload::Ice(serde_json::from_value(json["payload"].clone())?),
            _ => Err(format!("unknown type: \"{}\"", type_))?,
        };
        Ok(RelayEnvelope {
            serial,
            reply,
            payload,
        })
    }

    /// Take a relay envelope and package it in a Relay client-server message.
    pub fn pack(&self, peer_name: &str) -> Result<Relay, DemoError> {
        let mut map = serde_json::Map::new();
        map.insert("serial".to_string(), self.serial.into());
        map.insert("reply".to_string(), self.reply.into());
        let (type_, payload): (&str, serde_json::Value) = match self.payload {
            RelayPayload::Sdp(ref sdp) => ("sdp", serde_json::to_value(sdp)?),
            RelayPayload::Ice(ref ice) => ("ice", serde_json::to_value(ice)?),
        };
        map.insert("type".to_string(), type_.into());
        map.insert("payload".to_string(), payload);
        let object: serde_json::Value = map.into();

        Ok(Relay {
            name: peer_name.to_string(),
            json: object.to_string(),
        })
    }
}

////////////////////////////////////////////////////////////////////////

pub fn parse_message(message: &str) -> ClientMessage {
    match serde_json::from_str::<ClientMessage>(message) {
        Ok(message) => message,
        Err(e) => {
            panic!("cannot parse incoming message: {:?}", e);
        }
    }
}

use sdp::SimpleSession;

pub fn encode_answer(
    answer: &SimpleSession,
    recv_envelope: &RelayEnvelope,
    peer_name: &str,
) -> Result<String, DemoError> {
    let relay_envelope = RelayEnvelope {
        serial: recv_envelope.serial,
        reply: true,
        payload: RelayPayload::Sdp(SdpMessage {
            type_: "answer".to_string(),
            sdp: answer.to_string(),
        }),
    };

    let client_message = ClientMessage::Relay(relay_envelope.pack(peer_name)?);
    Ok(serde_json::to_string(&client_message)?)
}

pub fn encode_candidate(
    candidate: &ice::Candidate,
    mid: &str,
    peer_name: &str,
) -> Result<String, DemoError> {
    let relay_envelope = RelayEnvelope {
        serial: 1,
        reply: false,
        payload: RelayPayload::Ice(IceMessage {
            candidate: candidate.to_string(),
            sdp_mid: mid.to_string(),
            sdp_m_line_index: 0,
        }),
    };

    let client_message = ClientMessage::Relay(relay_envelope.pack(peer_name)?);
    Ok(serde_json::to_string(&client_message)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    static SDP_JSON: &str = r##"{"Relay":{"json":"{\"serial\":319209230,\"reply\":false,\"type\":\"sdp\",\"payload\":{\"type\":\"offer\",\"sdp\":\"v=0\\r\\no=- 5205093963319370922 2 IN IP4 127.0.0.1\\r\\ns=-\\r\\nt=0 0\\r\\na=group:BUNDLE data\\r\\na=msid-semantic: WMS\\r\\nm=application 9 DTLS/SCTP 5000\\r\\nc=IN IP4 0.0.0.0\\r\\na=ice-ufrag:IkD9\\r\\na=ice-pwd:WwSla+ZntFgoP01XvLlPTac9\\r\\na=ice-options:trickle\\r\\na=fingerprint:sha-256 8A:EB:A2:F0:A5:EA:6B:FB:08:6D:34:8D:D9:9D:BC:5B:0E:28:B4:8B:43:B1:F4:8B:A9:90:81:1F:DD:FC:17:4C\\r\\na=setup:actpass\\r\\na=mid:data\\r\\na=sctpmap:5000 webrtc-datachannel 1024\\r\\n\"}}","name":"Silent Platypus"}}"##;
    static SDP: &str = "v=0\r\no=- 5205093963319370922 2 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\na=group:BUNDLE data\r\na=msid-semantic: WMS\r\nm=application 9 DTLS/SCTP 5000\r\nc=IN IP4 0.0.0.0\r\na=ice-ufrag:IkD9\r\na=ice-pwd:WwSla+ZntFgoP01XvLlPTac9\r\na=ice-options:trickle\r\na=fingerprint:sha-256 8A:EB:A2:F0:A5:EA:6B:FB:08:6D:34:8D:D9:9D:BC:5B:0E:28:B4:8B:43:B1:F4:8B:A9:90:81:1F:DD:FC:17:4C\r\na=setup:actpass\r\na=mid:data\r\na=sctpmap:5000 webrtc-datachannel 1024\r\n";

    static ICE_JSON: &str = r##"{"Relay":{"json":"{\"serial\":285942443,\"reply\":false,\"type\":\"ice\",\"payload\":{\"candidate\":\"candidate:1559184509 1 udp 2113937151 192.168.1.100 64129 typ host generation 0 ufrag Ev7b network-cost 50\",\"sdpMid\":\"data\",\"sdpMLineIndex\":0}}","name":"Tremendous Manatee"}}"##;
    static ICE_CANDIDATE: &str = "candidate:1559184509 1 udp 2113937151 192.168.1.100 64129 typ host generation 0 ufrag Ev7b network-cost 50";
    static ICE_SDP_MID: &str = "data";
    static ICE_SDP_M_LINE_INDEX: u64 = 0;

    #[test]
    fn test_sdp() {
        let m = parse_message(SDP_JSON);
        let relay = if let ClientMessage::Relay(relay) = m {
            relay
        } else {
            panic!("not a Relay message");
        };
        let relay_envelope = RelayEnvelope::unpack(&relay).unwrap();

        let packed = relay_envelope.pack(&relay.name).unwrap();
        let unpacked = RelayEnvelope::unpack(&packed).unwrap();
        assert_eq!(packed.name, relay.name);
        assert_eq!(unpacked.serial, relay_envelope.serial);
        assert_eq!(unpacked.reply, relay_envelope.reply);
        match unpacked.payload {
            RelayPayload::Sdp(sdp) => {
                assert_eq!(sdp.type_, "offer");
                assert_eq!(sdp.sdp, SDP);
            }
            RelayPayload::Ice(_) => {
                panic!("expected sdp");
            }
        }
    }

    #[test]
    fn test_ice() {
        let m = parse_message(ICE_JSON);
        let relay = if let ClientMessage::Relay(relay) = m {
            relay
        } else {
            panic!("not a Relay message");
        };
        let relay_envelope = RelayEnvelope::unpack(&relay).unwrap();

        let packed = relay_envelope.pack(&relay.name).unwrap();
        let unpacked = RelayEnvelope::unpack(&packed).unwrap();
        assert_eq!(packed.name, relay.name);
        assert_eq!(unpacked.serial, relay_envelope.serial);
        assert_eq!(unpacked.reply, relay_envelope.reply);
        match unpacked.payload {
            RelayPayload::Sdp(_) => {
                panic!("expected ice");
            }
            RelayPayload::Ice(ice) => {
                assert_eq!(ice.candidate, ICE_CANDIDATE);
                assert_eq!(ice.sdp_mid, ICE_SDP_MID);
                assert_eq!(ice.sdp_m_line_index, ICE_SDP_M_LINE_INDEX);
            }
        }
    }
}
