use std::io;
use std::net::{IpAddr, SocketAddr};

use bytes::{BigEndian, BufMut, ByteOrder, Bytes, BytesMut};
use futures::{Async, Poll, Stream};
use rand::{self, RngCore};
use tokio::io::AsyncWrite;

use error::DemoError;
use ice::Ice;
use udp::UdpStream;

#[derive(Debug)]
pub enum StunEvent {}

enum StunState {
    Initial,
    RequestPending,
    #[allow(dead_code)]
    Done,
}

pub struct StunStream {
    stream: UdpStream,
    state: StunState,
    ice: Ice,
}

impl StunStream {
    pub fn new(stream: UdpStream, ice: Ice) -> StunStream {
        StunStream {
            stream,
            state: StunState::Initial,
            ice,
        }
    }
}

impl Stream for StunStream {
    type Item = StunEvent;
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Option<StunEvent>, io::Error> {
        match self.state {
            StunState::Initial => {
                // Send a binding request
                let username = format!(
                    "{}:{}",
                    self.ice.clone().peer.unwrap().username,
                    self.ice.clone().username
                );
                let mut request = StunMessage::new(Class::Request, Method::Binding);
                request.push_attribute(Attribute::Username(username.into_bytes()));
                // Controlled agents don't supply USE-CANDIDATE.
                //request.push_attribute(Attribute::UseCandidate);
                request.push_attribute(Attribute::Priority(1845501695));
                request.push_attribute(Attribute::IceControlled(1845501695));
                request.sign(&self.ice.clone().peer.unwrap().password);
                self.stream.poll_write(&request.render()).unwrap();
                trace!("STUN: send: {:?}", request);

                self.state = StunState::RequestPending;
            }
            StunState::RequestPending => {
                // poll for a received response
            }
            StunState::Done => {
                // respond to ongoing requests
                // TODO: shouldn't this be done in all states?
            }
        }

        loop {
            match self.stream.poll()? {
                Async::Ready(Some(payload)) => {
                    let stun_msg = StunMessage::parse(payload).unwrap();
                    trace!("STUN: recv: {:?}", stun_msg);
                    stun_msg.verify_fingerprint();

                    if stun_msg.class == Class::Request && stun_msg.method == Method::Binding {
                        // This is a binding request from the peer -- send response.
                        let mut response =
                            stun_msg.response(Class::SuccessResponse, Method::Binding);
                        response.push_attribute(Attribute::XorMappedAddress(self.stream.peer));
                        response.sign(&self.ice.password);
                        stun_msg.verify_fingerprint();
                        // TODO: fingerprint?
                        self.stream.poll_write(&response.render()).unwrap();
                        trace!("STUN: send: {:?}", response);
                    } else if stun_msg.class == Class::SuccessResponse
                        && stun_msg.method == Method::Binding
                    {
                        // This is a response to our binding request.

                    }
                }
                Async::Ready(None) => return Ok(Async::Ready(None)),
                Async::NotReady => break,
            }
        }

        Ok(Async::NotReady)
    }
}

//////////////////////////////////////////////////////////////////////

const STUN_MAGIC: u32 = 0x2112A442;
static STUN_MAGIC_U8: &[u8] = &[0x21, 0x12, 0xA4, 0x42];

#[allow(dead_code)]
enum MessageType {
    BindingRequest,
}

const HEADER_SIZE: usize = 20;
const TRANSACTION_ID_SIZE: usize = 12;
const STUN_FINGERPRINT_XOR: u32 = 0x5354554e;

// Generate a random 96-bit transaction ID.
#[allow(dead_code)]
fn generate_transaction_id() -> [u8; TRANSACTION_ID_SIZE] {
    let mut tid: [u8; TRANSACTION_ID_SIZE] = [0; TRANSACTION_ID_SIZE];
    rand::thread_rng().fill_bytes(&mut tid);
    tid
}

#[allow(dead_code)]
struct RawAttribute<'a> {
    type_: u16,
    value: &'a [u8],
}

impl<'a> RawAttribute<'a> {}

#[derive(Copy, Clone, Debug, PartialEq)]
enum Class {
    Request,
    Indication,
    SuccessResponse,
    ErrorResponse,
}

impl ::std::convert::From<u16> for Class {
    fn from(value: u16) -> Self {
        let value = value & 0x02;
        match value {
            0x00 => Class::Request,
            0x01 => Class::Indication,
            0x02 => Class::SuccessResponse,
            0x03 => Class::ErrorResponse,
            _ => unreachable!(),
        }
    }
}

impl ::std::convert::From<Class> for u16 {
    fn from(class: Class) -> Self {
        match class {
            Class::Request => 0x00,
            Class::Indication => 0x01,
            Class::SuccessResponse => 0x02,
            Class::ErrorResponse => 0x03,
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq)]
enum Method {
    Binding,
    Unknown(u16),
}

impl ::std::convert::From<u16> for Method {
    fn from(value: u16) -> Self {
        match value {
            0x0001 => Method::Binding,
            v => Method::Unknown(v),
        }
    }
}

impl ::std::convert::From<Method> for u16 {
    fn from(method: Method) -> Self {
        match method {
            Method::Binding => 0x0001,
            Method::Unknown(v) => v,
        }
    }
}

mod atype {
    pub const MAPPED_ADDRESS: u16 = 0x0001;
    pub const USERNAME: u16 = 0x0006;
    pub const MESSAGE_INTEGRITY: u16 = 0x0008;
    pub const XOR_MAPPED_ADDRESS: u16 = 0x0020;
    pub const PRIORITY: u16 = 0x0024;
    pub const USE_CANDIDATE: u16 = 0x0025;
    pub const FINGERPRINT: u16 = 0x8028;
    pub const ICE_CONTROLLED: u16 = 0x8029;
    pub const ICE_CONTROLLING: u16 = 0x802A;
}

#[derive(Debug)]
enum Attribute {
    MappedAddress(SocketAddr),
    Username(Vec<u8>),
    MessageIntegrity(Vec<u8>),
    XorMappedAddress(SocketAddr),
    Priority(u32),
    UseCandidate,
    IceControlled(u64),
    IceControlling(u64),
    Fingerprint(u32),
    Unknown(u16, Vec<u8>),
}

const ATTRIBUTE_HEADER_SIZE: usize = 4;
const MESSAGE_INTEGRITY_SIZE: usize = 20;

const FAMILY_IPV4: u8 = 0x01;
const FAMILY_IPV6: u8 = 0x02;
enum Family {
    V4,
    V6,
}

impl Attribute {
    fn parse(
        bytes: &mut Bytes,
        transaction_id: &[u8; TRANSACTION_ID_SIZE],
    ) -> Result<Attribute, DemoError> {
        if bytes.len() < 4 {
            return Err("stun attribute header underrun".into());
        }
        let type_ = BigEndian::read_u16(&bytes);
        let length = BigEndian::read_u16(&bytes[2..]) as usize;
        let padding = (4 - length % 4) % 4;
        let padded_length = length + padding;
        if padded_length > bytes[ATTRIBUTE_HEADER_SIZE..].len() {
            return Err("stun attribute value length mismatch".into());
        }
        bytes.advance(ATTRIBUTE_HEADER_SIZE);
        let value = bytes.split_to(padded_length);
        let value = value.slice(0, length); // remove padding

        fn be32(bytes: &Bytes) -> Result<u32, DemoError> {
            if bytes.len() != 4 {
                return Err("bad size for attribute u32 value".into());
            } else {
                Ok(BigEndian::read_u32(bytes))
            }
        }

        fn be64(bytes: &Bytes) -> Result<u64, DemoError> {
            if bytes.len() != 8 {
                return Err("bad size for attribute u64 value".into());
            } else {
                Ok(BigEndian::read_u64(bytes))
            }
        }

        use self::atype::*;
        Ok(match type_ {
            MAPPED_ADDRESS => {
                Attribute::MappedAddress(Self::parse_mapped_address(value, false, &transaction_id)?)
            }
            USERNAME => Attribute::Username(value.to_vec()),
            MESSAGE_INTEGRITY => {
                if value.len() != MESSAGE_INTEGRITY_SIZE {
                    return Err("bad message integrity size".into());
                }
                Attribute::MessageIntegrity(value.to_vec())
            }
            XOR_MAPPED_ADDRESS => Attribute::XorMappedAddress(Self::parse_mapped_address(
                value,
                true,
                &transaction_id,
            )?),
            PRIORITY => Attribute::Priority(be32(&value)?),
            USE_CANDIDATE => Attribute::UseCandidate,
            FINGERPRINT => Attribute::Fingerprint(be32(&value)?),
            ICE_CONTROLLED => Attribute::IceControlled(be64(&value)?),
            ICE_CONTROLLING => Attribute::IceControlling(be64(&value)?),
            _ => Attribute::Unknown(type_, value.to_vec()),
        })
    }

    fn render(&self, transaction_id: &[u8; TRANSACTION_ID_SIZE]) -> Bytes {
        use self::atype::*;
        use self::Attribute::*;

        // Render value
        let (tag, value) = match self {
            MappedAddress(s) => {
                let value = Self::render_mapped_address(s, false, transaction_id);
                (MAPPED_ADDRESS, value.into())
            }
            Username(s) => (USERNAME, s.clone().into()),
            MessageIntegrity(s) => (MESSAGE_INTEGRITY, s.clone().into()),
            XorMappedAddress(s) => {
                let value = Self::render_mapped_address(s, true, transaction_id);
                (XOR_MAPPED_ADDRESS, value.into())
            }
            Priority(n) => {
                let mut bytes = BytesMut::with_capacity(4);
                bytes.put_u32_be(*n);
                (PRIORITY, bytes.into())
            }
            UseCandidate => (USE_CANDIDATE, Bytes::new()),
            IceControlled(n) => {
                let mut bytes = BytesMut::with_capacity(8);
                bytes.put_u64_be(*n);
                (ICE_CONTROLLED, bytes.into())
            }
            IceControlling(n) => {
                let mut bytes = BytesMut::with_capacity(8);
                bytes.put_u64_be(*n);
                (ICE_CONTROLLING, bytes.into())
            }
            Fingerprint(n) => {
                let mut bytes = BytesMut::with_capacity(4);
                bytes.put_u32_be(*n);
                (FINGERPRINT, bytes.into())
            }
            Unknown(t, v) => (*t, v.clone().into()),
        };

        // Render entire attribute
        let padding = (4 - value.len() % 4) % 4;
        let mut bytes = BytesMut::with_capacity(ATTRIBUTE_HEADER_SIZE + value.len() + padding);
        bytes.put_u16_be(tag);
        bytes.put_u16_be(value.len() as u16);
        bytes.put_slice(&value);
        for _ in 0..padding {
            bytes.put_u8(0x00);
        }
        bytes.into()
    }

    fn parse_mapped_address(
        mut value: Bytes,
        xor: bool,
        transaction_id: &[u8; TRANSACTION_ID_SIZE],
    ) -> Result<SocketAddr, DemoError> {
        if value.len() < 4 {
            return Err("MAPPED_ADDRESS header underrun".into());
        }
        if value[0] != 0x00 {
            return Err("invalid MAPPED_ADDRESS lead-in".into());
        }
        let family = match value[1] {
            FAMILY_IPV4 => Family::V4,
            FAMILY_IPV6 => Family::V6,
            _ => return Err("MAPPED_ADDRESS: bad family".into()),
        };
        value.advance(2);
        let mut port = BigEndian::read_u16(&value);
        if xor {
            port = port ^ ((STUN_MAGIC >> 16) as u16);
        }
        value.advance(2);
        match family {
            Family::V4 => {
                if value.len() != 4 {
                    return Err("MAPPED_ADDRESS: Invalid address size for IPv4.".into());
                }
                let mut ip = BigEndian::read_u32(&value);
                if xor {
                    ip = ip ^ STUN_MAGIC;
                }
                Ok(SocketAddr::new(IpAddr::V4(ip.into()), port))
            }
            Family::V6 => {
                if value.len() != 16 {
                    return Err("MAPPED_ADDRESS: Invalid address size for IPv6.".into());
                }
                let mut buffer = [0u8; 16];
                if xor {
                    let mut i = 0;
                    for pair in STUN_MAGIC_U8
                        .iter()
                        .chain(transaction_id.iter())
                        .zip(value.iter())
                    {
                        buffer[i] = pair.0 ^ pair.1;
                        i += 1;
                    }
                } else {
                    buffer.copy_from_slice(&value);
                }
                Ok(SocketAddr::new(buffer.into(), port))
            }
        }
    }

    fn render_mapped_address(
        address: &SocketAddr,
        xor: bool,
        transaction_id: &[u8; TRANSACTION_ID_SIZE],
    ) -> Bytes {
        let (size, family_byte, ip_bytes) = match address {
            SocketAddr::V4(s) => (8, FAMILY_IPV4, s.ip().octets().to_vec()),
            SocketAddr::V6(s) => (20, FAMILY_IPV6, s.ip().octets().to_vec()),
        };
        let mut bytes = BytesMut::with_capacity(size);
        bytes.put_u8(0x00);
        bytes.put_u8(family_byte);
        let mut port = address.port();
        if xor {
            port = port ^ ((STUN_MAGIC >> 16) as u16);
        }
        bytes.put_u16_be(port);
        let ip_bytes: Vec<u8> = if xor {
            let mut xored_ip_bytes = Vec::new();
            for pair in STUN_MAGIC_U8
                .iter()
                .chain(transaction_id.iter())
                .zip(ip_bytes.iter())
            {
                xored_ip_bytes.push(pair.0 ^ pair.1);
            }
            xored_ip_bytes
        } else {
            ip_bytes
        };
        bytes.put_slice(&ip_bytes);
        bytes.into()
    }
}

#[derive(Debug)]
struct StunMessage {
    class: Class,   // 2-bit
    method: Method, // 12-bit
    transaction_id: [u8; TRANSACTION_ID_SIZE],
    attributes: Vec<Attribute>,
}

impl StunMessage {
    pub fn new(class: Class, method: Method) -> StunMessage {
        let mut transaction_id = [0u8; TRANSACTION_ID_SIZE];
        rand::thread_rng().fill_bytes(&mut transaction_id);
        StunMessage {
            class,
            method,
            transaction_id,
            attributes: vec![],
        }
    }

    pub fn response(&self, class: Class, method: Method) -> StunMessage {
        StunMessage {
            class,
            method,
            transaction_id: self.transaction_id,
            attributes: vec![],
        }
    }

    pub fn push_attribute(&mut self, attribute: Attribute) {
        self.attributes.push(attribute);
    }

    fn parse(mut payload: Bytes) -> Result<StunMessage, DemoError> {
        if payload.len() < HEADER_SIZE {
            return Err("stun header underrun".into());
        }

        let magic = BigEndian::read_u32(&payload[4..]);
        if magic != STUN_MAGIC {
            return Err("STUN magic mismatch".into());
        }

        let raw_type = BigEndian::read_u16(&payload);
        let method_num =
            ((raw_type & 0x000f) >> 0) | ((raw_type & 0x00e0) >> 1) | ((raw_type & 0x3e00) >> 2);
        let class_num = ((raw_type & 0x0010) >> 4) | ((raw_type & 0x0100) >> 7);
        let message_length = BigEndian::read_u16(&payload[2..]);
        if message_length as usize != payload.len() - HEADER_SIZE {
            return Err(format!(
                "stun message length mismatch ({}; expected: {})",
                message_length,
                payload.len() - HEADER_SIZE
            ).into());
        }
        let mut transaction_id = [0u8; TRANSACTION_ID_SIZE];
        transaction_id.copy_from_slice(&payload[8..20]);
        payload.advance(HEADER_SIZE);

        // Parse attributes
        let mut attributes = vec![];
        while !payload.is_empty() {
            let attribute = Attribute::parse(&mut payload, &transaction_id)?;
            attributes.push(attribute);
        }

        Ok(StunMessage {
            class: class_num.into(),
            method: method_num.into(),
            transaction_id: transaction_id,
            attributes: attributes,
        })
    }

    fn render(&self) -> Bytes {
        let mut attributes: Vec<Bytes> = vec![];
        let mut attribute_size = 0;
        for attribute in self.attributes.iter() {
            let attribute_bytes = attribute.render(&self.transaction_id);
            attribute_size += attribute_bytes.len();
            attributes.push(attribute_bytes);
        }

        let class: u16 = self.class.into();
        let method: u16 = self.method.into();
        let raw_type = (((method & 0x000f) >> 0) << 0)
            | (((method & 0x0070) >> 4) << 5)
            | (((method & 0x0f80) >> 7) << 9)
            | (((class & 0x0001) >> 0) << 4)
            | (((class & 0x0002) >> 1) << 8);

        let mut bytes = BytesMut::with_capacity(HEADER_SIZE + attribute_size);
        bytes.put_u16_be(raw_type);
        bytes.put_u16_be(attribute_size as u16);
        bytes.put_u32_be(STUN_MAGIC);
        bytes.put_slice(&self.transaction_id);
        for attribute in attributes {
            bytes.put_slice(&attribute);
        }
        bytes.into()
    }

    fn sign(&mut self, password: &str) {
        // These steps are simple but wasteful.

        // MESSAGE-INTEGRITY

        // What is the size before adding a message integrity attribute?
        let bytes_to_hash = self.render().len();
        // Add a dummy message integrity attribute.
        self.attributes
            .push(Attribute::MessageIntegrity([0u8; 20].to_vec()));
        // Render again, with the updated message length field reflecting the added M-I attribute,
        // but don't regard the M-I.
        let bytes = self.render().slice(0, bytes_to_hash);
        // Remove the dummy M-I attribute.
        self.attributes.pop();
        // Perform HMAC-SHA1
        let hmac = ::crypto::hmac_sha1(password.as_bytes(), &bytes);
        // Add the final message integrity attribute.
        self.attributes.push(Attribute::MessageIntegrity(hmac));

        // FINGERPRINT

        // What is the size before adding a fingerprint attribute?
        let bytes_to_hash = self.render().len();
        // Add a dummy message integrity attribute.
        self.attributes.push(Attribute::Fingerprint(0));
        // Render again, with the updated message length field reflecting the added attribute,
        // but don't regard the bytes of the fingerprint attribute itself.
        let bytes = self.render().slice(0, bytes_to_hash);
        // Remove the dummy fingerprint attribute.
        self.attributes.pop();
        // Perform CRC-32
        let fingerprint = ::crc::crc32::checksum_ieee(&bytes) ^ STUN_FINGERPRINT_XOR;
        // Add the final fingerprint attribute.
        self.attributes.push(Attribute::Fingerprint(fingerprint));
    }

    fn verify_fingerprint(&self) {
        let fingerprint = self
            .attributes
            .iter()
            .filter_map(|a| match a {
                Attribute::Fingerprint(f) => Some(*f),
                _ => None,
            }).last()
            .unwrap();

        let bytes = self.render();
        let bytes = bytes.slice(0, bytes.len() - 8); // don't include fingerprint attribute bytes
        let calculated_fingerprint = ::crc::crc32::checksum_ieee(&bytes) ^ STUN_FINGERPRINT_XOR;
        if fingerprint != calculated_fingerprint {
            panic!("fingerprint verification failure");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    static TID_1: [u8; TRANSACTION_ID_SIZE] = [
        0x63, 0x56, 0x57, 0x55, 0x6f, 0x57, 0x74, 0x59, 0x36, 0x55, 0x47, 0x54,
    ];
    static XOR_MAPPED_ADDRESS1: &[u8] = &[
        0x00, 0x20, 0x00, 0x14, 0x00, 0x02, 0xd1, 0xd9, 0x07, 0x13, 0xa6, 0xc2, 0x39, 0xd6, 0x41,
        0x55, 0x6a, 0xc6, 0x3f, 0xcf, 0x04, 0x45, 0x85, 0xaf,
    ];
    static IP1: &str = "2601:280:5a80:1600:591:4b96:3210:c2fb";
    static PORT1: u16 = 61643;

    static TID_2: [u8; TRANSACTION_ID_SIZE] = [
        0xd5, 0xc5, 0x19, 0xa2, 0x15, 0x71, 0xd5, 0x17, 0x99, 0x96, 0xf7, 0xc2,
    ];
    static XOR_MAPPED_ADDRESS2: &[u8] = &[
        0x00, 0x20, 0x00, 0x08, 0x00, 0x01, 0xe3, 0x07, 0xe1, 0xba, 0xee, 0x52,
    ];
    static IP2: &str = "192.168.74.16";
    static PORT2: u16 = 49685;

    #[test]
    fn test_xor_mapped_address() {
        println!("input bytes:\n{}", ::util::Hex(&XOR_MAPPED_ADDRESS1));
        let expected_address = SocketAddr::new(IP1.parse().unwrap(), PORT1);
        let a = Attribute::parse(&mut XOR_MAPPED_ADDRESS1.to_vec().into(), &TID_1).unwrap();
        println!("a: {:?}", a);
        let s = match a {
            Attribute::XorMappedAddress(s) => s,
            _ => panic!("not an XorMappedAddress"),
        };
        assert_eq!(s, expected_address);

        let mut bytes = Attribute::render(&a, &TID_1);
        println!("re-rendered: bytes:\n{}", ::util::Hex(&bytes));
        let a = Attribute::parse(&mut bytes, &TID_1).unwrap();
        println!("re-parsed a: {:?}", a);
        let s = match a {
            Attribute::XorMappedAddress(s) => s,
            _ => panic!("not an XorMappedAddress"),
        };
        assert_eq!(s, expected_address);

        println!("input bytes:\n{}", ::util::Hex(&XOR_MAPPED_ADDRESS2));
        let expected_address = SocketAddr::new(IP2.parse().unwrap(), PORT2);
        let a = Attribute::parse(&mut XOR_MAPPED_ADDRESS2.to_vec().into(), &TID_2).unwrap();
        println!("a: {:?}", a);
        let s = match a {
            Attribute::XorMappedAddress(s) => s,
            _ => panic!("not an XorMappedAddress"),
        };
        assert_eq!(s, expected_address);

        let mut bytes = Attribute::render(&a, &TID_2);
        println!("re-rendered: bytes:\n{}", ::util::Hex(&bytes));
        let a = Attribute::parse(&mut bytes, &TID_2).unwrap();
        println!("re-parsed a: {:?}", a);
        let s = match a {
            Attribute::XorMappedAddress(s) => s,
            _ => panic!("not an XorMappedAddress"),
        };
        assert_eq!(s, expected_address);
    }

    static TEST_ADDRESS: &str = "192.168.1.200:38668";

    #[test]
    fn test_stun() {
        let mut stun = StunMessage::new(Class::SuccessResponse, Method::Binding);
        stun.push_attribute(Attribute::XorMappedAddress(TEST_ADDRESS.parse().unwrap()));
        stun.push_attribute(Attribute::MessageIntegrity([0u8; 20].to_vec()));
        stun.push_attribute(Attribute::Fingerprint(0));
        println!("{:?}", stun);
        let bytes = stun.render();
        println!("rendered:\n{}", ::util::Hex(&bytes));
    }
}
