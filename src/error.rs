use std::fmt;
use std::io;
use std::net::AddrParseError;

use openssl;
use serde_json;

pub struct DemoError(String);

impl DemoError {
    pub fn new(msg: &str) -> DemoError {
        DemoError(msg.to_string())
    }
}

impl fmt::Display for DemoError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

impl fmt::Debug for DemoError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Debug::fmt(&self.0, f)
    }
}

impl ::std::convert::From<serde_json::Error> for DemoError {
    fn from(error: serde_json::Error) -> Self {
        DemoError::new(&format!("{}", error))
    }
}

impl<'a> ::std::convert::From<&'a str> for DemoError {
    fn from(error: &str) -> Self {
        DemoError::new(error)
    }
}

impl ::std::convert::From<String> for DemoError {
    fn from(error: String) -> Self {
        DemoError::new(&error)
    }
}

impl ::std::convert::From<AddrParseError> for DemoError {
    fn from(_error: AddrParseError) -> Self {
        DemoError::new("cannot parse address")
    }
}

impl ::std::convert::From<openssl::error::ErrorStack> for DemoError {
    fn from(error: openssl::error::ErrorStack) -> Self {
        DemoError::new(&format!("OpenSSL error: {}", error))
    }
}

impl ::std::convert::From<io::Error> for DemoError {
    fn from(error: io::Error) -> Self {
        DemoError::new(&format!("I/O error: {}", error))
    }
}
