use std::sync::Arc;

use error::DemoError;

use openssl;
use openssl::asn1::Asn1Time;
use openssl::bn::BigNum;
use openssl::ec::{Asn1Flag, EcGroup, EcKey};
use openssl::error::ErrorStack;
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::{PKey, Private};
use openssl::sign::Signer;
use openssl::x509::X509;
use openssl_sys;

/// The Rust openssl crate unfortunately has an extremely restrictive API for Asn1Time.  It only
/// allow creating an Asn1Time based on a positive integer number of days from the current time.
/// This isn't suitable for our case where we would like to represent a time in the past, thus we
/// provide a custom constructor here that allows an Asn1Time to be built from a signed integer
/// number of seconds relative to the current time.
fn make_asn1time(offset: i64) -> Result<Asn1Time, DemoError> {
    use foreign_types::ForeignType;
    use std::ptr;

    ::openssl_sys::init();
    unsafe {
        let handle = openssl_sys::X509_gmtime_adj(ptr::null_mut(), offset);
        if handle.is_null() {
            return Err(ErrorStack::get().into());
        }
        Ok(Asn1Time::from_ptr(handle))
    }
}

#[derive(Clone)]
pub struct Identity {
    pub private_key: Arc<PKey<Private>>,
    pub certificate: X509,
    pub fingerprint: Vec<u8>,
}

impl Identity {
    pub fn generate() -> Result<Identity, DemoError> {
        // Generate private key
        let mut group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
        group.set_asn1_flag(Asn1Flag::NAMED_CURVE);
        let eckey = EcKey::generate(&group)?;
        let pkey = PKey::from_ec_key(eckey)?;

        // Generate certificate
        let mut builder = X509::builder()?;
        // Serial number -- random 64-bit value
        use rand::RngCore;
        let mut serial: Vec<u8> = vec![0; 8];
        ::rand::thread_rng().fill_bytes(&mut serial);
        let serial = BigNum::from_slice(&serial)?.to_asn1_integer()?;
        builder.set_serial_number(&serial)?;
        // Validity: Mimic the Chrome behavior of a not-before time of one day ago, and a not-after
        // time of one month from now.
        let start = make_asn1time(-60 * 60 * 24)?;
        let stop = openssl::asn1::Asn1Time::days_from_now(30)?;
        builder.set_not_before(&start)?;
        builder.set_not_after(&stop)?;
        // Set public key
        builder.set_pubkey(&pkey)?;
        // Set subject name
        let mut name = openssl::x509::X509NameBuilder::new()?;
        name.append_entry_by_text("CN", "WebRTC")?;
        let name = name.build();
        builder.set_subject_name(&name)?;
        // Set the issuer to the same as the subject
        builder.set_issuer_name(&name)?;
        // Sign the certificate with SHA-256
        builder.sign(&pkey, MessageDigest::sha256())?;

        // Build certificate
        let certificate = builder.build();

        // SHA-256 hash the DER encoding of the certificate to determine the fingerprint.
        let fingerprint = ::openssl::sha::sha256(&certificate.to_der()?).to_vec();

        Ok(Identity {
            private_key: Arc::new(pkey),
            certificate,
            fingerprint,
        })
    }
}

pub fn hmac_sha1(key: &[u8], data: &[u8]) -> Vec<u8> {
    let pkey = PKey::hmac(key).unwrap();
    let mut signer = Signer::new(MessageDigest::sha1(), &pkey).unwrap();
    signer.update(data).unwrap();
    signer.sign_to_vec().unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_certificate() {
        let _identity = Identity::generate().unwrap();
        // TODO test signing & verifying
    }
}
