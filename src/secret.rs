//! The pre-shared key.
//!
//! The key is held as a [`SecretString`] (zeroized on drop, never printed). The
//! 32-byte Noise PSK is derived from it with HKDF-SHA256 — a standard KDF, not
//! hand-rolled crypto — so an arbitrary-length passphrase becomes a fixed-size
//! key. The key should be high-entropy (see the `keygen` subcommand): NNpsk0
//! with a low-entropy passphrase is open to an offline guess against a captured
//! handshake.

use std::fmt;

use hkdf::Hkdf;
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::Sha256;

const INFO: &[u8] = b"eva-hands psk v1";

#[derive(Clone)]
pub struct Psk(SecretString);

impl Psk {
    pub fn new(secret: impl Into<String>) -> Self {
        Psk(SecretString::from(secret.into()))
    }

    /// Derive the 32-byte Noise PSK.
    pub fn derive32(&self) -> [u8; 32] {
        let hk = Hkdf::<Sha256>::new(None, self.0.expose_secret().as_bytes());
        let mut out = [0u8; 32];
        hk.expand(INFO, &mut out)
            .expect("32 bytes is a valid HKDF-SHA256 output length");
        out
    }
}

impl fmt::Debug for Psk {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Psk(***)")
    }
}

/// Compare by the derived key, in constant time. Lets `Psk` sit inside a
/// `#[derive(PartialEq)]`/`#[eva::data]` config without leaking timing on the
/// secret.
impl PartialEq for Psk {
    fn eq(&self, other: &Self) -> bool {
        let (a, b) = (self.derive32(), other.derive32());
        a.iter().zip(b.iter()).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
    }
}

impl Eq for Psk {}

/// A plain string in a schema — lets `Psk` sit inside an `#[eva::data]` config.
impl schemars::JsonSchema for Psk {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        std::borrow::Cow::Borrowed("Psk")
    }

    fn schema_id() -> std::borrow::Cow<'static, str> {
        std::borrow::Cow::Borrowed(concat!(module_path!(), "::Psk"))
    }

    fn json_schema(generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
        String::json_schema(generator)
    }
}

impl<'de> Deserialize<'de> for Psk {
    fn deserialize<D: Deserializer<'de>>(de: D) -> Result<Self, D::Error> {
        Ok(Psk::new(String::deserialize(de)?))
    }
}

/// Redacted: the key never leaves through serialization (config is only ever
/// read back in through [`Deserialize`]).
impl Serialize for Psk {
    fn serialize<S: Serializer>(&self, se: S) -> Result<S::Ok, S::Error> {
        se.serialize_str("***")
    }
}
