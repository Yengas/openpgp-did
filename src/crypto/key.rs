use std::fmt;

// Curve types for signing keys
#[derive(PartialEq, Eq, Debug, Clone, Copy)]
#[non_exhaustive]
pub enum SigningKeyCurve {
    Ed25519, // EdDSA with Curve25519
}

impl fmt::Display for SigningKeyCurve {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let curve_str = match self {
            SigningKeyCurve::Ed25519 => "Ed25519",
        };
        write!(f, "{}", curve_str)
    }
}

// Curve types for encryption keys
#[derive(PartialEq, Eq, Debug, Clone, Copy)]
#[non_exhaustive]
pub enum EncryptionKeyCurve {
    Cv25519, // ECDH with Curve25519
}

impl fmt::Display for EncryptionKeyCurve {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let curve_str = match self {
            EncryptionKeyCurve::Cv25519 => "Cv25519",
        };
        write!(f, "{}", curve_str)
    }
}

// SigningKey struct
#[derive(PartialEq, Eq, Debug, Clone)]
pub struct SigningKey {
    fingerprint: String,
    curve: SigningKeyCurve,
    pub_data: Vec<u8>,
}

impl SigningKey {
    pub fn new(fingerprint: String, curve: SigningKeyCurve, pub_data: Vec<u8>) -> Self {
        Self {
            fingerprint,
            curve,
            pub_data,
        }
    }

    pub fn fingerprint(&self) -> &String {
        &self.fingerprint
    }

    pub fn curve(&self) -> &SigningKeyCurve {
        &self.curve
    }

    pub fn pub_data(&self) -> &[u8] {
        &self.pub_data
    }
}

// EncryptionKey struct
#[derive(PartialEq, Eq, Debug, Clone)]
pub struct EncryptionKey {
    fingerprint: String,
    curve: EncryptionKeyCurve,
    pub_data: Vec<u8>,
}

impl EncryptionKey {
    pub fn new(fingerprint: String, curve: EncryptionKeyCurve, pub_data: Vec<u8>) -> Self {
        Self {
            fingerprint,
            curve,
            pub_data,
        }
    }

    pub fn fingerprint(&self) -> &String {
        &self.fingerprint
    }

    pub fn curve(&self) -> &EncryptionKeyCurve {
        &self.curve
    }

    pub fn pub_data(&self) -> &[u8] {
        &self.pub_data
    }
}

#[derive(PartialEq, Eq, Debug, Clone)]
pub enum Key {
    Signing(SigningKey),
    Encryption(EncryptionKey),
}

impl Key {
    pub fn fingerprint(&self) -> &String {
        match self {
            Key::Signing(signing_key) => signing_key.fingerprint(),
            Key::Encryption(encryption_key) => encryption_key.fingerprint(),
        }
    }

    pub fn curve_as_string(&self) -> String {
        match self {
            Key::Signing(signing_key) => signing_key.curve().to_string(),
            Key::Encryption(encryption_key) => encryption_key.curve().to_string(),
        }
    }

    pub fn pub_data(&self) -> &[u8] {
        match self {
            Key::Signing(signing_key) => signing_key.pub_data(),
            Key::Encryption(encryption_key) => encryption_key.pub_data(),
        }
    }
}
