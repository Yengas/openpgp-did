// Curve types for signing keys
#[derive(PartialEq, Eq, Debug, Clone, Copy)]
#[non_exhaustive]
pub enum SigningKeyCurve {
    Ed25519, // EdDSA with Curve25519
}

// Curve types for encryption keys
#[derive(PartialEq, Eq, Debug, Clone, Copy)]
#[non_exhaustive]
pub enum EncryptionKeyCurve {
    Cv25519, // ECDH with Curve25519
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
