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
    curve: SigningKeyCurve,
    data: Vec<u8>,
}

impl SigningKey {
    pub fn new(curve: SigningKeyCurve, data: Vec<u8>) -> Self {
        Self { curve, data }
    }

    pub fn curve(&self) -> &SigningKeyCurve {
        &self.curve
    }

    pub fn pub_data(&self) -> &[u8] {
        &self.data
    }
}

// EncryptionKey struct
#[derive(PartialEq, Eq, Debug, Clone)]
pub struct EncryptionKey {
    curve: EncryptionKeyCurve,
    data: Vec<u8>,
}

impl EncryptionKey {
    pub fn new(curve: EncryptionKeyCurve, data: Vec<u8>) -> Self {
        Self { curve, data }
    }

    pub fn curve(&self) -> &EncryptionKeyCurve {
        &self.curve
    }

    pub fn pub_data(&self) -> &[u8] {
        &self.data
    }
}

#[derive(PartialEq, Eq, Debug, Clone)]
pub enum Key {
    Signing(SigningKey),
    Encryption(EncryptionKey),
}
