use std::error::Error;

use base64::{engine, Engine};
use ssi::{
    did::{PrimaryDIDURL, DIDURL},
    jwk::{Algorithm, Base64urlUInt, OctetParams, Params, JWK},
};

use crate::{
    crypto::{
        key::{Key, SigningKey},
        smart_card::SmartCard,
    },
    smart_card::openpgp::OpenPgpSmartCard,
    ssi::{Did, KeyAgent},
};

fn create_jwk(did_url: DIDURL, signing_key: &SigningKey) -> JWK {
    let public_key_as_base64 =
        engine::general_purpose::URL_SAFE_NO_PAD.encode(signing_key.pub_data());
    let kid = format!("{}#{}", did_url.did, public_key_as_base64.to_string());

    JWK {
        public_key_use: Some("sig".to_string()),
        key_operations: Some(vec!["sig".to_string()]),
        algorithm: Some(Algorithm::EdDSA),
        key_id: Some(kid),
        x509_url: None,
        x509_certificate_chain: None,
        x509_thumbprint_sha1: None,
        x509_thumbprint_sha256: None,
        params: Params::OKP(OctetParams {
            curve: "Ed25519".to_string(),
            public_key: Base64urlUInt(public_key_as_base64.as_bytes().to_vec()),
            private_key: None,
        }),
    }
}

pub struct SmartCardKeyAgent {
    smart_card: Box<dyn SmartCard>,
    active_signing_key: SigningKey,
    active_signing_key_jwk: JWK,
}

impl KeyAgent for SmartCardKeyAgent {
    fn sign(&mut self, data: Vec<u8>) -> Result<Vec<u8>, Box<dyn Error>> {
        self.smart_card.sign_data(&self.active_signing_key, data)
    }

    fn signing_key_jwk(&self) -> JWK {
        self.active_signing_key_jwk.clone()
    }
}

pub fn create() -> Result<Did, Box<dyn Error>> {
    let did_url: DIDURL = PrimaryDIDURL::try_from("did:web:yigitcan.dev".to_string())
        .expect("could not parse did")
        .into();

    let mut smart_card =
        OpenPgpSmartCard::try_new().expect("could not initialize openpgp smartcard");

    let smart_card_info = smart_card
        .get_card_info()
        .expect("could not get smart card info");

    let active_signing_key = smart_card_info
        .keys
        .iter()
        .filter_map(|key| match key {
            Key::Signing(key) => Some(key),
            _ => None,
        })
        .next()
        .expect("could not find a signing key");

    let smart_card_key_agent = SmartCardKeyAgent {
        smart_card: Box::new(smart_card),
        active_signing_key: active_signing_key.clone(),
        active_signing_key_jwk: create_jwk(did_url.clone(), active_signing_key),
    };

    Ok(Did::new(did_url, Box::new(smart_card_key_agent)))
}
