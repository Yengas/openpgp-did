use std::error::Error;

use base64::{engine, Engine};
use did_web::DIDWeb;
use ssi::{
    did::DIDURL,
    jsonld::ContextLoader,
    jwk::{Algorithm, Base64urlUInt, OctetParams, Params, JWK},
    ldp::{ProofSuite, ProofSuiteType, SigningInput},
    vc::{Credential, LinkedDataProofOptions, URI},
};

use crate::crypto::{
    key::{EncryptionKey, Key, SigningKey},
    smart_card::SmartCard,
};

fn create_jwk(did_url: &DIDURL, key: &Key) -> JWK {
    let public_key_as_base64 = engine::general_purpose::URL_SAFE_NO_PAD.encode(key.pub_data());
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
            curve: match key {
                Key::Signing(_) => "Ed25519",
                Key::Encryption(_) => "X25519",
            }
            .to_string(),
            public_key: Base64urlUInt(public_key_as_base64.as_bytes().to_vec()),
            private_key: None,
        }),
    }
}

pub struct DidConfiguration {
    pub did_url: DIDURL,
    pub active_signing_key_fp: String,
    pub active_encryption_key_fp: String,
}

pub struct Did {
    did_url: DIDURL,
    active_signing_key: SigningKey,
    active_signing_key_jwk: JWK,
    active_encryption_key: EncryptionKey,
    active_encryption_key_jwk: JWK,
    smart_card: Box<dyn SmartCard>,
}

impl Did {
    pub fn did_url(&self) -> &DIDURL {
        &self.did_url
    }

    pub async fn from_smart_card(
        configuration: DidConfiguration,
        mut smart_card: Box<dyn SmartCard>,
    ) -> Result<Self, Box<dyn Error>> {
        let card_info = smart_card
            .get_card_info()
            .expect("could not read card info");

        let active_signing_key: SigningKey = card_info
            .keys
            .iter()
            .find_map(|key| match key {
                Key::Signing(signing_key) => {
                    if *signing_key.fingerprint() == configuration.active_signing_key_fp {
                        Some(signing_key)
                    } else {
                        None
                    }
                }
                _ => None,
            })
            .expect(
                format!(
                    "active signing key '{}' required for did was not on smart card",
                    configuration.active_signing_key_fp
                )
                .as_str(),
            )
            .clone();

        let active_encryption_key: EncryptionKey = card_info
            .keys
            .iter()
            .find_map(|key| match key {
                Key::Encryption(encryption_key) => {
                    if *encryption_key.fingerprint() == configuration.active_encryption_key_fp {
                        Some(encryption_key)
                    } else {
                        None
                    }
                }
                _ => None,
            })
            .expect(
                format!(
                    "active encryption key '{}' required for did was not on smart card",
                    configuration.active_encryption_key_fp
                )
                .as_str(),
            )
            .clone();

        Ok(Self {
            did_url: configuration.did_url.clone(),
            active_signing_key: active_signing_key.clone(),
            active_signing_key_jwk: create_jwk(
                &configuration.did_url,
                &Key::Signing(active_signing_key),
            ),
            active_encryption_key: active_encryption_key.clone(),
            active_encryption_key_jwk: create_jwk(
                &configuration.did_url,
                &Key::Encryption(active_encryption_key),
            ),
            smart_card,
        })
    }
}

impl Did {
    pub async fn create_signed_credential(
        &mut self,
        unsigned_credential: &Credential,
    ) -> Result<Credential, Box<dyn Error>> {
        let proof_suite: Box<dyn ProofSuite> = Box::new(ProofSuiteType::JsonWebSignature2020);
        let mut signed_credential = unsigned_credential.clone();

        let proof_preparation = proof_suite
            .prepare(
                &signed_credential,
                &LinkedDataProofOptions {
                    verification_method: Some(URI::String(
                        self.active_signing_key_jwk
                            .key_id
                            .clone()
                            .expect("signing key JWK should have kid"),
                    )),
                    ..LinkedDataProofOptions::default()
                },
                &DIDWeb,
                &mut ContextLoader::default(),
                &self.active_signing_key_jwk,
                None,
            )
            .await
            .expect("could not prepare the proof");

        let bytes_to_sign = match &proof_preparation.signing_input {
            SigningInput::Bytes(base64_url_uint) => Some(base64_url_uint.0.clone()),
            _ => None,
        }
        .expect("no bytes to sign");

        let signature_base64 = engine::general_purpose::URL_SAFE_NO_PAD.encode(
            self.smart_card
                .sign_data(&self.active_signing_key, bytes_to_sign)
                .expect("could not sign"),
        );

        let proof = proof_suite
            .complete(&proof_preparation, &signature_base64)
            .await
            .expect("could not complete proof preparation");

        signed_credential.add_proof(proof);

        Ok(signed_credential)
    }
}
