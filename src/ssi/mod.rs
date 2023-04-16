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
    key::SigningKey,
    smart_card::{SmartCard, SmartCardInfo},
};

trait KeyAgent {
    fn sign(&mut self, data: Vec<u8>) -> Result<Vec<u8>, Box<dyn Error>>;
    fn signing_key_jwk(&self) -> JWK;
}

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

pub struct Did {
    key_agent: Box<dyn KeyAgent>,
}

impl Did {
    pub fn new(
        did_url: DIDURL,
        smart_card: Box<dyn SmartCard>,
        smart_card_info: SmartCardInfo,
    ) -> Self {
        Self {
            key_agent: Box::new(SmartCardKeyAgent {
                smart_card,
                active_signing_key_jwk: create_jwk(did_url, &smart_card_info.signing_key),
                active_signing_key: smart_card_info.signing_key,
            }),
        }
    }
}

impl Did {
    pub async fn create_sign_credential(
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
                        self.key_agent
                            .signing_key_jwk()
                            .key_id
                            .expect("public key should have jwk"),
                    )),
                    ..LinkedDataProofOptions::default()
                },
                &DIDWeb,
                &mut ContextLoader::default(),
                &self.key_agent.signing_key_jwk(),
                None,
            )
            .await
            .expect("could not prepare the proof");

        let bytes_to_sign = match &proof_preparation.signing_input {
            SigningInput::Bytes(base64_url_uint) => Some(base64_url_uint.0.clone()),
            _ => None,
        }
        .expect("no bytes to sign");

        let signature_base64 = engine::general_purpose::URL_SAFE_NO_PAD
            .encode(self.key_agent.sign(bytes_to_sign).expect("could not sign"));

        let proof = proof_suite
            .complete(&proof_preparation, &signature_base64)
            .await
            .expect("could not complete proof preparation");

        signed_credential.add_proof(proof);

        Ok(signed_credential)
    }
}
