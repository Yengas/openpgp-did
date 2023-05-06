use std::error::Error;

use base64::{engine, Engine};
use did_web::DIDWeb;
use ssi::{
    did::DIDURL,
    jsonld::ContextLoader,
    jwk::JWK,
    ldp::{ProofSuite, ProofSuiteType, SigningInput},
    vc::{Credential, LinkedDataProofOptions, URI},
};

pub trait KeyAgent {
    fn sign(&mut self, data: Vec<u8>) -> Result<Vec<u8>, Box<dyn Error>>;
    fn signing_key_jwk(&self) -> JWK;
}

pub struct Did {
    key_agent: Box<dyn KeyAgent>,
}

impl Did {
    pub fn new(did_url: DIDURL, key_agent: Box<dyn KeyAgent>) -> Self {
        Self { key_agent }
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
