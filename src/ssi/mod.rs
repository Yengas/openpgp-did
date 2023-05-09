use std::error::Error;

use base64::{engine, Engine};
use did_web::DIDWeb;
use iref::Iri;
use ssi::{
    did::{
        Context, Contexts, Document, VerificationMethod, VerificationMethodMap, DEFAULT_CONTEXT,
        DIDURL,
    },
    jsonld::ContextLoader,
    jwk::{Base64urlUInt, OctetParams, Params, JWK},
    ldp::{ProofSuite, ProofSuiteType, SigningInput},
    vc::{Credential, LinkedDataProofOptions, URI},
};

use crate::crypto::{
    key::{EncryptionKey, Key, SigningKey},
    smart_card::SmartCard,
};

const SECURITY_JWS_2020_V1_CONTEXT: &str = "https://w3id.org/security/suites/jws-2020/v1";

fn create_jwk(did_url: &DIDURL, key: &Key) -> JWK {
    let public_key_as_base64 = engine::general_purpose::URL_SAFE_NO_PAD.encode(key.pub_data());
    let kid = format!("{}#{}", did_url.did, public_key_as_base64.to_string());

    JWK {
        public_key_use: None,
        key_operations: None,
        algorithm: None,
        x509_url: None,
        x509_certificate_chain: None,
        x509_thumbprint_sha1: None,
        x509_thumbprint_sha256: None,
        key_id: Some(kid),
        params: Params::OKP(OctetParams {
            curve: match key {
                Key::Signing(_) => "Ed25519",
                Key::Encryption(_) => "X25519",
            }
            .to_string(),
            public_key: Base64urlUInt(key.pub_data().into()),
            private_key: None,
        }),
    }
}

fn create_did_document(
    did_url: &DIDURL,
    active_signing_key_jwk: &JWK,
    active_encryption_key_jwk: &JWK,
) -> Result<Document, Box<dyn Error>> {
    let did_url_str = did_url.to_string();
    let active_signing_key_did_url: DIDURL =
        DIDURL::try_from(active_signing_key_jwk.key_id.as_ref().unwrap().clone())
            .expect("active signing key id is invalid")
            .into();

    let mut document = Document::new(&did_url_str.as_str());
    let security_context = Iri::from_str(SECURITY_JWS_2020_V1_CONTEXT)?.to_owned();

    document.context = Contexts::Many(vec![
        Context::URI(DEFAULT_CONTEXT.to_owned().into()),
        Context::URI(security_context.into()),
    ]);

    document.verification_method = Some(vec![VerificationMethod::Map(VerificationMethodMap {
        id: active_signing_key_jwk.key_id.as_ref().unwrap().clone(),
        type_: String::from("JsonWebKey2020"),
        controller: did_url_str.clone(),
        public_key_jwk: Some(map_jwk_for_did_document(active_signing_key_jwk)),
        ..Default::default()
    })]);

    document.key_agreement = Some(vec![VerificationMethod::Map(VerificationMethodMap {
        id: active_encryption_key_jwk.key_id.as_ref().unwrap().clone(),
        type_: String::from("JsonWebKey2020"),
        controller: did_url_str.clone(),
        public_key_jwk: Some(map_jwk_for_did_document(active_encryption_key_jwk)),
        ..Default::default()
    })]);

    document.assertion_method = Some(vec![VerificationMethod::DIDURL(
        active_signing_key_did_url.clone(),
    )]);
    document.authentication = Some(vec![VerificationMethod::DIDURL(
        active_signing_key_did_url.clone(),
    )]);
    document.capability_delegation = Some(vec![VerificationMethod::DIDURL(
        active_signing_key_did_url.clone(),
    )]);
    document.capability_invocation = Some(vec![VerificationMethod::DIDURL(
        active_signing_key_did_url.clone(),
    )]);

    Ok(document)
}

fn map_jwk_for_did_document(jwk: &JWK) -> JWK {
    JWK {
        public_key_use: None,
        key_operations: None,
        algorithm: None,
        x509_url: None,
        x509_certificate_chain: None,
        x509_thumbprint_sha1: None,
        x509_thumbprint_sha256: None,
        key_id: None,
        params: jwk.params.clone(),
    }
}

pub struct DidConfiguration {
    pub did_url: DIDURL,
    pub active_signing_key_fp: String,
    pub active_encryption_key_fp: String,
}

pub struct Did {
    smart_card: Box<dyn SmartCard>,
    did_url: DIDURL,
    did_document: Document,
    active_signing_key: SigningKey,
    active_signing_key_jwk: JWK,
}

impl Did {
    pub fn did_url(&self) -> &DIDURL {
        &self.did_url
    }

    pub fn did_document(&self) -> &Document {
        &self.did_document
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

        let active_signing_key_jwk = create_jwk(
            &configuration.did_url,
            &Key::Signing(active_signing_key.clone()),
        );

        let active_encryption_key_jwk = create_jwk(
            &configuration.did_url,
            &Key::Encryption(active_encryption_key),
        );

        let did_document = create_did_document(
            &configuration.did_url,
            &active_signing_key_jwk,
            &active_encryption_key_jwk,
        )
        .expect("could not create did document");

        Ok(Self {
            smart_card,
            did_url: configuration.did_url.clone(),
            did_document,
            active_signing_key: active_signing_key.clone(),
            active_signing_key_jwk,
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
