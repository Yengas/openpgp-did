use base64::{engine, Engine};
use did_web::DIDWeb;
use ssi::{
    jsonld::ContextLoader,
    jwk::{Algorithm, Base64urlUInt, OctetParams, Params, JWK},
    ldp::{ProofSuite, ProofSuiteType, SigningInput},
    vc::{Credential, LinkedDataProofOptions, URI},
};

use crate::{crypto::smart_card::SmartCard, smart_card::openpgp::OpenPgpSmartCard};

pub async fn run() {
    let mut smart_card =
        OpenPgpSmartCard::try_new().expect("could not initialize openpgp smartcard");
    let smart_card_info = smart_card
        .get_card_info()
        .expect("could not get smart card info");
    let signing_key_pub_base64 =
        engine::general_purpose::URL_SAFE_NO_PAD.encode(smart_card_info.signing_key.pub_data());
    println!("initialized the OpenPgp correctly");

    println!(
        "got signing key with public key: {}",
        signing_key_pub_base64
    );

    println!(
        "current signing counter is: {}",
        smart_card_info.signing_counter
    );

    let mut credential: Credential = serde_json::from_str(
        r#"
{
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://www.w3.org/2018/credentials/examples/v1"
  ],
  "id": "https://example.edu/credentials/3732",
  "issuer": "did:web:yigitcan.dev",
  "type": ["VerifiableCredential", "UniversityDegreeCredential"],
  "credentialSubject": {
    "id": "did:example:ebfeb1f712ebc6f1c276e12ec21",
    "degree": {
      "type": "BachelorDegree",
      "name": "Bachelor of Science and Arts"
    }
  },
  "issuanceDate": "2021-04-08T15:01:20.110Z"
}
"#,
    )
    .expect("could not parse credential");

    let proof_suite: Box<dyn ProofSuite> = Box::new(ProofSuiteType::JsonWebSignature2020);
    let jwk = JWK {
        public_key_use: Some("sig".to_string()),
        key_operations: Some(vec!["sig".to_string()]),
        algorithm: Some(Algorithm::EdDSA),
        key_id: Some(
            "did:web:yigitcan.dev#AD9t5zc7yeWQNQr2QbsydsX-b59zgOrPgcDJcEXBZzk".to_string(),
        ),
        x509_url: None,
        x509_certificate_chain: None,
        x509_thumbprint_sha1: None,
        x509_thumbprint_sha256: None,
        params: Params::OKP(OctetParams {
            curve: "Ed25519".to_string(),
            public_key: Base64urlUInt(
                engine::general_purpose::URL_SAFE_NO_PAD
                    .decode("AD9t5zc7yeWQNQr2QbsydsX-b59zgOrPgcDJcEXBZzk")
                    .expect("public key is not valid"),
            ),
            private_key: None,
        }),
    };

    let proof_preparation = proof_suite
        .prepare(
            &credential,
            &LinkedDataProofOptions {
                verification_method: Some(URI::String(
                    "did:web:yigitcan.dev#AD9t5zc7yeWQNQr2QbsydsX-b59zgOrPgcDJcEXBZzk".to_string(),
                )),
                ..LinkedDataProofOptions::default()
            },
            &DIDWeb,
            &mut ContextLoader::default(),
            &jwk,
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
        smart_card
            .sign_data(smart_card_info.signing_key, bytes_to_sign)
            .expect("could not sign"),
    );

    let proof = proof_suite
        .complete(&proof_preparation, &signature_base64)
        .await
        .expect("could not complete proof preparation");

    credential.add_proof(proof);

    println!(
        "signed credential:\n{}",
        serde_json::to_string_pretty(&credential).expect("can not stringify credential"),
    );
}
