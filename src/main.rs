use std::error::Error;

use base64::{engine, Engine};
use did_web::DIDWeb;
use openpgp_card::{crypto_data::PublicKeyMaterial, OpenPgp};
use openpgp_card_pcsc::PcscBackend;
use pinentry::PassphraseInput;
use secrecy::{ExposeSecret, Secret};
use ssi::{
    jsonld::ContextLoader,
    jwk::{Algorithm, Base64urlUInt, OctetParams, Params, JWK},
    ldp::{ProofSuite, ProofSuiteType, SigningInput},
    vc::{Credential, LinkedDataProofOptions, URI},
};

struct SmartCardInfo {
    signing_key_pub_base64: String,
    signing_counter: u32,
}

trait SmartCard {
    fn get_card_info(&mut self) -> Result<SmartCardInfo, Box<dyn Error>>;
}

impl SmartCard for OpenPgp {
    fn get_card_info(&mut self) -> Result<SmartCardInfo, Box<dyn Error>> {
        let mut transaction = self.transaction()?;
        let public_key = transaction.public_key(openpgp_card::KeyType::Signing)?;
        let template = transaction.security_support_template()?;

        if let PublicKeyMaterial::E(ecc_pub) = public_key {
            let signing_key_pub_base64 =
                engine::general_purpose::URL_SAFE_NO_PAD.encode(ecc_pub.data());

            Ok(SmartCardInfo {
                signing_key_pub_base64,
                signing_counter: template.signature_count(),
            })
        } else {
            Err("the signing key is not ECC".into())
        }
    }
}

fn get_card_backend() -> Result<PcscBackend, Box<dyn Error>> {
    let mut backends = PcscBackend::cards(None)?;
    if backends.len() == 1 {
        return Ok(backends.remove(0));
    }

    return Err(format!(
        "expected exactly one backend to be listed but got = {}",
        backends.len()
    )
    .into());
}

fn get_passphrase(dsc: u32) -> Secret<String> {
    let binary = which::which("pinentry").expect("`pinentry` not installed");
    let mut input = PassphraseInput::with_binary(binary).expect("could not initialize pinentry");

    match input
        .with_description(
            format!(
                "Enter your Yubikey passcode for signing a credential. Signing Counter is {}",
                dsc
            )
            .as_str(),
        )
        .with_prompt("User Pin Code:")
        .interact()
    {
        Ok(passphrase) => passphrase,
        Err(err) => panic!("could not get the passphrase from the user: {:?}", err),
    }
}

#[tokio::main]
async fn main() {
    let backend = get_card_backend().expect("got some error when listing the cards");
    let mut openpgp = OpenPgp::new(backend);
    println!("initialized the OpenPgp correctly");

    let card_info = openpgp.get_card_info().expect("could not get card info");

    println!(
        "got signing key with public key: {}",
        card_info.signing_key_pub_base64
    );

    println!("current signing counter is: {}", card_info.signing_counter);

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

    let passphrase = get_passphrase(card_info.signing_counter);
    let mut transaction = openpgp.transaction().expect("could not create transaction");

    assert!(
        transaction
            .verify_pw1_sign(passphrase.expose_secret().as_bytes())
            .is_ok(),
        "the pin was not accepted!"
    );

    let signature_bytes = transaction
        .pso_compute_digital_signature(bytes_to_sign.clone())
        .expect("could not sign the jwt");
    let signature_base64 = engine::general_purpose::URL_SAFE_NO_PAD.encode(signature_bytes);

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
