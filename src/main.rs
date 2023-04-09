use std::error::Error;

use base64::{engine, Engine};
use openpgp_card::{crypto_data::PublicKeyMaterial, OpenPgp};
use openpgp_card_pcsc::PcscBackend;
use pinentry::PassphraseInput;
use secrecy::{ExposeSecret, Secret};

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

fn main() {
    let backend = get_card_backend().expect("got some error when listing the cards");
    let mut openpgp = OpenPgp::new(backend);
    println!("initialized the OpenPgp correctly");

    let card_info = openpgp.get_card_info().expect("could not get card info");

    println!(
        "got signing key with public key: {}",
        card_info.signing_key_pub_base64
    );

    println!("current signing counter is: {}", card_info.signing_counter);

    let jwt_to_sign: Vec<u8> = b"eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.eyJ2YyI6eyJAY29udGV4dCI6WyJodHRwczovL3d3dy53My5vcmcvMjAxOC9jcmVkZW50aWFscy92MSJdLCJ0eXBlIjpbIlZlcmlmaWFibGVDcmVkZW50aWFsIl0sImNyZWRlbnRpYWxTdWJqZWN0Ijp7InlvdSI6IlJvY2sifX0sInN1YiI6ImRpZDp3ZWI6ZXhhbXBsZS5jb20iLCJuYmYiOjE2ODEwNTI4MDQsImlzcyI6ImRpZDp3ZWI6eWlnaXRjYW4uZGV2In0".to_vec();
    let passphrase = get_passphrase(card_info.signing_counter);
    let mut transaction = openpgp.transaction().expect("could not create transaction");

    assert!(
        transaction
            .verify_pw1_sign(passphrase.expose_secret().as_bytes())
            .is_ok(),
        "the pin was not accepted!"
    );

    let signature_bytes = transaction
        .pso_compute_digital_signature(jwt_to_sign.clone())
        .expect("could not sign the jwt");
    let signature_base64 = engine::general_purpose::URL_SAFE_NO_PAD.encode(signature_bytes);

    println!(
        "signed jwt: {}.{}",
        String::from_utf8(jwt_to_sign).unwrap(),
        signature_base64
    );
}
