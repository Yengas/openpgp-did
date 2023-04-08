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
    println!("initialied the OpenPgp correctly");

    let data: Vec<u8> = vec![0, 1, 2];

    let card_info = openpgp.get_card_info().expect("could not get card info");

    println!(
        "got signing key with public key: {}",
        card_info.signing_key_pub_base64
    );

    println!("current signing counter is: {}", card_info.signing_counter);

    let passphrase = get_passphrase(card_info.signing_counter);
    assert!(
        openpgp
            .transaction()
            .and_then(|mut transaction| {
                match transaction.verify_pw1_sign(passphrase.expose_secret().as_bytes()) {
                    Ok(_) => Ok(transaction),
                    Err(err) => Err(err),
                }
            })
            .is_ok(),
        "the pin was not accepted!"
    );

    match openpgp
        .transaction()
        .and_then(|mut transaction| transaction.pso_compute_digital_signature(data))
    {
        Ok(signature) => {
            let str = engine::general_purpose::URL_SAFE_NO_PAD.encode(signature);

            println!("got signature => {}", str);
        }
        Err(err) => println!("got some error when signing data: {}", err),
    }
}
