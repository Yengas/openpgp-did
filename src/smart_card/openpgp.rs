use std::error::Error;

use openpgp_card::{
    algorithm::{Algo, Curve},
    card_do::Fingerprint,
    crypto_data::PublicKeyMaterial,
    OpenPgp, OpenPgpTransaction,
};
use openpgp_card_pcsc::PcscBackend;
use pinentry::PassphraseInput;
use secrecy::{ExposeSecret, Secret};

use crate::crypto::{
    key::{EncryptionKey, EncryptionKeyCurve, Key, SigningKey, SigningKeyCurve},
    smart_card::{SmartCard, SmartCardInfo},
};

pub struct OpenPgpSmartCard {
    openpgp: OpenPgp,
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

impl OpenPgpSmartCard {
    pub fn try_new() -> Result<Self, Box<dyn Error>> {
        let backend = get_card_backend().map_err(|err| -> Box<dyn Error> {
            format!("got some error when listing the cards: {:?}", err).into()
        })?;

        let openpgp = OpenPgp::new(backend);

        Ok(Self { openpgp })
    }

    fn transaction(&mut self) -> Result<OpenPgpTransaction, Box<dyn Error>> {
        self.openpgp
            .transaction()
            .map_err(|err| format!("could not create transaction: {}", err).into())
    }

    fn get_signing_counter(&mut self) -> Result<u32, Box<dyn Error>> {
        let mut transaction = self.openpgp.transaction()?;
        let template = transaction.security_support_template()?;

        Ok(template.signature_count())
    }

    fn get_signing_key_fingerprint(&mut self) -> Result<Fingerprint, Box<dyn Error>> {
        let fingerprints = self
            .transaction()?
            .application_related_data()?
            .fingerprints()?;

        fingerprints
            .signature()
            .map(|f| f.clone())
            .ok_or("there is no signing key".into())
    }
}

fn get_signing_key(
    transaction: &mut OpenPgpTransaction,
    fingerprint: String,
) -> Result<SigningKey, Box<dyn Error>> {
    let public_key = transaction
        .public_key(openpgp_card::KeyType::Signing)
        .expect("could not get signing key");

    match public_key {
        PublicKeyMaterial::E(ecc_pub) => match ecc_pub.algo() {
            Algo::Ecc(attrs) if attrs.curve() == Curve::Ed25519 => Ok(SigningKey::new(
                fingerprint,
                SigningKeyCurve::Ed25519,
                ecc_pub.data().to_vec(),
            )),
            Algo::Ecc(attrs) => Err(format!(
                "expected signing key curve to be {:?} but it was {:?}",
                SigningKeyCurve::Ed25519,
                attrs.curve()
            )
            .into()),
            _ => Err(
                "corrupted result from the openpgp card. ecc key did not have ecc attrs.".into(),
            ),
        },
        _ => Err("signing key was not ECC".into()),
    }
}

fn get_encryption_key(
    transaction: &mut OpenPgpTransaction,
    fingerprint: String,
) -> Result<EncryptionKey, Box<dyn Error>> {
    let public_key = transaction
        .public_key(openpgp_card::KeyType::Decryption)
        .expect("could not get encryption key");

    match public_key {
        PublicKeyMaterial::E(ecc_pub) => match ecc_pub.algo() {
            Algo::Ecc(attrs) if attrs.curve() == Curve::Cv25519 => Ok(EncryptionKey::new(
                fingerprint,
                EncryptionKeyCurve::Cv25519,
                ecc_pub.data().to_vec(),
            )),
            Algo::Ecc(attrs) => Err(format!(
                "expected encryption key curve to be {:?} but it was {:?}",
                EncryptionKeyCurve::Cv25519,
                attrs.curve()
            )
            .into()),
            _ => Err(
                "corrupted result from the openpgp card. ecc key did not have ecc attrs.".into(),
            ),
        },
        _ => Err("encryption key was not ECC".into()),
    }
}

fn convert_firmware_version_to_string(firmware_version: Vec<u8>) -> String {
    firmware_version
        .iter()
        .map(|&num| num.to_string())
        .collect::<Vec<String>>()
        .join(".")
}

impl SmartCard for OpenPgpSmartCard {
    fn get_card_info(&mut self) -> Result<SmartCardInfo, Box<dyn Error>> {
        let mut transaction = self.openpgp.transaction()?;

        let application_related_data = transaction.application_related_data()?;
        let application_identifier = application_related_data.application_id()?.to_string();

        let firmware_version = convert_firmware_version_to_string(transaction.firmware_version()?);
        let signing_counter = transaction.security_support_template()?.signature_count();

        let fingerprints = application_related_data.fingerprints()?;
        let signing_key = get_signing_key(
            &mut transaction,
            fingerprints.signature().unwrap().to_string(),
        )?;
        let encryption_key = get_encryption_key(
            &mut transaction,
            fingerprints.decryption().unwrap().to_string(),
        )?;

        return Ok(SmartCardInfo {
            application_identifier,
            firmware_version,
            signing_counter,
            keys: vec![Key::Signing(signing_key), Key::Encryption(encryption_key)],
        });
    }

    fn sign_data(&mut self, key: &SigningKey, data: Vec<u8>) -> Result<Vec<u8>, Box<dyn Error>> {
        if *key.curve() != SigningKeyCurve::Ed25519 {
            return Err("can only sign with ed25519".into());
        }

        if self.get_signing_key_fingerprint()?.to_string() != *key.fingerprint() {
            return Err("active card signing key does not match the chosen key".into());
        }

        let signing_counter = self.get_signing_counter()?;
        let passphrase = get_passphrase(signing_counter);
        let mut transaction = self.transaction()?;

        assert!(
            transaction
                .verify_pw1_sign(passphrase.expose_secret().as_bytes())
                .is_ok(),
            "the pin was not accepted!"
        );

        Ok(transaction
            .pso_compute_digital_signature(data.clone())
            .expect("could not sign the jwt"))
    }
}
