use std::error::Error;

use openpgp_card::{
    Card,
    ocard::{
        KeyType,
        algorithm::{AlgorithmAttributes, Curve},
        crypto::PublicKeyMaterial,
        data::Fingerprint,
    },
    state::{Open, Transaction},
};
use pinentry::PassphraseInput;
use secrecy::SecretString;

use crate::crypto::{
    key::{EncryptionKey, EncryptionKeyCurve, Key, SigningKey, SigningKeyCurve},
    smart_card::{SmartCard, SmartCardInfo},
};
use crate::smart_card::scdaemon::ScdaemonBackend;

pub struct OpenPgpSmartCard {
    openpgp: Card<Open>,
}

fn get_passphrase(dsc: u32) -> SecretString {
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

impl OpenPgpSmartCard {
    pub fn try_new() -> Result<Self, Box<dyn Error>> {
        let backend = ScdaemonBackend::try_new().map_err(|err| -> Box<dyn Error> {
            format!("could not initialize scdaemon card backend: {err}").into()
        })?;

        let openpgp = Card::<Open>::new(backend)?;

        Ok(Self { openpgp })
    }

    fn transaction(&mut self) -> Result<Card<Transaction<'_>>, Box<dyn Error>> {
        self.openpgp
            .transaction()
            .map_err(|err| format!("could not create transaction: {}", err).into())
    }

    fn get_signing_counter(&mut self) -> Result<u32, Box<dyn Error>> {
        let mut transaction = self.openpgp.transaction()?;

        Ok(transaction.digital_signature_count()?)
    }

    fn get_signing_key_fingerprint(&mut self) -> Result<Fingerprint, Box<dyn Error>> {
        self.transaction()?
            .fingerprint(KeyType::Signing)?
            .ok_or("there is no signing key".into())
    }
}

fn get_signing_key(
    transaction: &mut Card<Transaction<'_>>,
    fingerprint: String,
) -> Result<SigningKey, Box<dyn Error>> {
    let public_key = transaction
        .public_key_material(KeyType::Signing)
        .expect("could not get signing key");

    match public_key {
        PublicKeyMaterial::E(ecc_pub) => match ecc_pub.algo() {
            AlgorithmAttributes::Ecc(attrs) if attrs.curve() == &Curve::Ed25519 => {
                Ok(SigningKey::new(
                    fingerprint,
                    SigningKeyCurve::Ed25519,
                    ecc_pub.data().to_vec(),
                ))
            }
            AlgorithmAttributes::Ecc(attrs) => Err(format!(
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
    transaction: &mut Card<Transaction<'_>>,
    fingerprint: String,
) -> Result<EncryptionKey, Box<dyn Error>> {
    let public_key = transaction
        .public_key_material(KeyType::Decryption)
        .expect("could not get encryption key");

    match public_key {
        PublicKeyMaterial::E(ecc_pub) => match ecc_pub.algo() {
            AlgorithmAttributes::Ecc(attrs) if attrs.curve() == &Curve::Curve25519 => {
                Ok(EncryptionKey::new(
                    fingerprint,
                    EncryptionKeyCurve::Cv25519,
                    ecc_pub.data().to_vec(),
                ))
            }
            AlgorithmAttributes::Ecc(attrs) => Err(format!(
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

        let application_identifier = transaction.application_identifier()?.to_string();

        let firmware_version = convert_firmware_version_to_string(transaction.firmware_version()?);
        let signing_counter = transaction.digital_signature_count().unwrap_or(0);

        let fingerprints = transaction.fingerprints()?;

        let mut keys: Vec<Key> = Vec::new();

        if let Some(signature_fingerprint) = fingerprints.signature() {
            keys.push(
                get_signing_key(&mut transaction, signature_fingerprint.to_string())
                    .map(Key::Signing)?,
            );
        }

        if let Some(encryption_fingerprint) = fingerprints.decryption() {
            keys.push(
                get_encryption_key(&mut transaction, encryption_fingerprint.to_string())
                    .map(Key::Encryption)?,
            );
        }

        Ok(SmartCardInfo {
            application_identifier,
            firmware_version,
            signing_counter,
            keys,
        })
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

        transaction.verify_user_signing_pin(passphrase)?;

        Ok(transaction.card().pso_compute_digital_signature(data)?)
    }
}
