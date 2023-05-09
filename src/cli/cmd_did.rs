use std::{
    error::Error,
    io::{stdin, stdout, Write},
};

use ssi::did::{PrimaryDIDURL, DIDURL};

use crate::{
    crypto::{key::Key, smart_card::SmartCard},
    smart_card::openpgp::OpenPgpSmartCard,
    ssi::DidConfiguration,
};

use super::{
    config::{does_valid_did_configuration_exist, save_did_configuration},
    utils,
};

fn ask_user(question: &str) -> Result<String, Box<dyn Error>> {
    print!("{}", question);
    stdout().flush()?;
    let mut input = String::new();
    stdin().read_line(&mut input)?;

    Ok(input.trim().to_string())
}

pub async fn cmd_did_init() -> Result<(), Box<dyn Error>> {
    if does_valid_did_configuration_exist().await {
        let answer = ask_user("Do you want to overwrite existing Did Configuration? (y/n) ")?;

        if answer.to_lowercase() != "y".to_string() {
            println!("Exiting as you did not want to overwrite the existing configuration.");

            return Ok(());
        }
    }

    let did_url_input = ask_user("Your DID (e.g. did:web:yigitcan.dev): ")?;
    let did_url: DIDURL = PrimaryDIDURL::try_from(did_url_input)
        .expect("could not parse did")
        .into();

    let mut smart_card = OpenPgpSmartCard::try_new().expect("could not initialize OpenPGP Card");
    let smart_card_info = smart_card
        .get_card_info()
        .expect("could not get smart card info");

    let signing_key = smart_card_info
        .keys
        .iter()
        .find_map(|key| match key {
            Key::Signing(signing_key) => Some(signing_key.clone()),
            _ => None,
        })
        .expect("could not find signing key to use");

    let encryption_key = smart_card_info
        .keys
        .iter()
        .find_map(|key| match key {
            Key::Encryption(encryption_key) => Some(encryption_key.clone()),
            _ => None,
        })
        .expect("could not find encryption key to use");

    let did_configuration = DidConfiguration {
        did_url,
        active_signing_key_fp: signing_key.fingerprint().clone(),
        active_encryption_key_fp: encryption_key.fingerprint().clone(),
    };

    save_did_configuration(&did_configuration)
        .await
        .expect("could not write did configuration file");

    println!("Your DID Configuration was written successfully!");

    Ok(())
}

pub async fn cmd_did_document() -> Result<(), Box<dyn Error>> {
    let did = utils::create_did().await?;
    let document = did.did_document();

    let document_json_str =
        serde_json::to_string_pretty(document).expect("could not stringify did document");

    println!("{}", document_json_str);

    Ok(())
}
