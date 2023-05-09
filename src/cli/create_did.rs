use std::error::Error;

use crate::{smart_card::openpgp::OpenPgpSmartCard, ssi::Did};

use super::config::read_did_configuration;

pub async fn create() -> Result<Did, Box<dyn Error>> {
    let did_configuration = read_did_configuration()
        .await
        .expect("could not read did configuration file")
        .expect("did configuration does not exist");

    let smart_card = OpenPgpSmartCard::try_new().expect("could not initialize openpgp smartcard");

    let did: Did = Did::from_smart_card(did_configuration, Box::new(smart_card))
        .await
        .expect("could not create did");

    Ok(did)
}
