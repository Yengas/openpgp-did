use std::error::Error;
use tokio::{fs::File, io::stdin, io::AsyncReadExt};

use crate::{smart_card::openpgp::OpenPgpSmartCard, ssi::Did};

use super::config::read_did_configuration;

pub async fn read_file_by_path(path: Option<&str>) -> Result<String, Box<dyn Error>> {
    let mut contents = String::new();

    match path {
        Some("-") | None => {
            stdin().read_to_string(&mut contents).await?;
        }
        Some(file_path) => {
            let mut file = File::open(file_path).await?;

            file.read_to_string(&mut contents).await?;
        }
    }

    Ok(contents)
}

pub async fn create_did() -> Result<Did, Box<dyn Error>> {
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
