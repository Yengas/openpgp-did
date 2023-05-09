use serde::{Deserialize, Serialize};
use ssi::did::{PrimaryDIDURL, DIDURL};
use std::error::Error;
use std::path::PathBuf;
use tokio::{
    fs::{self, File},
    io::{AsyncReadExt, AsyncWriteExt},
};

use crate::ssi::DidConfiguration;

const OPENPGP_DID_CONFIG_FOLDER: &str = ".openpgp-did";
const DID_CONFIGURATION_FILE: &str = "did-configuration.yml";

#[derive(Serialize, Deserialize)]
struct ConfigDidConfiguration {
    pub did_url: String,
    pub key_fingerprints: ConfigDidConfigurationKeyFingerprints,
}

#[derive(Serialize, Deserialize)]
struct ConfigDidConfigurationKeyFingerprints {
    pub active_signing_key: String,
    pub active_encryption_key: String,
}

fn get_config_dir() -> Result<PathBuf, Box<dyn Error>> {
    let mut config_dir = dirs::home_dir().ok_or("Failed to find home directory")?;

    config_dir.push(OPENPGP_DID_CONFIG_FOLDER);

    Ok(config_dir)
}

fn get_config_file_path(file_path: &str) -> Result<PathBuf, Box<dyn Error>> {
    let mut config_dir = get_config_dir()?;

    config_dir.push(file_path);

    Ok(config_dir)
}

pub async fn save_did_configuration(
    did_configuration: &DidConfiguration,
) -> Result<(), Box<dyn Error>> {
    let config_dir = get_config_dir()?;
    fs::create_dir_all(&config_dir)
        .await
        .expect("could not create configuration directory");

    let did_configuration_file = get_config_file_path(DID_CONFIGURATION_FILE)?;
    let mut file = File::create(did_configuration_file)
        .await
        .expect("could not create did configuration file");

    let serialized = serde_yaml::to_string(&ConfigDidConfiguration {
        did_url: did_configuration.did_url.to_string(),
        key_fingerprints: ConfigDidConfigurationKeyFingerprints {
            active_signing_key: did_configuration.active_signing_key_fp.clone(),
            active_encryption_key: did_configuration.active_encryption_key_fp.clone(),
        },
    })?;

    file.write_all(serialized.as_bytes())
        .await
        .expect("could not write to did configuration file");

    Ok(())
}

pub async fn read_did_configuration() -> Result<Option<DidConfiguration>, Box<dyn Error>> {
    let did_configuration_file = get_config_file_path(DID_CONFIGURATION_FILE)?;
    let mut file = match File::open(did_configuration_file).await {
        Ok(file) => file,
        Err(_) => return Ok(None),
    };

    let mut contents = String::new();
    file.read_to_string(&mut contents)
        .await
        .expect("could not read the did configuration file");

    let did_config: ConfigDidConfiguration =
        serde_yaml::from_str(&contents).expect("could not parse did configuration file");

    let did_url: DIDURL = PrimaryDIDURL::try_from(did_config.did_url)
        .expect("could not parse did")
        .into();

    Ok(Some(DidConfiguration {
        did_url,
        active_signing_key_fp: did_config.key_fingerprints.active_signing_key,
        active_encryption_key_fp: did_config.key_fingerprints.active_encryption_key,
    }))
}

pub async fn does_valid_did_configuration_exist() -> bool {
    match read_did_configuration().await {
        Ok(Some(_)) => true,
        _ => false,
    }
}
