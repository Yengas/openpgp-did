use std::error::Error;

use chrono::Timelike;
use ssi::vc::{Credential, Issuer, VCDateTime, URI};

use super::utils::{create_did, read_file_by_path};

async fn read_unsigned_credential_by_path(
    path: Option<&str>,
) -> Result<Credential, Box<dyn Error>> {
    let credential_json_str = read_file_by_path(path)
        .await
        .expect("could not read credential file");

    Ok(serde_json::from_str::<Credential>(&credential_json_str)
        .expect("could not parse file into Credential"))
}

pub async fn cmd_ssi_sign_credential(file_path: Option<&str>) -> Result<(), Box<dyn Error>> {
    let mut did = create_did().await?;
    let mut unsigned_credential = read_unsigned_credential_by_path(file_path)
        .await
        .expect("could not read credential");

    unsigned_credential.issuer = Some(Issuer::URI(URI::String(did.did_url().to_string())));
    if unsigned_credential.issuance_date == None {
        let current_date_time = chrono::Utc::now().with_nanosecond(0).unwrap();

        unsigned_credential.issuance_date = Some(VCDateTime::from(current_date_time));
    }

    let signed_credential = did
        .create_signed_credential(&unsigned_credential)
        .await
        .expect("could not sign credential");

    println!(
        "{}",
        serde_json::to_string_pretty(&signed_credential).expect("can not stringify credential")
    );

    Ok(())
}
