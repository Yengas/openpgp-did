use std::error::Error;

use chrono::Timelike;
use ssi::vc::{Credential, Issuer, VCDateTime, URI};

use crate::cli::create_did;

pub async fn cmd_ssi_sign_credential() -> Result<(), Box<dyn Error>> {
    let mut did = create_did::create().await?;

    let mut unsigned_credential: Credential = serde_json::from_str(
        r#"
{
"@context": [
  "https://www.w3.org/2018/credentials/v1",
  "https://www.w3.org/2018/credentials/examples/v1",
  "https://w3id.org/security/suites/jws-2020/v1"
],
"id": "https://trakya.edu.tr/credentials/0001",
"type": ["VerifiableCredential", "UniversityDegreeCredential"],
"credentialSubject": {
  "id": "did:web:yigitcan.dev",
  "degree": {
    "type": "BachelorDegree",
    "name": "Bachelor of Computer Science"
  }
}
}
"#,
    )
    .expect("could not parse credential");

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
