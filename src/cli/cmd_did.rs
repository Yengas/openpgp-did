use std::error::Error;

use ssi::vc::Credential;

use crate::cli::create_did;

pub async fn cmd_sign_credential() -> Result<(), Box<dyn Error>> {
    let mut did = create_did::create().expect("could not create did");

    let unsigned_credential: Credential = serde_json::from_str(
        r#"
{
"@context": [
  "https://www.w3.org/2018/credentials/v1",
  "https://www.w3.org/2018/credentials/examples/v1",
  "https://w3id.org/security/suites/jws-2020/v1"
],
"id": "https://trakya.edu.tr/credentials/0001",
"issuer": "did:web:yigitcan.dev",
"type": ["VerifiableCredential", "UniversityDegreeCredential"],
"credentialSubject": {
  "id": "did:web:yigitcan.dev",
  "degree": {
    "type": "BachelorDegree",
    "name": "Bachelor of Computer Science"
  }
},
"issuanceDate": "2019-05-08T15:01:20.110Z"
}
"#,
    )
    .expect("could not parse credential");

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
