use ssi::{
    did::{PrimaryDIDURL, DIDURL},
    vc::Credential,
};

use crate::{crypto::smart_card::SmartCard, smart_card::openpgp::OpenPgpSmartCard, ssi::Did};

pub async fn run() {
    let did_url: DIDURL = PrimaryDIDURL::try_from("did:web:yigitcan.dev".to_string())
        .expect("could not parse did")
        .into();

    let mut smart_card =
        OpenPgpSmartCard::try_new().expect("could not initialize openpgp smartcard");

    let smart_card_info = smart_card
        .get_card_info()
        .expect("could not get smart card info");

    let mut did = Did::new(did_url, Box::new(smart_card), smart_card_info);

    let unsigned_credential: Credential = serde_json::from_str(
        r#"
{
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://www.w3.org/2018/credentials/examples/v1"
  ],
  "id": "https://example.edu/credentials/3732",
  "issuer": "did:web:yigitcan.dev",
  "type": ["VerifiableCredential", "UniversityDegreeCredential"],
  "credentialSubject": {
    "id": "did:example:ebfeb1f712ebc6f1c276e12ec21",
    "degree": {
      "type": "BachelorDegree",
      "name": "Bachelor of Science and Arts"
    }
  },
  "issuanceDate": "2021-04-08T15:01:20.110Z"
}
"#,
    )
    .expect("could not parse credential");

    let signed_credential = did
        .create_sign_credential(&unsigned_credential)
        .await
        .expect("could not sign credential");

    println!(
        "signed credential:\n{}",
        serde_json::to_string_pretty(&signed_credential).expect("can not stringify credential"),
    );
}
