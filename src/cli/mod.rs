use ssi::{
    did::{PrimaryDIDURL, DIDURL},
    vc::Credential,
};
use std::error::Error;

use crate::{crypto::smart_card::SmartCard, smart_card::openpgp::OpenPgpSmartCard, ssi::Did};

fn create_did() -> Did {
    let did_url: DIDURL = PrimaryDIDURL::try_from("did:web:yigitcan.dev".to_string())
        .expect("could not parse did")
        .into();

    let mut smart_card =
        OpenPgpSmartCard::try_new().expect("could not initialize openpgp smartcard");

    let smart_card_info = smart_card
        .get_card_info()
        .expect("could not get smart card info");

    Did::new(did_url, Box::new(smart_card), smart_card_info)
}

async fn cmd_sign_credential() -> Result<(), Box<dyn Error>> {
    let mut did = create_did();

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
        "{}",
        serde_json::to_string_pretty(&signed_credential).expect("can not stringify credential")
    );

    Ok(())
}

pub async fn run() -> Result<(), Box<dyn Error>> {
    let cmd = clap::Command::new("idagent")
        .bin_name("idagent")
        .version("0.1")
        .author("Yiğitcan UÇUM <yigitcan@hotmail.com.tr>")
        .subcommand_required(true)
        .subcommand(
            clap::Command::new("did")
                .subcommand_required(true)
                .subcommand(clap::Command::new("sign-credential")),
        );

    let matches = cmd.get_matches();

    match matches.subcommand() {
        Some(("did", arg_matches)) => match arg_matches.subcommand() {
            Some(("sign-credential", _)) => cmd_sign_credential().await,
            _ => Err("invalid command".into()),
        },
        _ => Err("invalid command".into()),
    }
}
