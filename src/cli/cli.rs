use std::error::Error;

use crate::cli::{cmd_card, cmd_did};

pub async fn run() -> Result<(), Box<dyn Error>> {
    let cmd = clap::Command::new("idagent")
        .bin_name("idagent")
        .version("0.1")
        .author("Yiğitcan UÇUM <yigitcan@hotmail.com.tr>")
        .subcommand_required(true)
        .subcommand(
            clap::Command::new("card")
                .subcommand_required(true)
                .subcommand(clap::Command::new("info"))
                .subcommand(clap::Command::new("diagnostic")),
        )
        .subcommand(
            clap::Command::new("did")
                .subcommand_required(true)
                .subcommand(clap::Command::new("sign-credential")),
        );

    let matches = cmd.get_matches();

    match matches.subcommand() {
        Some(("card", arg_matches)) => match arg_matches.subcommand() {
            Some(("info", _)) => cmd_card::cmd_card_info().await,
            Some(("diagnostic", _)) => cmd_card::cmd_card_diagnostic().await,
            _ => Err("invalid command".into()),
        },
        Some(("did", arg_matches)) => match arg_matches.subcommand() {
            Some(("sign-credential", _)) => cmd_did::cmd_sign_credential().await,
            _ => Err("invalid command".into()),
        },
        _ => Err("invalid command".into()),
    }
}
