use std::error::Error;

use crate::cli::{cmd_card, cmd_ssi};

pub async fn run() -> Result<(), Box<dyn Error>> {
    let cmd = clap::Command::new("openpgp-did")
        .bin_name("openpgp-did")
        .version("0.1")
        .author("Yiğitcan UÇUM <yigitcan@hotmail.com.tr>")
        .arg_required_else_help(true)
        .subcommand(
            clap::Command::new("card")
                .about("OpenPGP card related operations")
                .arg_required_else_help(true)
                .subcommand(
                    clap::Command::new("info")
                        .about("Output human-readable information about your card"),
                )
                .subcommand(
                    clap::Command::new("diagnostic").about(
                        "Run diagnostic about your card and whether it is usable by this CLI",
                    ),
                ),
        )
        .subcommand(
            clap::Command::new("ssi")
                .about("Self-sovereign Identity related operations")
                .arg_required_else_help(true)
                .subcommand(
                    clap::Command::new("sign-credential")
                        .about("Create proof and append it to an unsigned verifiable credential"),
                ),
        );

    let matches = cmd.get_matches();

    match matches.subcommand() {
        Some(("card", arg_matches)) => match arg_matches.subcommand() {
            Some(("info", _)) => cmd_card::cmd_card_info().await,
            Some(("diagnostic", _)) => cmd_card::cmd_card_diagnostic().await,
            _ => Err("invalid command".into()),
        },
        Some(("ssi", arg_matches)) => match arg_matches.subcommand() {
            Some(("sign-credential", _)) => cmd_ssi::cmd_ssi_sign_credential().await,
            _ => Err("invalid command".into()),
        },
        _ => Err("invalid command".into()),
    }
}
