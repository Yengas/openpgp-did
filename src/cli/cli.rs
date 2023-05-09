use std::error::Error;

use clap::Arg;

use crate::cli::{cmd_card, cmd_ssi};

use super::cmd_did;

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
            clap::Command::new("did")
                .about("DID and DID Document related operations")
                .arg_required_else_help(true)
                .subcommand(
                    clap::Command::new("init").about("Initialize your DID for further operations"),
                )
                .subcommand(clap::Command::new("document").about("Export your DID Document")),
        )
        .subcommand(
            clap::Command::new("ssi")
                .about("Self-sovereign Identity related operations")
                .arg_required_else_help(true)
                .subcommand(
                    clap::Command::new("sign-credential")
                        .arg(
                            Arg::new("file")
                            .required(false)
                            .short('f')
                            .long("file")
                            .value_name("FILE")
                            .help("Sets the input file to use as the credential. Omit or use '-' for stdin."),
                        )
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
        Some(("did", arg_matches)) => match arg_matches.subcommand() {
            Some(("init", _)) => cmd_did::cmd_did_init().await,
            Some(("document", _)) => cmd_did::cmd_did_document().await,
            _ => Err("invalid command".into()),
        },
        Some(("ssi", arg_matches)) => match arg_matches.subcommand() {
            Some(("sign-credential", args)) => {
                cmd_ssi::cmd_ssi_sign_credential(
                    args.get_one::<String>("file").map(|str| str.as_str()),
                )
                .await
            }
            _ => Err("invalid command".into()),
        },
        _ => Err("invalid command".into()),
    }
}
