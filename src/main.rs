mod cli;
mod crypto;
mod smart_card;
mod ssi;

use crate::cli::cli::run;

#[tokio::main]
async fn main() {
    run().await.expect("could not execute the CLI")
}
