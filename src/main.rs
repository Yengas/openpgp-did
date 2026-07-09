mod cli;
mod crypto;
mod smart_card;
mod ssi;

use std::error::Error;

use crate::cli::cli::run;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    run().await
}
