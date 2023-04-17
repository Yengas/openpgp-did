mod cli;
mod crypto;
mod smart_card;
mod ssi;

#[tokio::main]
async fn main() {
    cli::run().await.expect("could not execute the CLI")
}
