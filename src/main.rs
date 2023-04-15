mod cli;
mod crypto;
mod smart_card;

#[tokio::main]
async fn main() {
    cli::run().await
}
