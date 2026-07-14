//! Carrack filesystem CLI entry point.

#[tokio::main]
async fn main() {
    if let Err(error) = carrack_cli::run(carrack_cli::Surface::Filesystem).await {
        carrack_cli::exit_with_error(&error);
    }
}
