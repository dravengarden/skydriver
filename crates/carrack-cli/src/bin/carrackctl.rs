//! Carrack management CLI entry point for operators and AI agents.

#[tokio::main]
async fn main() {
    if let Err(error) = carrack_cli::run(carrack_cli::Surface::Management).await {
        carrack_cli::exit_with_error(&error);
    }
}
