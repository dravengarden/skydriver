//! Skydriver management CLI entry point for operators and AI agents.

#[tokio::main]
async fn main() {
    if let Err(error) = skydriver_cli::run(skydriver_cli::Surface::Management).await {
        skydriver_cli::exit_with_error(&error);
    }
}
