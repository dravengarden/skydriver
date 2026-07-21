//! Skydriver filesystem CLI entry point.

#[tokio::main]
async fn main() {
    if let Err(error) = skydriver_cli::run(skydriver_cli::Surface::Filesystem).await {
        skydriver_cli::exit_with_error(&error);
    }
}
