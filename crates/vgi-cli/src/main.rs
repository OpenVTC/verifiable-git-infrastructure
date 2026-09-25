//! The `vgi` command.

use clap::Parser;

#[tokio::main]
async fn main() -> std::process::ExitCode {
    let cli = vgi_cli::cli::Cli::parse();
    let mut stdout = std::io::stdout();
    match vgi_cli::run(cli, &mut stdout).await {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("vgi: {e:#}");
            std::process::ExitCode::FAILURE
        }
    }
}
