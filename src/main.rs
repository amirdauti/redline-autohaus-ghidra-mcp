use clap::Parser;
use ghidra_mcp::{backend::Backend, domain::EmptyParams, mailbox::Mailbox, server::GhidraServer};
use rmcp::ServiceExt;
use std::{path::PathBuf, time::Duration};

#[derive(Debug, Parser)]
#[command(version, about = "Local MCP server for the Ghidra companion bridge")]
struct Args {
    /// Absolute local directory shared with the Ghidra Java bridge.
    #[arg(long)]
    bridge_dir: PathBuf,
    #[arg(long, default_value_t = 45000, value_parser = clap::value_parser!(u64).range(100..=120000))]
    timeout_ms: u64,
    /// Print bridge status as JSON and exit instead of serving MCP over stdio.
    #[arg(long)]
    doctor: bool,
}

#[tokio::main]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("ghidra-mcp: {error}");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), String> {
    let args = Args::parse();
    let mut backend = Backend::new(Mailbox::open(
        &args.bridge_dir,
        Duration::from_millis(args.timeout_ms),
    )?);
    if args.doctor {
        println!(
            "{}",
            serde_json::to_string_pretty(&backend.execute("status", &EmptyParams {}).await?)
                .map_err(|e| e.to_string())?
        );
        return Ok(());
    }
    let service = GhidraServer::new(backend)
        .serve(rmcp::transport::stdio())
        .await
        .map_err(|error| error.to_string())?;
    service.waiting().await.map_err(|error| error.to_string())?;
    Ok(())
}
