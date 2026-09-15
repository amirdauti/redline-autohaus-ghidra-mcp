use clap::Parser;
use ghidra_mcp::{
    backend::Backend, domain::EmptyParams, launch, mailbox::Mailbox, server::GhidraServer,
};
use rmcp::ServiceExt;
use std::{path::PathBuf, time::Duration};

#[derive(Debug, Parser)]
#[command(version, about = "Local MCP server for the Ghidra companion bridge")]
struct Args {
    /// Absolute local directory shared with the Ghidra Java bridge.
    #[arg(long)]
    bridge_dir: PathBuf,
    /// Windows only: start the configured Java bridge if bridge.lock is not held.
    #[arg(long)]
    launch_config: Option<PathBuf>,
    #[arg(long, default_value_t = 45000, value_parser = clap::value_parser!(u64).range(100..=120000))]
    timeout_ms: u64,
    /// Print bridge status as JSON and exit instead of serving MCP over stdio.
    #[arg(long)]
    doctor: bool,
}

fn main() {
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("ghidra-mcp: cannot start async runtime: {error}");
            std::process::exit(1);
        }
    };
    let result = runtime.block_on(run());
    // On Windows, aborted launcher pipe readers can retain blocking ReadFile workers until
    // the independent Java descendant exits. MCP completion must not wait for that daemon's
    // lifetime. Pending mailbox operations already preserve their durable recovery marker.
    runtime.shutdown_timeout(Duration::from_millis(100));
    if let Err(error) = result {
        eprintln!("ghidra-mcp: {error}");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), String> {
    let args = Args::parse();
    // Hold client ownership and reject stale exchanges before a launcher could start Java.
    let mailbox = Mailbox::open(&args.bridge_dir, Duration::from_millis(args.timeout_ms))?;
    if let Some(config) = &args.launch_config {
        launch::ensure_bridge(config, &args.bridge_dir).await?;
    }
    let mut backend = Backend::new(mailbox);
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
