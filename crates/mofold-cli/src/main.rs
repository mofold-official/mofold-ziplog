// mofold-cli/src/main.rs — ziplog CLI entry point
//
// Commands:
//   ziplog init       — Generate PMK + key hierarchy
//   ziplog rotate     — Recover RK/WK from encrypted PMK file
//   ziplog voucher    — Issue a signed voucher token
//   ziplog tail       — Tail a file → batch-encrypt → batch-ship to Gateway
//   ziplog encrypt    — One-shot encrypt (stdin or --message)
//   ziplog decrypt    — Decrypt a BDP blob (requires WK)
//   ziplog read       — Retrieve + decrypt a single entry (RK auth, WK decrypt)
//   ziplog get-burn   — Retrieve-and-delete an entry
//   ziplog batch-get  — Retrieve + decrypt a range of entries in bulk
//   ziplog delete     — Delete a stored entry (WK required)
//   ziplog status     — Check gateway, keys, voucher health

mod commands;
mod agent;
mod pmk;

use clap::{Parser, Subcommand};
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(
    name    = "ziplog",
    about   = "MofoldZiplog — Zero-identity encrypted log shipping & secret management",
    version = env!("CARGO_PKG_VERSION"),
)]
struct Cli {
    /// Gateway URL (e.g. https://ziplog.your-worker.workers.dev)
    #[arg(long, env = "ZIPLOG_GATEWAY_URL", global = true)]
    gateway: Option<String>,

    #[arg(short, long, action = clap::ArgAction::Count, global = true)]
    verbose: u8,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Generate a new Project Master Key hierarchy
    Init(commands::init::InitArgs),

    /// Load an encrypted PMK file and re-print RK + WK
    Rotate(commands::rotate::RotateArgs),

    /// Issue a signed voucher token
    Voucher(commands::voucher::VoucherArgs),

    /// Tail a log file and ship encrypted entries (batch per window)
    Tail(commands::tail::TailArgs),

    /// Encrypt a message to a BDP fold (stdin if --message omitted)
    Encrypt(commands::encrypt::EncryptArgs),

    /// Decrypt a BDP blob (WK required — WK is the encryption key)
    Decrypt(commands::decrypt::DecryptArgs),

    /// Retrieve and decrypt a single stored entry (RK auth, WK decrypt)
    Read(commands::read::ReadArgs),

    /// Retrieve-and-delete (burn-on-read) a stored entry
    GetBurn(commands::read::GetBurnArgs),

    /// Retrieve and decrypt a range of entries in one Gateway round trip
    BatchGet(commands::batch_get::BatchGetArgs),

    /// Delete a stored entry from the Gateway (WK required)
    Delete(commands::delete::DeleteArgs),

    /// Check gateway connectivity, key format, and voucher validity
    Status(commands::status::StatusArgs),
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    let log_level = match cli.verbose {
        0 => "warn", 1 => "info", 2 => "debug", _ => "trace",
    };
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new(log_level))
        )
        .init();

    let gateway = cli.gateway.clone();
    match cli.command {
        Command::Init(a)     => commands::init::run(a).await,
        Command::Rotate(a)   => commands::rotate::run(a).await,
        Command::Voucher(a)  => commands::voucher::run(a).await,
        Command::Tail(a)     => commands::tail::run(a, gateway).await,
        Command::Encrypt(a)  => commands::encrypt::run(a).await,
        Command::Decrypt(a)  => commands::decrypt::run(a).await,
        Command::Read(a)     => commands::read::run_read(a, gateway).await,
        Command::GetBurn(a)  => commands::read::run_get_burn(a, gateway).await,
        Command::BatchGet(a) => commands::batch_get::run(a, gateway).await,
        Command::Delete(a)   => commands::delete::run(a, gateway).await,
        Command::Status(a)   => commands::status::run(a, gateway).await,
    }
}
