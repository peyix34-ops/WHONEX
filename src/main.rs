
use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(
    name = "whonex",
    version,
    about = "WHONEX - Enterprise File Security Analysis Engine",
    long_about = "WHONEX is a local-first security analysis engine designed for authorized enterprise file assessments.",
    subcommand_required = true,
    arg_required_else_help = true
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Display WHONEX project information.
    Info,
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Info => {
            display_info();
        }
    }
}

fn display_info() {
    println!("========================================");
    println!("              WHONEX");
    println!("    Enterprise Security Analysis");
    println!("========================================");
    println!("Version: {}", env!("CARGO_PKG_VERSION"));
    println!("Engine: Rust");
    println!("Architecture: Local-first");
    println!("Status: Initial development");
    println!("========================================");
}
