mod web;

use clap::{Parser, Subcommand};
use std::path::PathBuf;

use whonex::report::write_report;
use whonex::scanner::{scan_file, ScanLimits};

#[derive(Parser, Debug)]
#[command(
    name = "whonex",
    version,
    about = "WHONEX - Security Analysis Engine"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    Info,

    Scan {
        #[arg(value_name = "FILE")]
        file: PathBuf,

        #[arg(short, long, value_name = "PATH")]
        output: Option<PathBuf>,

        #[arg(long, default_value_t = 20)]
        max_file_mb: u64,
    },

    Web {
        #[arg(short, long, value_name = "PATH")]
        output: Option<PathBuf>,
    },
}

fn main() {
    if let Err(error) = run() {
        eprintln!("WHONEX ERROR: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Info => {
            println!("==================================");
            println!("             WHONEX");
            println!("     Security Analysis Engine");
            println!("==================================");
            println!("Version: {}", env!("CARGO_PKG_VERSION"));
            println!("Engine: Rust");
            println!("Mode: Local-first");
            println!("File analysis: Available");
            println!("Web assessment: Initial version");
            println!("Automatic file modification: Disabled");
            println!("==================================");
        }

        Commands::Scan {
            file,
            output,
            max_file_mb,
        } => {
            if max_file_mb == 0 {
                return Err(
                    "Maximum file size must be greater than zero.".into()
                );
            }

            let max_file_size = max_file_mb
                .checked_mul(1024 * 1024)
                .ok_or("Maximum file size is too large.")?;

            let limits = ScanLimits { max_file_size };

            println!("WHONEX: Starting file analysis...");

            let report = scan_file(&file, &limits)?;

            println!();
            println!("Analysis completed.");
            println!("File: {}", report.target);
            println!("Size: {} bytes", report.file_size_bytes);
            println!("SHA-256: {}", report.sha256);
            println!();
            println!("Findings: {}", report.summary.total_findings);
            println!("Critical: {}", report.summary.critical);
            println!("High: {}", report.summary.high);
            println!("Medium: {}", report.summary.medium);
            println!("Low: {}", report.summary.low);
            println!("Info: {}", report.summary.info);

            if report.findings.is_empty() {
                println!("No matching security rules were detected.");
            } else {
                println!();
                println!("Detected findings:");

                for finding in &report.findings {
                    let line = finding
                        .line
                        .map(|value| value.to_string())
                        .unwrap_or_else(|| "-".to_string());

                    println!(
                        "[{:?}] {} | {} | Line {}",
                        finding.severity,
                        finding.rule_id,
                        finding.title,
                        line
                    );
                }
            }

            if let Some(output_path) = output {
                write_report(&report, &output_path)?;
                println!("JSON report saved: {}", output_path.display());
            }
        }

        Commands::Web { output } => {
            web::run_interactive(output)?;
        }
    }

    Ok(())
}
