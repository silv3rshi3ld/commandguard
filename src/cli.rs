use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(name = "commandguard")]
#[command(about = "Semantic paste firewall for Linux terminals")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Debug, Subcommand)]
pub enum Commands {
    /// Run a guarded interactive shell under a PTY.
    Guard {
        /// Shell to launch. Defaults to $SHELL or /bin/bash.
        #[arg(long)]
        shell: Option<PathBuf>,
    },

    /// Analyze command text from stdin.
    Analyze {
        /// Emit the structured Analysis model as JSON.
        #[arg(long)]
        json: bool,
    },

    /// Run a fixture corpus and print detection metrics.
    Bench {
        /// Corpus root containing benign, malicious, or mutations cases.
        dir: PathBuf,
    },
}
