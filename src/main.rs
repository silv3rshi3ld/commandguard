use anyhow::Context;
use clap::Parser;
use commandguard::analyzer::Analyzer;
use commandguard::bench;
use commandguard::cli::{Cli, Commands};
use commandguard::guard;
use commandguard::warning;
use std::io::{self, Read};

fn main() {
    if let Err(error) = run() {
        eprintln!("commandguard: {error:?}");
        std::process::exit(1);
    }
}

fn run() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Guard { shell } => guard::run(shell),
        Commands::Analyze { json } => {
            let mut input = String::new();
            io::stdin()
                .read_to_string(&mut input)
                .context("failed to read command text from stdin")?;
            let analysis = Analyzer::default().analyze(&input);
            if json {
                println!("{}", serde_json::to_string_pretty(&analysis)?);
            } else {
                print!("{}", warning::human_report(&analysis));
            }
            Ok(())
        }
        Commands::Bench { dir } => {
            let report = bench::run(&dir)?;
            print!("{}", report.render());
            Ok(())
        }
    }
}
