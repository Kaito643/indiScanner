//! ThreatHarvester CLI — a thin front-end over the `threat_harvester` library crate.

mod tui;

use clap::{Parser, Subcommand};
use std::path::Path;
use threat_harvester::config::Config;
use threat_harvester::engine::{DownloadReport, Engine, Outcome};
use threat_harvester::export::{self, Format};
use threat_harvester::model::entity::{EntityKind, ThreatEntity};
use threat_harvester::model::indicator::IndicatorType;
use threat_harvester::model::request::{Filters, RawIoc, Request};
use threat_harvester::sources;

#[derive(Parser, Debug)]
#[command(name = "threatharvester", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,

    /// Output format: json | csv | stix | misp
    #[arg(short, long, default_value = "json", global = true)]
    output: String,

    /// Path to a config file (defaults to $TH_CONFIG or ./threatharvester.toml)
    #[arg(short, long, global = true)]
    config: Option<String>,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Enrich a single IOC (IP / domain / URL / hash) — type is auto-detected.
    Enrich {
        /// The IOC value to enrich (may be defanged, e.g. `1[.]2[.]3[.]4`).
        value: String,
    },
    /// Collect IOCs related to a threat entity (actor / malware family / campaign).
    Collect {
        /// The entity name to collect for.
        target: String,
        /// Entity kind: actor | malware | campaign
        #[arg(short, long, default_value = "malware")]
        kind: String,
        /// Cap results per source (default: each source's API maximum).
        #[arg(short, long)]
        limit: Option<usize>,
        /// After collecting, download every SHA-256 sample found.
        #[arg(long)]
        download: bool,
        /// With --download, also extract each binary from its zip (password: infected).
        #[arg(long)]
        extract: bool,
        /// Directory for downloaded samples.
        #[arg(long, default_value = "samples")]
        samples_dir: String,
    },
    /// Download malware sample(s) by SHA-256 (from MalwareBazaar) to disk.
    Download {
        /// One or more SHA-256 hashes.
        #[arg(required = true)]
        hashes: Vec<String>,
        /// Directory to save samples into.
        #[arg(short, long, default_value = "samples")]
        dir: String,
        /// Extract the binary from the password-protected zip (password: infected).
        #[arg(long)]
        extract: bool,
    },
    /// List the active sources and what each can answer.
    Sources,
    /// Launch the interactive terminal UI.
    Tui,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenv::dotenv().ok();
    env_logger::init();

    let cli = Cli::parse();

    let config = match &cli.config {
        Some(path) => Config::from_path(path).unwrap_or_default(),
        None => Config::load(),
    };

    // Commands that don't run an enrich/collect request handle themselves.
    match &cli.command {
        Command::Sources => {
            print_sources(&sources::from_config(&config));
            return Ok(());
        }
        Command::Download {
            hashes,
            dir,
            extract,
        } => {
            let engine = Engine::new(sources::from_config(&config), config);
            let reports = engine.download(hashes, Path::new(dir), *extract).await;
            print_download_reports(&reports, false);
            return Ok(());
        }
        Command::Tui => {
            let engine = Engine::new(sources::from_config(&config), config);
            return tui::run(engine).await;
        }
        _ => {}
    }

    // `download_after` carries (dir, extract) when `collect --download` is set.
    let (request, download_after) = match &cli.command {
        Command::Enrich { value } => (Request::Enrich(RawIoc::new(value.clone())), None),
        Command::Collect {
            target,
            kind,
            limit,
            download,
            extract,
            samples_dir,
        } => (
            Request::Collect {
                entity: ThreatEntity::new(target.clone(), parse_kind(kind)),
                filters: Filters {
                    max_results: *limit,
                    ..Filters::default()
                },
            },
            download.then(|| (samples_dir.clone(), *extract)),
        ),
        Command::Sources | Command::Download { .. } | Command::Tui => {
            unreachable!("handled above")
        }
    };

    let format: Format = cli.output.parse()?;

    let engine = Engine::new(sources::from_config(&config), config);
    let indicators = engine.run(request).await?;

    println!("{}", export::render(&indicators, format)?);

    // Sample downloads report on stderr so stdout stays clean export data.
    if let Some((dir, extract)) = download_after {
        let hashes: Vec<String> = indicators
            .iter()
            .filter(|i| i.indicator_type == IndicatorType::Sha256)
            .map(|i| i.value.clone())
            .collect();
        if hashes.is_empty() {
            eprintln!("No SHA-256 samples in the results to download.");
        } else {
            eprintln!("Downloading {} sample(s) to {dir}/ …", hashes.len());
            let reports = engine.download(&hashes, Path::new(&dir), extract).await;
            print_download_reports(&reports, true);
        }
    }
    Ok(())
}

/// Print one line per requested sample, plus a summary. Routes to stderr when
/// downloads accompany a `collect` (keeping the exported IOCs alone on stdout).
fn print_download_reports(reports: &[DownloadReport], to_stderr: bool) {
    let emit = |s: String| {
        if to_stderr {
            eprintln!("{s}");
        } else {
            println!("{s}");
        }
    };
    let mut saved = 0;
    for r in reports {
        emit(match &r.outcome {
            Outcome::Saved {
                source,
                archive,
                extracted,
            } => {
                saved += 1;
                match extracted {
                    Some(p) => format!(
                        "  saved {} -> {} (extracted {}) [{source}]",
                        r.sha256,
                        archive.display(),
                        p.display()
                    ),
                    None => format!("  saved {} -> {} [{source}]", r.sha256, archive.display()),
                }
            }
            Outcome::NotFound => format!("  {} not available from any source", r.sha256),
            Outcome::Failed(e) => format!("  {} failed: {e}", r.sha256),
        });
    }
    emit(format!("{saved}/{} sample(s) downloaded", reports.len()));
}

/// Print a capability table for the sources that are enabled *and* credentialed
/// (key-gated sources missing their key have already logged a warning and are
/// absent here).
fn print_sources(active: &[Box<dyn sources::ThreatSource>]) {
    println!("{:<15} {:<45} OPERATIONS", "SOURCE", "IOC TYPES");
    for source in active {
        let caps = source.capabilities();
        let types: Vec<&str> = caps.ioc_types.iter().map(|t| t.as_tag()).collect();
        let ops: Vec<&str> = caps
            .operations
            .iter()
            .map(|op| match op {
                sources::Operation::Lookup => "lookup",
                sources::Operation::Search => "search",
                sources::Operation::Feed => "feed",
                sources::Operation::Download => "download",
            })
            .collect();
        println!(
            "{:<15} {:<45} {}",
            source.name(),
            types.join(", "),
            ops.join(", ")
        );
    }
}

fn parse_kind(kind: &str) -> EntityKind {
    match kind.to_lowercase().as_str() {
        "actor" => EntityKind::Actor,
        "campaign" => EntityKind::Campaign,
        _ => EntityKind::MalwareFamily,
    }
}
