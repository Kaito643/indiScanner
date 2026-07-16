//! ThreatHarvester CLI — a thin front-end over the `threat_harvester` library crate.

use clap::{Parser, Subcommand};
use threat_harvester::config::Config;
use threat_harvester::engine::Engine;
use threat_harvester::export::{self, Format};
use threat_harvester::model::entity::{EntityKind, ThreatEntity};
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
    },
    /// List the active sources and what each can answer.
    Sources,
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

    let request = match &cli.command {
        Command::Enrich { value } => Request::Enrich(RawIoc::new(value.clone())),
        Command::Collect { target, kind } => Request::Collect {
            entity: ThreatEntity::new(target.clone(), parse_kind(kind)),
            filters: Filters::default(),
        },
        Command::Sources => {
            print_sources(&sources::from_config(&config));
            return Ok(());
        }
    };

    let format: Format = cli.output.parse()?;

    let engine = Engine::new(sources::from_config(&config), config);
    let indicators = engine.run(request).await?;

    println!("{}", export::render(&indicators, format)?);
    Ok(())
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
