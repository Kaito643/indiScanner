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
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenv::dotenv().ok();
    env_logger::init();

    let cli = Cli::parse();

    let request = match &cli.command {
        Command::Enrich { value } => Request::Enrich(RawIoc::new(value.clone())),
        Command::Collect { target, kind } => Request::Collect {
            entity: ThreatEntity::new(target.clone(), parse_kind(kind)),
            filters: Filters::default(),
        },
    };

    let config = match &cli.config {
        Some(path) => Config::from_path(path).unwrap_or_default(),
        None => Config::load(),
    };
    let format: Format = cli.output.parse()?;

    let engine = Engine::new(sources::from_config(&config), config);
    let indicators = engine.run(request).await?;

    println!("{}", export::render(&indicators, format)?);
    Ok(())
}

fn parse_kind(kind: &str) -> EntityKind {
    match kind.to_lowercase().as_str() {
        "actor" => EntityKind::Actor,
        "campaign" => EntityKind::Campaign,
        _ => EntityKind::MalwareFamily,
    }
}
