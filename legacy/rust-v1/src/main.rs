pub mod models;
pub mod sources;
pub mod engine;

use clap::Parser;
use log::{info, error};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Name of the Threat Actor or Malware Family
    #[arg(short, long)]
    target: String,

    /// Type of target (ACTOR | MALWARE)
    #[arg(short = 'T', long, default_value = "MALWARE")]
    type_: String,

    /// Number of days to look back
    #[arg(short, long, default_value_t = 30)]
    days: u32,

    /// Output format (json | csv)
    #[arg(short, long, default_value = "json")]
    output: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();
    
    let args = Args::parse();
    info!("Starting ThreatHarvester for target: {}", args.target);

    // Provide default sources
    // In a real app, we might load these from config or CLI args
    let sources: Vec<Box<dyn crate::sources::ThreatSource>> = vec![
        Box::new(crate::sources::MockAlienVault),
        Box::new(crate::sources::MockThreatFox),
    ];

    let engine = crate::engine::Engine::new(sources);

    let config = crate::models::QueryConfig {
        target_name: args.target.clone(),
        target_type: match args.type_.to_uppercase().as_str() {
            "ACTOR" => crate::models::ThreatEntity::Actor,
            "CAMPAIGN" => crate::models::ThreatEntity::Campaign,
            _ => crate::models::ThreatEntity::MalwareFamily,
        },
        lookback_days: args.days,
    };

    match engine.run(config).await {
        Ok(indicators) => {
            if args.output.to_lowercase() == "json" {
                println!("{}", serde_json::to_string_pretty(&indicators)?);
            } else {
                // CSV or other format
                println!("value,type,source,confidence");
                for ind in indicators {
                    println!("{},{:?},{},{}", ind.value, ind.indicator_type, ind.source, ind.confidence_level);
                }
            }
        }
        Err(e) => {
            error!("Application error: {}", e);
        }
    }
    
    Ok(())
}
