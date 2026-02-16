use std::collections::{HashMap, HashSet};
use crate::models::{Indicator, QueryConfig};
use crate::sources::ThreatSource;
use anyhow::Result;
use log::info;
use futures::future::join_all;
use std::sync::Arc;

pub struct AliasResolver {
    // Simple map: "Master Name" -> ["Alias1", "Alias2"]
    // Or "Alias" -> "Master Name" depending on strategy. 
    // Here we map "Input" -> List of related terms to query.
    aliases: HashMap<String, Vec<String>>,
}

impl AliasResolver {
    pub fn new() -> Self {
        let mut aliases = HashMap::new();
        aliases.insert(
            "BlackNevas".to_string(),
            vec!["Trigona".to_string(), "BlackNevas".to_string()],
        );
        aliases.insert(
            "Lazarus".to_string(),
            vec!["Hidden Cobra".to_string(), "Zinc".to_string(), "Lazarus".to_string()],
        );
        Self { aliases }
    }

    pub fn resolve(&self, target: &str) -> Vec<String> {
        self.aliases.get(target).cloned().unwrap_or_else(|| vec![target.to_string()])
    }
}

pub struct Engine {
    sources: Vec<Box<dyn ThreatSource>>,
    resolver: AliasResolver,
}

impl Engine {
    pub fn new(sources: Vec<Box<dyn ThreatSource>>) -> Self {
        Self {
            sources,
            resolver: AliasResolver::new(),
        }
    }

    pub async fn run(&self, config: QueryConfig) -> Result<Vec<Indicator>> {
        // 1. Resolve Aliases
        let mut search_terms = self.resolver.resolve(&config.target_name);
        // Include the original target name if not already in the list
        if !search_terms.contains(&config.target_name) {
            search_terms.push(config.target_name.clone());
        }
        
        info!("Resolved '{}' to search terms: {:?}", config.target_name, search_terms);

        // 2. Query All Sources for All Terms
        let mut futures = Vec::new();

        for source in &self.sources {
            for term in &search_terms {
                // Cloning term for the async move block if necessary, 
                // but fetch takes &str so we must ensure `source` is safe to share.
                // The trait object is Box<dyn ThreatSource>, which is Send+Sync.
                // We use the `fetch` call directly.
                futures.push(source.fetch(term));
            }
        }

        let results = join_all(futures).await;

        // 3. Aggregate & Deduplicate
        let mut all_indicators = Vec::new();
        // Use a set of (Value, Type) strings to deduplicate more robustly
        let mut seen = HashSet::new();

        for res in results {
            match res {
                Ok(indicators) => {
                    for ind in indicators {
                        let key = format!("{}:{:?}", ind.value, ind.indicator_type);
                        if seen.insert(key) {
                            all_indicators.push(ind);
                        }
                    }
                }
                Err(e) => {
                    // Log error but continue
                    eprintln!("Error fetching from source: {}", e);
                }
            }
        }

        Ok(all_indicators)
    }
}
