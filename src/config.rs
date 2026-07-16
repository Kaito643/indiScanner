//! Configuration: an optional TOML file layered over sensible defaults.
//!
//! Everything here is data, not code: source enable/disable toggles, the alias
//! map (restored from v1), rate limits, and cache settings. If no file is found,
//! the defaults below are used, so the tool works with zero configuration.

use serde::Deserialize;
use std::collections::HashMap;
use std::path::Path;

/// Top-level configuration.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct Config {
    pub sources: SourceToggles,
    pub cache: CacheConfig,
    pub ratelimit: RateLimitConfig,
    /// Per-source reliability weights in `0.0..=1.0` (lowercase source name →
    /// weight). A source's weight scales both its own confidence claim and how
    /// much its agreement boosts consensus. Unlisted sources weigh 1.0.
    #[serde(default)]
    pub weights: HashMap<String, f64>,
    /// Entity name → search terms (aliases). The name itself is always included.
    #[serde(default = "default_aliases")]
    pub aliases: HashMap<String, Vec<String>>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            sources: SourceToggles::default(),
            cache: CacheConfig::default(),
            ratelimit: RateLimitConfig::default(),
            weights: HashMap::new(),
            aliases: default_aliases(),
        }
    }
}

/// Which sources are enabled (key-gated ones still require their credential).
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct SourceToggles {
    pub threatfox: bool,
    pub urlhaus: bool,
    pub malwarebazaar: bool,
    pub otx: bool,
    pub abuseipdb: bool,
    pub virustotal: bool,
    pub greynoise: bool,
    pub shodan: bool,
    pub ransomwhere: bool,
}

impl Default for SourceToggles {
    fn default() -> Self {
        Self {
            threatfox: true,
            urlhaus: true,
            malwarebazaar: true,
            otx: true,
            abuseipdb: true,
            virustotal: true,
            greynoise: true,
            shodan: true,
            ransomwhere: true,
        }
    }
}

/// Cross-run disk cache settings.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct CacheConfig {
    pub enabled: bool,
    pub ttl_seconds: u64,
    pub dir: String,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            ttl_seconds: 3600,
            dir: ".th-cache".to_string(),
        }
    }
}

/// Per-source rate limiting.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct RateLimitConfig {
    /// Minimum milliseconds between consecutive requests to the same source.
    pub default_ms: u64,
    /// Per-source overrides (lowercase source name → ms). Seeded with
    /// VirusTotal's free-tier pace (4 requests/minute).
    pub per_source: HashMap<String, u64>,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            default_ms: 1000,
            per_source: HashMap::from([("virustotal".to_string(), 15_000)]),
        }
    }
}

/// Seed aliases (carried over from the v1 resolver).
fn default_aliases() -> HashMap<String, Vec<String>> {
    HashMap::from([
        (
            "Lazarus".to_string(),
            vec![
                "Hidden Cobra".to_string(),
                "Zinc".to_string(),
                "Lazarus".to_string(),
            ],
        ),
        (
            "BlackNevas".to_string(),
            vec!["Trigona".to_string(), "BlackNevas".to_string()],
        ),
    ])
}

impl Config {
    /// Load from `TH_CONFIG` (if set) or `./threatharvester.toml`, else defaults.
    pub fn load() -> Self {
        let path =
            std::env::var("TH_CONFIG").unwrap_or_else(|_| "threatharvester.toml".to_string());
        Self::from_path(&path).unwrap_or_default()
    }

    /// Load from an explicit path. Returns `None` if missing or invalid.
    pub fn from_path(path: impl AsRef<Path>) -> Option<Self> {
        let text = std::fs::read_to_string(path).ok()?;
        match toml::from_str(&text) {
            Ok(config) => Some(config),
            Err(e) => {
                log::warn!("Invalid config, falling back to defaults: {e}");
                None
            }
        }
    }

    /// Expand an entity name into all search terms, always including the name.
    pub fn resolve_aliases(&self, name: &str) -> Vec<String> {
        let mut terms = self.aliases.get(name).cloned().unwrap_or_default();
        if !terms.iter().any(|t| t == name) {
            terms.push(name.to_string());
        }
        terms
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_enable_all_sources_and_seed_aliases() {
        let c = Config::default();
        assert!(c.sources.threatfox && c.sources.abuseipdb && c.sources.malwarebazaar);
        assert!(c.sources.greynoise && c.sources.shodan);
        assert!(c.aliases.contains_key("Lazarus"));
    }

    #[test]
    fn resolve_aliases_includes_the_name_itself() {
        let c = Config::default();
        assert_eq!(c.resolve_aliases("Unknown"), vec!["Unknown".to_string()]);
        assert!(c.resolve_aliases("Lazarus").contains(&"Zinc".to_string()));
    }

    #[test]
    fn partial_toml_keeps_other_defaults() {
        let c: Config = toml::from_str("[sources]\nurlhaus = false\n").unwrap();
        assert!(!c.sources.urlhaus);
        assert!(c.sources.threatfox); // untouched default
        assert!(c.cache.enabled); // whole [cache] section defaulted
        assert_eq!(c.ratelimit.per_source.get("virustotal"), Some(&15_000)); // seeded
    }

    #[test]
    fn weights_parse_from_toml_and_default_empty() {
        let c: Config = toml::from_str("[weights]\ngreynoise = 0.6\n").unwrap();
        assert_eq!(c.weights.get("greynoise"), Some(&0.6));
        assert!(Config::default().weights.is_empty());
    }

    #[test]
    fn per_source_ratelimit_parses_from_toml() {
        let c: Config = toml::from_str(
            "[ratelimit]\ndefault_ms = 500\n[ratelimit.per_source]\nshodan = 2000\n",
        )
        .unwrap();
        assert_eq!(c.ratelimit.default_ms, 500);
        assert_eq!(c.ratelimit.per_source.get("shodan"), Some(&2000));
    }
}
