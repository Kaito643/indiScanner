use async_trait::async_trait;
use crate::models::{Indicator, IndicatorType};
use anyhow::Result;

#[async_trait]
pub trait ThreatSource: Send + Sync {
    /// Returns the name of the source (e.g., "AlienVault")
    fn name(&self) -> &str;

    /// Fetches indicators based on the query string
    async fn fetch(&self, query: &str) -> Result<Vec<Indicator>>;
}

// --- Mock Implementations ---

pub struct MockAlienVault;

#[async_trait]
impl ThreatSource for MockAlienVault {
    fn name(&self) -> &str {
        "AlienVault OTX (Mock)"
    }

    async fn fetch(&self, query: &str) -> Result<Vec<Indicator>> {
        // Simulate IO delay
        tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
        
        Ok(vec![
            Indicator {
                value: "192.168.1.100".to_string(),
                indicator_type: IndicatorType::IPv4,
                source: self.name().to_string(),
                first_seen: Some("2023-10-01".to_string()),
                confidence_level: 80,
                tags: vec![query.to_string(), "C2".to_string()],
            }
        ])
    }
}

pub struct MockThreatFox;

#[async_trait]
impl ThreatSource for MockThreatFox {
    fn name(&self) -> &str {
        "ThreatFox (Mock)"
    }

    async fn fetch(&self, query: &str) -> Result<Vec<Indicator>> {
        // Simulate IO delay
        tokio::time::sleep(tokio::time::Duration::from_millis(300)).await;
        
        Ok(vec![
            Indicator {
                value: "malicious-domain.com".to_string(),
                indicator_type: IndicatorType::Domain,
                source: self.name().to_string(),
                first_seen: Some("2023-10-05".to_string()),
                confidence_level: 90,
                tags: vec![query.to_string(), "Botnet".to_string()],
            }
        ])
    }
}
