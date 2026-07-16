//! Aggregation: fold raw [`Observation`]s into deduplicated, scored [`Indicator`]s.

use super::score;
use crate::model::indicator::{Indicator, IndicatorType, Observation};
use std::collections::HashMap;

/// Group observations by `(value, type)`, then build one [`Indicator`] per group
/// with a consensus score, a unioned tag set, and all contributing observations
/// retained for provenance. Output order follows first appearance of each group.
pub fn aggregate(observations: Vec<Observation>, weights: &HashMap<String, f64>) -> Vec<Indicator> {
    let mut order: Vec<(String, IndicatorType)> = Vec::new();
    let mut groups: HashMap<(String, IndicatorType), Vec<Observation>> = HashMap::new();

    for obs in observations {
        let key = obs.dedup_key();
        if !groups.contains_key(&key) {
            order.push(key.clone());
        }
        groups.entry(key).or_default().push(obs);
    }

    let mut indicators = Vec::with_capacity(order.len());
    for key in order {
        let obs = groups.remove(&key).expect("key came from the same map");
        let confidence = score::consensus(&obs, weights);

        let mut tags: Vec<String> = Vec::new();
        for o in &obs {
            for t in &o.tags {
                if !tags.contains(t) {
                    tags.push(t.clone());
                }
            }
        }

        indicators.push(Indicator {
            value: key.0,
            indicator_type: key.1,
            confidence,
            tags,
            observations: obs,
        });
    }
    indicators
}

#[cfg(test)]
mod tests {
    use super::*;

    fn obs(value: &str, ty: IndicatorType, source: &str, conf: u8, tags: &[&str]) -> Observation {
        let mut o = Observation::new(value, ty, source, conf);
        o.tags = tags.iter().map(|s| s.to_string()).collect();
        o
    }

    #[test]
    fn merges_same_value_and_unions_tags() {
        let input = vec![
            obs("1.2.3.4", IndicatorType::IPv4, "A", 60, &["c2"]),
            obs("1.2.3.4", IndicatorType::IPv4, "B", 60, &["botnet"]),
            obs("evil.com", IndicatorType::Domain, "A", 50, &["phish"]),
        ];
        let out = aggregate(input, &HashMap::new());
        assert_eq!(out.len(), 2);

        let ip = &out[0];
        assert_eq!(ip.value, "1.2.3.4");
        assert_eq!(ip.observations.len(), 2);
        assert_eq!(ip.sources(), vec!["A", "B"]);
        assert_eq!(ip.confidence, 80); // two agreeing sources at 60
        assert_eq!(ip.tags, vec!["c2", "botnet"]);
    }
}
