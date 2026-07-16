//! Aggregation: fold raw [`Observation`]s into deduplicated, scored [`Indicator`]s.

use super::score;
use crate::model::attack;
use crate::model::indicator::{Indicator, IndicatorType, Observation};
use crate::model::relationship::Relationship;
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
        let mut relationships: Vec<Relationship> = Vec::new();
        let mut attack_patterns: Vec<crate::model::attack::AttackPattern> = Vec::new();
        for o in &obs {
            for t in &o.tags {
                if !tags.contains(t) {
                    tags.push(t.clone());
                }
            }
            for r in &o.relationships {
                if !relationships.contains(r) {
                    relationships.push(r.clone());
                }
            }
            // Source-asserted techniques (sandbox verdicts) come first.
            for p in &o.attack_patterns {
                if !attack_patterns
                    .iter()
                    .any(|q| q.technique_id == p.technique_id)
                {
                    attack_patterns.push(p.clone());
                }
            }
        }
        // Tag-derived techniques fill in whatever no source asserted directly.
        for p in attack::from_tags(&tags) {
            if !attack_patterns
                .iter()
                .any(|q| q.technique_id == p.technique_id)
            {
                attack_patterns.push(p);
            }
        }

        indicators.push(Indicator {
            value: key.0,
            indicator_type: key.1,
            confidence,
            tags,
            attack_patterns,
            relationships,
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
        // The IOA layer derives techniques from the unioned tags.
        let ids: Vec<&str> = ip
            .attack_patterns
            .iter()
            .map(|p| p.technique_id.as_str())
            .collect();
        assert_eq!(ids, vec!["T1071", "T1584.005"]);
    }

    #[test]
    fn unions_relationship_edges_without_duplicates() {
        use crate::model::relationship::{RelationKind, Relationship};
        let edge = Relationship::new("h.com", "http://h.com/mal", RelationKind::Hosts);
        let mut a = obs("h.com", IndicatorType::Domain, "A", 60, &[]);
        a.relationships.push(edge.clone());
        let mut b = obs("h.com", IndicatorType::Domain, "B", 60, &[]);
        b.relationships.push(edge.clone());

        let out = aggregate(vec![a, b], &HashMap::new());
        assert_eq!(out[0].relationships, vec![edge]);
    }
}
