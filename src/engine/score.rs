//! Consensus confidence scoring.

use crate::model::indicator::Observation;
use std::collections::HashMap;

/// Combine per-source confidences into a single consensus score in `0..=100`.
///
/// The score starts from the highest single-source claim, then each
/// *additional* agreeing source closes half of the remaining gap to 100. So
/// agreement raises confidence with diminishing returns, and a lone
/// low-confidence claim stays low:
///
/// | sources | result (max = 60) |
/// |---------|-------------------|
/// | 1       | 60                |
/// | 2       | 80                |
/// | 3       | 90                |
/// | 4       | 95                |
///
/// Per-source *reliability weights* (lowercase source name → `0.0..=1.0`,
/// unlisted = 1.0) scale both effects: a source's own claim counts as
/// `confidence × weight`, and its agreement closes `weight × half` of the
/// remaining gap. Gap-closing is multiplicative, so the result does not depend
/// on observation order.
pub fn consensus(observations: &[Observation], weights: &HashMap<String, f64>) -> u8 {
    if observations.is_empty() {
        return 0;
    }
    let weight_of = |o: &Observation| -> f64 {
        weights
            .get(&o.source.to_lowercase())
            .copied()
            .unwrap_or(1.0)
            .clamp(0.0, 1.0)
    };

    let effective: Vec<f64> = observations
        .iter()
        .map(|o| o.confidence as f64 * weight_of(o))
        .collect();
    let (anchor_idx, anchor) = effective
        .iter()
        .copied()
        .enumerate()
        .max_by(|a, b| a.1.total_cmp(&b.1))
        .expect("non-empty checked above");

    let remaining_gap: f64 = observations
        .iter()
        .enumerate()
        .filter(|(i, _)| *i != anchor_idx)
        .map(|(_, o)| 1.0 - 0.5 * weight_of(o))
        .product();
    let score = 100.0 - (100.0 - anchor) * remaining_gap;
    score.round().clamp(0.0, 100.0) as u8
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::indicator::IndicatorType;

    fn obs(source: &str, conf: u8) -> Observation {
        Observation::new("v", IndicatorType::IPv4, source, conf)
    }

    fn no_weights() -> HashMap<String, f64> {
        HashMap::new()
    }

    #[test]
    fn empty_is_zero() {
        assert_eq!(consensus(&[], &no_weights()), 0);
    }

    #[test]
    fn single_source_is_its_own_confidence() {
        assert_eq!(consensus(&[obs("s", 60)], &no_weights()), 60);
    }

    #[test]
    fn agreement_closes_half_the_gap_each_time() {
        assert_eq!(consensus(&[obs("a", 60), obs("b", 60)], &no_weights()), 80);
        assert_eq!(
            consensus(&[obs("a", 60), obs("b", 40), obs("c", 50)], &no_weights()),
            90
        );
    }

    #[test]
    fn weight_scales_a_sources_own_claim() {
        let w = HashMap::from([("shodan".to_string(), 0.5)]);
        // 80 × 0.5 = 40 effective, alone.
        assert_eq!(consensus(&[obs("Shodan", 80)], &w), 40);
    }

    #[test]
    fn weight_scales_agreement_boost() {
        let w = HashMap::from([("b".to_string(), 0.5)]);
        // Anchor 60; b closes 0.5×0.5 = a quarter of the gap: 60 + 40×0.25 = 70.
        assert_eq!(consensus(&[obs("a", 60), obs("b", 60)], &w), 70);
    }

    #[test]
    fn zero_weight_mutes_a_source_entirely() {
        let w = HashMap::from([("junk".to_string(), 0.0)]);
        assert_eq!(consensus(&[obs("a", 60), obs("Junk", 100)], &w), 60);
    }

    #[test]
    fn result_is_order_independent() {
        let w = HashMap::from([("b".to_string(), 0.3)]);
        let forward = consensus(&[obs("a", 70), obs("b", 50), obs("c", 20)], &w);
        let reversed = consensus(&[obs("c", 20), obs("b", 50), obs("a", 70)], &w);
        assert_eq!(forward, reversed);
    }
}
