//! Consensus confidence scoring.

use crate::model::indicator::Observation;

/// Combine per-source confidences into a single consensus score in `0..=100`.
///
/// The score starts from the highest single-source confidence, then each
/// *additional* agreeing source closes half of the remaining gap to 100. So
/// agreement raises confidence with diminishing returns, and a lone low-confidence
/// claim stays low:
///
/// | sources | result (max = 60) |
/// |---------|-------------------|
/// | 1       | 60                |
/// | 2       | 80                |
/// | 3       | 90                |
/// | 4       | 95                |
///
/// A per-source *reliability weight* can be folded in here later without changing
/// callers.
pub fn consensus(observations: &[Observation]) -> u8 {
    if observations.is_empty() {
        return 0;
    }
    let max = observations.iter().map(|o| o.confidence).max().unwrap_or(0) as f64;
    let extra = observations.len().saturating_sub(1) as i32;
    let closed = 1.0 - 0.5_f64.powi(extra); // 0 for 1 source, 0.5 for 2, 0.75 for 3 ...
    let score = max + (100.0 - max) * closed;
    score.round().clamp(0.0, 100.0) as u8
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::indicator::IndicatorType;

    fn obs(conf: u8) -> Observation {
        Observation::new("v", IndicatorType::IPv4, "s", conf)
    }

    #[test]
    fn empty_is_zero() {
        assert_eq!(consensus(&[]), 0);
    }

    #[test]
    fn single_source_is_its_own_confidence() {
        assert_eq!(consensus(&[obs(60)]), 60);
    }

    #[test]
    fn agreement_closes_half_the_gap_each_time() {
        assert_eq!(consensus(&[obs(60), obs(60)]), 80);
        assert_eq!(consensus(&[obs(60), obs(40), obs(50)]), 90);
    }
}
