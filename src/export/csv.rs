//! CSV export — one row per indicator, RFC 4180 quoting.

use crate::model::indicator::Indicator;

pub fn render(indicators: &[Indicator]) -> String {
    let mut out = String::from("value,type,confidence,sources,tags,attack\n");
    for ind in indicators {
        let attack: Vec<&str> = ind
            .attack_patterns
            .iter()
            .map(|p| p.technique_id.as_str())
            .collect();
        let row = [
            ind.value.clone(),
            ind.indicator_type.as_tag().to_string(),
            ind.confidence.to_string(),
            ind.sources().join("|"),
            ind.tags.join("|"),
            attack.join("|"),
        ];
        let line: Vec<String> = row.iter().map(|f| escape(f)).collect();
        out.push_str(&line.join(","));
        out.push('\n');
    }
    out
}

/// Quote a field if it contains a comma, quote, or newline (RFC 4180).
fn escape(field: &str) -> String {
    if field.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", field.replace('"', "\"\""))
    } else {
        field.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quotes_fields_with_commas_and_escapes_quotes() {
        assert_eq!(escape("plain"), "plain");
        assert_eq!(escape("a,b"), "\"a,b\"");
        assert_eq!(escape("he said \"hi\""), "\"he said \"\"hi\"\"\"");
    }
}
