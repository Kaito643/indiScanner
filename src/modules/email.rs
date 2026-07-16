//! The `email` IOC-type module: email addresses.
//!
//! Detection is one `@` splitting a conservative local part from a hostname
//! that passes the network module's domain check. Common defangings
//! (`user[at]evil[.]com`, `mailto:` prefixes) are undone first.

use super::{network, Detection, IocModule};
use crate::model::indicator::IndicatorType;

pub struct EmailModule;

impl EmailModule {
    /// Undo common defanging so `user[at]evil[.]com` parses.
    fn refang(raw: &str) -> String {
        raw.trim()
            .trim_start_matches("mailto:")
            .replace("[at]", "@")
            .replace("(at)", "@")
            .replace("[@]", "@")
            .replace("[.]", ".")
            .replace("(.)", ".")
            .replace("{.}", ".")
    }
}

impl IocModule for EmailModule {
    fn name(&self) -> &str {
        "email"
    }

    fn handles(&self) -> Vec<IndicatorType> {
        vec![IndicatorType::Email]
    }

    fn detect(&self, raw: &str) -> Option<Detection> {
        let v = Self::refang(raw);
        let (local, domain) = v.split_once('@')?;
        if domain.contains('@') || !is_local_part(local) || !network::is_domain(domain) {
            return None;
        }
        Some(Detection {
            indicator_type: IndicatorType::Email,
            canonical: v.to_lowercase(),
        })
    }
}

/// A conservative local-part check: the character set that covers real-world
/// addresses without accepting arbitrary junk (no quoted-string forms).
fn is_local_part(local: &str) -> bool {
    !local.is_empty()
        && local.len() <= 64
        && !local.starts_with('.')
        && !local.ends_with('.')
        && local
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "._%+-".contains(c))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn detect(raw: &str) -> Option<(IndicatorType, String)> {
        EmailModule
            .detect(raw)
            .map(|d| (d.indicator_type, d.canonical))
    }

    #[test]
    fn detects_email_and_lowercases() {
        assert_eq!(
            detect("Payload.Delivery+spam@Evil.COM"),
            Some((
                IndicatorType::Email,
                "payload.delivery+spam@evil.com".to_string()
            ))
        );
    }

    #[test]
    fn refangs_at_and_dots_and_mailto() {
        assert_eq!(
            detect("user[at]evil[.]com"),
            Some((IndicatorType::Email, "user@evil.com".to_string()))
        );
        assert_eq!(
            detect("mailto:user@evil.com").map(|(_, c)| c),
            Some("user@evil.com".to_string())
        );
    }

    #[test]
    fn rejects_invalid_shapes() {
        assert_eq!(detect("no-at-sign.com"), None);
        assert_eq!(detect("two@@evil.com"), None);
        assert_eq!(detect("a@b@evil.com"), None);
        assert_eq!(detect("@evil.com"), None);
        assert_eq!(detect("user@no-tld"), None);
        assert_eq!(detect(".dot-first@evil.com"), None);
        assert_eq!(detect(""), None);
    }
}
