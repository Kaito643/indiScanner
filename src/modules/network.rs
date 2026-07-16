//! The `network` IOC-type module: IPv4, IPv6, domain, and URL.

use super::{Detection, IocModule};
use crate::model::indicator::IndicatorType;
use std::net::{Ipv4Addr, Ipv6Addr};

pub struct NetworkModule;

impl NetworkModule {
    /// Undo common defanging so `1[.]2[.]3[.]4` and `hxxp://e[.]com` parse.
    fn refang(raw: &str) -> String {
        raw.trim()
            .replace("[.]", ".")
            .replace("(.)", ".")
            .replace("{.}", ".")
            .replace("[:]", ":")
            .replace("hxxps", "https")
            .replace("hxxp", "http")
    }
}

impl IocModule for NetworkModule {
    fn name(&self) -> &str {
        "network"
    }

    fn handles(&self) -> Vec<IndicatorType> {
        vec![
            IndicatorType::IPv4,
            IndicatorType::IPv6,
            IndicatorType::Domain,
            IndicatorType::Url,
        ]
    }

    fn detect(&self, raw: &str) -> Option<Detection> {
        let v = Self::refang(raw);
        if v.is_empty() {
            return None;
        }

        // URL — scheme is the cheapest, most unambiguous signal.
        if v.starts_with("http://") || v.starts_with("https://") {
            return Some(Detection {
                indicator_type: IndicatorType::Url,
                canonical: v,
            });
        }

        // IPv4 / IPv6 — exact parse, no allocation of a canonical variant needed.
        if v.parse::<Ipv4Addr>().is_ok() {
            return Some(Detection {
                indicator_type: IndicatorType::IPv4,
                canonical: v,
            });
        }
        if v.parse::<Ipv6Addr>().is_ok() {
            return Some(Detection {
                indicator_type: IndicatorType::IPv6,
                canonical: v,
            });
        }

        // Domain — lowercase canonical form.
        if is_domain(&v) {
            return Some(Detection {
                indicator_type: IndicatorType::Domain,
                canonical: v.to_lowercase(),
            });
        }

        None
    }
}

/// A conservative hostname check: dotted, ASCII labels, valid label chars.
/// Shared with the email module for validating the domain part of an address.
pub(super) fn is_domain(v: &str) -> bool {
    if v.contains(char::is_whitespace) || !v.contains('.') {
        return false;
    }
    // Must have a non-numeric TLD to avoid matching things like "1.2.3.4.5".
    let last = v.rsplit('.').next().unwrap_or("");
    if last.is_empty() || last.chars().all(|c| c.is_ascii_digit()) {
        return false;
    }
    v.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
            && !label.starts_with('-')
            && !label.ends_with('-')
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn detect(raw: &str) -> Option<(IndicatorType, String)> {
        NetworkModule
            .detect(raw)
            .map(|d| (d.indicator_type, d.canonical))
    }

    #[test]
    fn detects_ipv4_and_refangs() {
        assert_eq!(
            detect("1[.]2[.]3[.]4"),
            Some((IndicatorType::IPv4, "1.2.3.4".to_string()))
        );
    }

    #[test]
    fn detects_ipv6() {
        assert_eq!(
            detect("2001:db8::1").map(|(t, _)| t),
            Some(IndicatorType::IPv6)
        );
    }

    #[test]
    fn detects_url_and_refangs_scheme() {
        assert_eq!(
            detect("hxxps://evil[.]com/a"),
            Some((IndicatorType::Url, "https://evil.com/a".to_string()))
        );
    }

    #[test]
    fn detects_domain_lowercased() {
        assert_eq!(
            detect("Evil.COM"),
            Some((IndicatorType::Domain, "evil.com".to_string()))
        );
    }

    #[test]
    fn rejects_bare_numbers_and_junk() {
        assert_eq!(detect("1.2.3.4.5"), None);
        assert_eq!(detect("not a domain"), None);
        assert_eq!(detect(""), None);
    }
}
