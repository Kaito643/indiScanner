//! The `file` IOC-type module: hash digests (MD5/SHA-1/SHA-256/SHA-512) and
//! ssdeep fuzzy hashes. Detection is by length + charset; a 32-hex value is
//! reported as MD5 (imphash is format-identical and lands here too).

use super::{Detection, IocModule};
use crate::model::indicator::IndicatorType;

pub struct FileModule;

impl IocModule for FileModule {
    fn name(&self) -> &str {
        "file"
    }

    fn handles(&self) -> Vec<IndicatorType> {
        vec![
            IndicatorType::Md5,
            IndicatorType::Sha1,
            IndicatorType::Sha256,
            IndicatorType::Sha512,
            IndicatorType::Ssdeep,
        ]
    }

    fn detect(&self, raw: &str) -> Option<Detection> {
        let v = raw.trim();
        if !v.is_empty() && v.chars().all(|c| c.is_ascii_hexdigit()) {
            let ty = match v.len() {
                32 => IndicatorType::Md5,
                40 => IndicatorType::Sha1,
                64 => IndicatorType::Sha256,
                128 => IndicatorType::Sha512,
                _ => return None,
            };
            return Some(Detection {
                indicator_type: ty,
                canonical: v.to_lowercase(),
            });
        }
        if is_ssdeep(v) {
            return Some(Detection {
                indicator_type: IndicatorType::Ssdeep,
                canonical: v.to_string(),
            });
        }
        None
    }
}

/// ssdeep format: `blocksize:chunk:double_chunk` — a decimal block size and two
/// non-empty base64 chunks.
fn is_ssdeep(v: &str) -> bool {
    let mut parts = v.splitn(3, ':');
    let (Some(bs), Some(c1), Some(c2)) = (parts.next(), parts.next(), parts.next()) else {
        return false;
    };
    !bs.is_empty()
        && bs.chars().all(|c| c.is_ascii_digit())
        && !c1.is_empty()
        && !c2.is_empty()
        && [c1, c2].iter().all(|chunk| {
            chunk
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '/' || c == '+')
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn detect(raw: &str) -> Option<(IndicatorType, String)> {
        FileModule
            .detect(raw)
            .map(|d| (d.indicator_type, d.canonical))
    }

    #[test]
    fn detects_hashes_by_length_and_lowercases() {
        assert_eq!(
            detect("803385CF25070740F5B09E685D2F531C"),
            Some((
                IndicatorType::Md5,
                "803385cf25070740f5b09e685d2f531c".to_string()
            ))
        );
        assert_eq!(
            detect("5143c2befd448fdbb0bb5a7304659fc1d3bddcb7").map(|(t, _)| t),
            Some(IndicatorType::Sha1)
        );
        assert_eq!(
            detect("251037ceebfbacd419b663ebcf0e01ec80a2c46dbfc85f66492c8585b481fb8c")
                .map(|(t, _)| t),
            Some(IndicatorType::Sha256)
        );
        assert_eq!(
            detect(&"a".repeat(128)).map(|(t, _)| t),
            Some(IndicatorType::Sha512)
        );
    }

    #[test]
    fn detects_ssdeep() {
        assert_eq!(
            detect("196608:k4SCTjKEzG5wRrkPTCpbEi8rjAPlNICsPLRbEdUxoNChqu+S:kOjyo8Tx9YtaNbEXNChn")
                .map(|(t, _)| t),
            Some(IndicatorType::Ssdeep)
        );
    }

    #[test]
    fn rejects_wrong_lengths_and_junk() {
        assert_eq!(detect(&"a".repeat(63)), None); // not a valid digest length
        assert_eq!(detect("not-a-hash"), None);
        assert_eq!(detect("12345:"), None); // ssdeep needs two non-empty chunks
        assert_eq!(detect(""), None);
    }
}
