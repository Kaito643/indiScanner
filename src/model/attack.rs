//! MITRE ATT&CK references — the first live IOA layer.
//!
//! Sources already return behavioural tags (`bruteforce`, `powershell`,
//! `portscan`, sandbox-evasion markers, ...). [`from_tags`] maps them onto
//! ATT&CK techniques with a curated keyword table, so indicators carry TTPs
//! today; sandbox sources (Phase 11 proper) will later attach techniques
//! directly.

use serde::{Deserialize, Serialize};

/// A reference to a MITRE ATT&CK technique.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttackPattern {
    /// e.g. "T1059.001" (PowerShell).
    pub technique_id: String,
    /// Human-readable technique name, if known.
    pub name: Option<String>,
}

impl AttackPattern {
    fn new(technique_id: &str, name: &str) -> Self {
        Self {
            technique_id: technique_id.to_string(),
            name: Some(name.to_string()),
        }
    }
}

/// Tag-token → technique. Tokens are matched exactly after lowercasing and
/// splitting tags on non-alphanumeric characters, so `"SSH Bruteforce Hosts"`
/// and `"bruteforce"` both hit, while `"ec2"` can never hit `"c2"`.
const TOKEN_TECHNIQUES: &[(&str, &str, &str)] = &[
    ("bruteforce", "T1110", "Brute Force"),
    ("bruteforcer", "T1110", "Brute Force"),
    (
        "powershell",
        "T1059.001",
        "Command and Scripting Interpreter: PowerShell",
    ),
    (
        "vba",
        "T1059.005",
        "Command and Scripting Interpreter: Visual Basic",
    ),
    (
        "macro",
        "T1059.005",
        "Command and Scripting Interpreter: Visual Basic",
    ),
    ("portscan", "T1595", "Active Scanning"),
    ("scanner", "T1595", "Active Scanning"),
    ("scanners", "T1595", "Active Scanning"),
    ("scanning", "T1595", "Active Scanning"),
    ("webscan", "T1595", "Active Scanning"),
    ("webscanner", "T1595", "Active Scanning"),
    ("probing", "T1595", "Active Scanning"),
    ("phishing", "T1566", "Phishing"),
    ("phish", "T1566", "Phishing"),
    ("c2", "T1071", "Application Layer Protocol (C2)"),
    ("cobalt", "T1071", "Application Layer Protocol (C2)"),
    ("botnet", "T1584.005", "Compromise Infrastructure: Botnet"),
    ("ransomware", "T1486", "Data Encrypted for Impact"),
    ("cryptomining", "T1496", "Resource Hijacking"),
    ("coinminer", "T1496", "Resource Hijacking"),
    ("miner", "T1496", "Resource Hijacking"),
    ("xmrig", "T1496", "Resource Hijacking"),
    ("keylogger", "T1056.001", "Input Capture: Keylogging"),
    (
        "rdp",
        "T1021.001",
        "Remote Services: Remote Desktop Protocol",
    ),
    ("tor", "T1090.003", "Proxy: Multi-hop Proxy"),
    ("dropper", "T1105", "Ingress Tool Transfer"),
    ("loader", "T1105", "Ingress Tool Transfer"),
    ("stealer", "T1555", "Credentials from Password Stores"),
    ("infostealer", "T1555", "Credentials from Password Stores"),
    ("exploit", "T1190", "Exploit Public-Facing Application"),
    ("sqli", "T1190", "Exploit Public-Facing Application"),
    ("debug", "T1622", "Debugger Evasion"),
];

/// Derive ATT&CK techniques from observation tags. Deduplicated by technique
/// id, in first-hit order. A miss is silent — this is enrichment, not a claim
/// of completeness.
pub fn from_tags<S: AsRef<str>>(tags: &[S]) -> Vec<AttackPattern> {
    let mut out: Vec<AttackPattern> = Vec::new();
    for tag in tags {
        let lower = tag.as_ref().to_lowercase();
        for token in lower.split(|c: char| !c.is_ascii_alphanumeric()) {
            for (kw, id, name) in TOKEN_TECHNIQUES {
                if token == *kw && !out.iter().any(|p| p.technique_id == *id) {
                    out.push(AttackPattern::new(id, name));
                }
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_tokens_inside_longer_tags() {
        let got = from_tags(&["Vultr SSH Bruteforce Hosts for 2026-07-08", "powershell"]);
        let ids: Vec<&str> = got.iter().map(|p| p.technique_id.as_str()).collect();
        assert_eq!(ids, vec!["T1110", "T1059.001"]);
    }

    #[test]
    fn dedups_by_technique() {
        let got = from_tags(&["scanner", "portscan", "webscan"]);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].technique_id, "T1595");
    }

    #[test]
    fn token_match_avoids_substring_false_positives() {
        // "ec2" must not trigger the "c2" mapping.
        assert!(from_tags(&["aws-ec2-instance"]).is_empty());
        assert_eq!(from_tags(&["emotet-c2"])[0].technique_id, "T1071");
    }

    #[test]
    fn unknown_tags_map_to_nothing() {
        assert!(from_tags(&["windows", "malware", "2026-02"]).is_empty());
    }
}
