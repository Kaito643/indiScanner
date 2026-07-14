# ThreatHarvester

A high-performance Cyber Threat Intelligence (CTI) aggregator written in Rust. It queries a
wide range of OSINT / threat-intel sources, normalizes and deduplicates Indicators of
Compromise (IOCs), scores them by cross-source consensus, and exports actionable data.

> **v2 rewrite in progress.** The project is being redesigned around a capability-routed,
> IOC-type-module architecture. The first-generation Rust engine is archived under
> [`legacy/rust-v1/`](legacy/rust-v1/); the original Python tool lives under [`legacy/`](legacy/).

## Design

Three layers, so the tool scales to many sources without querying sources that can't answer:

1. **IOC-type modules** (`src/modules/`) — one per category (`network`: IP/domain/URL,
   `file`: hashes/samples, `email`, ...). Each owns validation, normalization, defanging,
   and knows which sources are relevant for its type. This is the routing brain.
2. **Source connectors** (`src/sources/`) — each declares a **capability** (which IOC types
   and operations it supports). The engine only calls sources that match the request.
3. **Orchestration engine** (`src/engine/`) — routes a request to the right module, fans out
   to capable sources concurrently, and aggregates results.

Two verbs share one engine:

- **Enrich** — look up a single IOC (type auto-detected) and gather reputation/context.
- **Collect** — harvest IOCs related to a threat entity (actor / malware family / campaign).

The domain model splits an **`Observation`** (one source's raw claim, with provenance) from
an **`Indicator`** (the merged, deduplicated, **consensus-scored** result), which enables real
confidence scoring and clean STIX 2.1 / MISP export.

## Sources

| Source | Type | Operations | Status |
| --- | --- | --- | --- |
| ThreatFox (abuse.ch) | IOCs | lookup + search | ✅ |
| URLhaus (abuse.ch) | Malicious URLs | lookup + search | ✅ |
| AlienVault OTX | Open Threat Exchange | lookup | ✅ |
| AbuseIPDB | IP reputation | lookup | ✅ |
| VirusTotal, MISP, Pulsedive, MalwareBazaar | mixed | — | planned |

## Roadmap

- [x] **Phase 0** — Archive v1, scaffold the new `lib + bin` crate.
- [x] **Phase 1** — Core model + `ThreatSource`/`Capability` and `IocModule` traits + `network` module.
- [x] **Phase 2** — Router, aggregator, consensus scoring; port ThreatFox/URLhaus/OTX.
- [x] **Phase 3** — Enrichment path end-to-end + AbuseIPDB.
- [x] **Phase 4** — Per-source caching + rate limiting + config file.
- [x] **Phase 5** — STIX 2.1 / MISP export.
- [ ] **Future** — Indicators of Attack (IOA): relationship graph + MITRE ATT&CK mapping.

## Build & Run

Requires the [Rust toolchain](https://rustup.rs/) (`cargo`).

```bash
cargo build --release

# Enrich a single IOC (type auto-detected; supports defanged input)
cargo run -- enrich 1.2.3.4
cargo run -- enrich "1[.]2[.]3[.]4"

# Collect IOCs for a threat entity (aliases are expanded automatically)
cargo run -- collect LockBit --kind actor

# Output formats: json (default) | csv | stix | misp
cargo run -- enrich 1.2.3.4 --output stix
```

Copy `.env.example` to `.env` and add API keys:

- `ABUSE_CH_AUTH_KEY` — required for ThreatFox + URLhaus (free from <https://auth.abuse.ch/>)
- `OTX_API_KEY` — enables AlienVault OTX
- `ABUSEIPDB_API_KEY` — enables AbuseIPDB IP reputation

## Configuration

Optional `threatharvester.toml` (or `$TH_CONFIG`, or `--config <path>`) tunes source
toggles, aliases, caching, and rate limits — see [`threatharvester.toml.example`](threatharvester.toml.example).
With no config file, sensible defaults apply. Responses are cached under `.th-cache/`.

## Disclaimer

For **educational and research purposes only**. Any downloaded artifacts may be live malware
and must be handled only within a secure, isolated analysis environment. The authors assume no
liability for misuse.

## License

MIT — see [LICENSE](LICENSE).
