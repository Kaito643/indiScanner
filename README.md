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
| MalwareBazaar (abuse.ch) | Malware samples | lookup + search + **download** | ✅ |
| AlienVault OTX | Open Threat Exchange | lookup | ✅ |
| AbuseIPDB | IP reputation | lookup | ✅ |
| VirusTotal | Multi-engine verdicts | lookup | ✅ |
| GreyNoise | Internet-scanner context | lookup | ✅ |
| Shodan | Exposure / CVE context | lookup | ✅ |
| Ransomwhere | Ransomware BTC addresses | lookup + search | ✅ |
| Triage (tria.ge) | Sandbox behaviour: TTPs + C2 endpoints | lookup + search | ✅ |
| MISP, Pulsedive | mixed | — | planned |

## Roadmap

- [x] **Phase 0** — Archive v1, scaffold the new `lib + bin` crate.
- [x] **Phase 1** — Core model + `ThreatSource`/`Capability` and `IocModule` traits + `network` module.
- [x] **Phase 2** — Router, aggregator, consensus scoring; port ThreatFox/URLhaus/OTX.
- [x] **Phase 3** — Enrichment path end-to-end + AbuseIPDB.
- [x] **Phase 4** — Per-source caching + rate limiting + config file.
- [x] **Phase 5** — STIX 2.1 / MISP export.
- [x] **Phase 6** — `file` module (hash digests + ssdeep) + MalwareBazaar.
- [x] **Phase 7** — VirusTotal v3 + per-source rate limits.
- [x] **Phase 8** — GreyNoise + Shodan (network enrichment context).
- [x] **Phase 9** — `email` + `crypto` modules (BTC/ETH/XMR, checksum-validated) + Ransomwhere.
- [x] **IOA groundwork** — MITRE ATT&CK techniques derived from source tags; relationship
      edges (host→URL, sample→sibling hashes) carried on observations and indicators.
- [x] **Phase 11** — Triage sandbox source: signature-asserted ATT&CK TTPs and
      `CommunicatesWith` behaviour edges from detonation network IOCs.
- [ ] **Future** — MISP integration (when an instance exists); Pulsedive.

## Build & Run

Requires the [Rust toolchain](https://rustup.rs/) (`cargo`).

```bash
cargo build --release

# Enrich a single IOC (type auto-detected; supports defanged input)
cargo run -- enrich 1.2.3.4
cargo run -- enrich "1[.]2[.]3[.]4"

# Enrich a file hash (MD5/SHA-1/SHA-256/SHA-512/ssdeep auto-detected)
cargo run -- enrich 803385cf25070740f5b09e685d2f531c

# Enrich an email address or a crypto wallet (BTC/ETH/XMR)
cargo run -- enrich "user[at]evil[.]com"
cargo run -- enrich 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa

# Collect IOCs for a threat entity (aliases are expanded automatically)
cargo run -- collect LockBit --kind actor

# Output formats: json (default) | csv | stix | misp
cargo run -- enrich 1.2.3.4 --output stix

# Download the raw malware sample for a hash (password-protected zip)
cargo run -- download <sha256> --dir samples
cargo run -- download <sha256> --extract          # also unpack the binary

# Collect a family and pull every sample it turns up
cargo run -- collect AgentTesla --download --samples-dir samples

# List the active sources and their capabilities
cargo run -- sources
```

> **Handling samples safely.** Downloaded files are live malware. They arrive as
> AES-encrypted zips (password `infected`, the abuse.ch convention) so nothing
> executes by accident; only `--extract` unpacks the binary, and you should do
> that only inside an isolated analysis VM. The `samples/` directory is gitignored.

Copy `.env.example` to `.env` and add API keys:

- `ABUSE_CH_AUTH_KEY` — required for ThreatFox + URLhaus + MalwareBazaar (free from <https://auth.abuse.ch/>)
- `OTX_API_KEY` — enables AlienVault OTX
- `ABUSEIPDB_API_KEY` — enables AbuseIPDB IP reputation
- `VT_API_KEY` — enables VirusTotal (free tier is 4 req/min; paced automatically)
- `GREYNOISE_API_KEY` — enables GreyNoise scanner context (free community key)
- `SHODAN_API_KEY` — enables Shodan exposure/CVE context
- `TRIAGE_API_KEY` — enables Triage sandbox behaviour (TTPs, C2 endpoints)

## Configuration

Optional `threatharvester.toml` (or `$TH_CONFIG`, or `--config <path>`) tunes source
toggles, aliases, caching, rate limits, and per-source reliability weights — see
[`threatharvester.toml.example`](threatharvester.toml.example). With no config file,
sensible defaults apply. Responses are cached under `.th-cache/`; transient HTTP
failures (5xx, timeouts) are retried twice with backoff.

## Disclaimer

For **educational and research purposes only**. Any downloaded artifacts may be live malware
and must be handled only within a secure, isolated analysis environment. The authors assume no
liability for misuse.

## License

MIT — see [LICENSE](LICENSE).
