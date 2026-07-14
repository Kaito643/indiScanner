# ThreatHarvester — Rust v1 (archived)

This is the **first-generation Rust engine**, archived for reference. It is **not part of
the active build** (excluded via the workspace `exclude` list in the root `Cargo.toml`).

## What it was

A source-first CTI aggregator: each source (`ThreatFox`, `URLhaus`, `OTX`) implemented a
single `fetch(query)` method, and the engine queried *every source × every alias term*,
then deduplicated by `(value, type)`. Query was entity-name-centric (tag search).

## Why it was replaced

The v2 redesign inverts this into a **capability-routed, IOC-type-module architecture**:

- IOC-type modules (network / file / email ...) own validation, normalization, defanging,
  and source routing.
- Sources declare **capabilities** (which IOC types + operations they serve) so the engine
  only calls sources that can answer.
- `Observation` (raw per-source claim, with provenance) is split from `Indicator`
  (merged + consensus-scored), enabling real confidence scoring and STIX/MISP export.
- Two verbs — `Enrich` (lookup a single IOC) and `Collect` (harvest for an entity/feed) —
  share one engine.

See the root `README.md` for the current design.
