# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-09-05

First public GitHub release of the T1003.001 Sigma robustness benchmark.

### Added

- Pinned corpus manifest (commits + sha256) and reproducible fetch/split (`eval/corpus.py`).
- pySigma matcher that owns compilation (no SIEM backend in the scoring path).
- Miss classifier: detected / miss-telemetry / out-of-scope / miss-logic.
- Mutation tiers (rename, relocate, strip PE, new identity) plus a control that must not move coverage.
- Prescreen, three-population selection, and derived sensitivity / robustness records.
- Committed measured records: `benchmark/results`, `selection`, `sensitivity`, `robustness`, `chain`, `crosscheck`.
- Six authored Sigma rules, converted Splunk SPL and Kusto under `rules/converted/`.
- Zircolite cross-check; APT29 transfer / label-transfer module.
- CI that runs tests, validates rules, and fails on results drift; `scripts/ci-local.sh` (`--fast` / default / `--release`).
- Observable local pipeline progress and MIT license.
- Method, decisions, corpora, deploying, and contrib write-ups (none of the contrib drafts sent upstream).

### Changed

- Transfer test named as a label-transfer test rather than an intrusion-chain reconstruction.
- README structured around the per-tool headline and the rename/relocation findings.

### Fixed

- Field-name handling so rules read fields the captures actually carry.
- ATT&CK taxonomy seed URL that an egress proxy does not block.
- Checkout paths kept out of committed results.

[1.0.0]: https://github.com/YaCnDehfuli/detection-under-load/releases/tag/v1.0.0
