# Changelog

All notable changes to mcp-sentinel will be documented here.

This project follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Added
- Initial project documentation: `README.md`, `ARCHITECTURE.md`, `THREAT-MODEL.md`, `ROADMAP.md`, `CONTRIBUTING.md`, `SECURITY.md`, `CHANGELOG.md`
- Threat intelligence source registry (`rules/sources.yaml`) with 5 sources:
  - OWASP MCP Top 10
  - OWASP Top 10 for Agentic Applications 2026
  - OWASP Top 10 for LLMs 2025
  - MITRE ATLAS
  - NIST AI Risk Management Framework
- Initial rule set (`rules/rules.yaml`) with 5 rules:
  - MCPS-001: Tool Poisoning via Description Field (CRITICAL, static)
  - MCPS-002: Secret and Token Exposure in Tool Definitions (CRITICAL, static)
  - MCPS-003: Overly Permissive Parameter Schemas (HIGH, static)
  - MCPS-004: Insecure Transport Configuration (HIGH, static)
  - MCPS-005: Agentic Supply Chain: Unverified Tool Provenance (HIGH, static)
- Multi-source rule mapping system supporting simultaneous mapping across all registered sources
- Pluggable detection pattern types: `regex`, `keyword`, `length`, `unicode`, `schema_analysis`, `value_check`
- Per-pattern severity override support

---

## Version History

No releases yet. Active development toward v0.1.0.

See [`ROADMAP.md`](ROADMAP.md) for the Phase 1 definition of done that constitutes the v0.1.0 release criteria.

---

## Release Format

```
## [0.1.0] - YYYY-MM-DD

### Added        New features and capabilities
### Changed      Changes to existing behavior
### Fixed        Bug fixes
### Deprecated   Features to be removed in a future release
### Removed      Features removed in this release
### Security     Security fixes (with advisory reference where applicable)
```
