## Summary

<!-- One or two sentences describing what this PR does and why. -->

## Type of change

- [ ] New rule (YAML only)
- [ ] New threat intelligence source (YAML only)
- [ ] New check module (Python)
- [ ] Bug fix
- [ ] Documentation update
- [ ] Other (describe below)

---

## For new rules (MCPS-NNN)

**Rule ID:** MCPS-NNN
**Severity:** CRITICAL / HIGH / MEDIUM / LOW / INFO
**Detection type:** static / dynamic / both

**Vulnerability being detected:**
<!-- What is the attacker doing, what field allows it, and what is the impact? -->

**Source mappings:**
<!-- List each source mapping with the entry ID and a link to the specific entry. -->
- OWASP MCP Top 10: MCP0X (https://...)
- MITRE ATLAS: AML.Txxxx (https://...)

**False positive risk and mitigation:**
<!-- In what legitimate cases might this fire incorrectly? How does the pattern address this? -->

**Fixture test results:**
```
# Positive fixture (should fire):
$ mcp-sentinel scan --target tests/fixtures/malicious/MCPS-NNN-<name>.json
[paste output]

# Negative fixture (should not fire for this rule):
$ mcp-sentinel scan --target tests/fixtures/benign/MCPS-NNN-<name>.json
[paste output]
```

---

## Checklist

- [ ] `CHANGELOG.md` updated under `[Unreleased]`
- [ ] Rule `updated` date set to today (if modifying an existing rule)
- [ ] Positive and negative fixtures added to `tests/fixtures/`
- [ ] `pytest tests/` passes
- [ ] `ruff check mcp_sentinel/` passes (for Python changes)
- [ ] `mypy mcp_sentinel/` passes (for Python changes)
