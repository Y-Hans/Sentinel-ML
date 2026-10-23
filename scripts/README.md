# Sentinel — Workspace Shared Utilities

This directory is reserved for workspace-level shared verification tools, environment checkers, and cross-project auditing utilities.

---

## 1. Directory Purpose

The `tools/` directory provides workspace-wide automation for:
- Environment and dependency preflight verification.
- Cross-project cryptographic ledger audits.
- Parity report compilation and indexing.

---

## 2. Tooling Rules & Boundaries

> [!WARNING]
> **Safety Constraints:**
> - Tools located here must **NEVER** modify, write into, delete, or stage files within `sentinel-ai/`.
> - All scripts must accept or verify working directories explicitly rather than assuming hardcoded local paths.
> - Tools must not mutate frozen model files (`v8_champion.joblib`, `v8_champion_portable.json`) or alter active datasets.
