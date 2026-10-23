# Decisions for the user — no automatic action

1. Approve or edit PRE_REGISTRATION.md against its SHA before Stage5. All gates are PROPOSED; note G4 is a pilot5% false-alert bound, not a field-readiness claim.
2. Review frozen/REVIEW_SAMPLE_v2.csv (random60M/40B/20S); >5% wrong requires a new set. Please return a marked copy/new filename so existing outputs stay immutable.
3. Send DATASETS MOVED after AgentB handoff; supply the exact1,009-row evaluation sheet path/hash if not in the manifest.
4. Sealed leakage control: supply a non-content exclusion index for exact/fuzzy matching, or explicitly approve checking leakage only in the single Stage6 read, with contaminated gates invalidated. Hash-only access cannot prove absence of content overlap.
5. Confirm whether C2, larger vocabulary and temperature calibration are diagnostic-only in this sprint; they require later Kotlin/runtime authorization. No Android execution/export is requested now.
