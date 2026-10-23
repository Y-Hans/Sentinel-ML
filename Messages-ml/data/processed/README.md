# Processed Data Directory

This directory stores normalized, token-indexed, and group-partitioned dataset splits (`train.parquet`, `val.parquet`, `test.parquet`).

Partitioning is enforced via group-aware template clustering (`leakage_analysis.py`) to prevent cross-split template leakage.
