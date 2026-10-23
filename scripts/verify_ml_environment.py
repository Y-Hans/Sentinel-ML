#!/usr/bin/env python3
"""Sentinel-ML — Environment and Model Integrity Verification Script.

This verification script audits the local Sentinel-ML repository environment:
1. Python version and required dependency availability (scikit-learn, joblib, numpy).
2. Presence and file status of frozen champion model artifacts.
3. Integrity of cross-language portable JSON bundles.
4. Validation that no nested Git metadata exists within the repository.

STRICT CONSTRAINTS:
- Performs ZERO Git commands.
- Modifies ZERO files.
- Retrains ZERO models.
"""

import hashlib
import json
import os
import sys
from pathlib import Path


def calculate_sha256(filepath: Path) -> str:
    """Calculate the SHA-256 digest of a file in streaming chunks."""
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


def main() -> int:
    repo_root = Path(__file__).resolve().parent.parent
    print("=" * 70)
    print("Sentinel-ML — Local Repository Readiness & Integrity Audit")
    print(f"Repository Root: {repo_root}")
    print("=" * 70)

    all_passed = True

    # 1. Python Environment Check
    print("\n[1/4] Checking Python Runtime & Core Dependencies...")
    py_ver = sys.version_info
    print(f"  • Python Version: {py_ver.major}.{py_ver.minor}.{py_ver.micro}")
    if py_ver.major < 3 or (py_ver.major == 3 and py_ver.minor < 10):
        print("    [!] Warning: Recommended Python version is >= 3.10")

    required_packages = ["numpy", "scipy", "sklearn", "joblib"]
    for pkg in required_packages:
        try:
            __import__(pkg)
            print(f"  • Package '{pkg}': Available")
        except ImportError:
            print(f"  • Package '{pkg}': NOT INSTALLED (Required for offline Python evaluation)")
            all_passed = False

    # 2. Champion Model Check
    print("\n[2/4] Verifying Champion Model Artifacts...")
    models_to_check = [
        {
            "name": "URL V8 Champion (Joblib)",
            "path": repo_root / "URL-ml" / "models" / "v8_champion.joblib",
            "expected_sha256": "073e70f215c0c3279288ec69a692ed5cab7e99a443ed7b4f87da51ae67cf0e58",
            "type": "binary"
        },
        {
            "name": "URL V8 Champion Portable JSON",
            "path": repo_root / "URL-ml" / "models" / "v8_champion_portable.json",
            "expected_sha256": "e0e5e817beb6e1718843641b2e19e5b131690a0fc959764d83702883f557e870",
            "type": "json"
        },
        {
            "name": "Messages V4 Champion (Pickle)",
            "path": repo_root / "Messages-ml" / "champion_model.pkl",
            "expected_sha256": None,
            "type": "binary"
        },
        {
            "name": "Messages V4 Champion TFIDF",
            "path": repo_root / "Messages-ml" / "champion_tfidf.pkl",
            "expected_sha256": None,
            "type": "binary"
        },
        {
            "name": "Messages V4 Champion Scaler",
            "path": repo_root / "Messages-ml" / "champion_scaler.pkl",
            "expected_sha256": None,
            "type": "binary"
        },
        {
            "name": "Messages V2 Champion Model",
            "path": repo_root / "Messages-ml" / "champion_v2_model.pkl",
            "expected_sha256": None,
            "type": "binary"
        },
        {
            "name": "Android Runtime URL Portable JSON",
            "path": repo_root / "android-runtime" / "url" / "assets" / "v8_champion_portable.json",
            "expected_sha256": "e0e5e817beb6e1718843641b2e19e5b131690a0fc959764d83702883f557e870",
            "type": "json"
        },
    ]

    for m in models_to_check:
        p: Path = m["path"]
        if p.exists():
            size_kb = p.stat().st_size / 1024
            actual_sha = calculate_sha256(p)
            expected = m.get("expected_sha256")
            if expected:
                if actual_sha == expected:
                    print(f"  • {m['name']}: OK ({size_kb:.1f} KB, SHA-256 verified)")
                else:
                    print(f"  • {m['name']}: HASH MISMATCH! Actual: {actual_sha[:16]}... Expected: {expected[:16]}...")
                    all_passed = False
            else:
                print(f"  • {m['name']}: PRESENT ({size_kb:.1f} KB, SHA-256: {actual_sha[:16]}...)")
        else:
            print(f"  • {m['name']}: MISSING at {p.relative_to(repo_root)}")
            all_passed = False

    # 3. Check for Nested Git Metadata
    print("\n[3/4] Verifying No Nested Git Repositories Remain...")
    nested_git = []
    for item in repo_root.rglob(".git"):
        if item != repo_root / ".git":
            nested_git.append(item)
    if nested_git:
        print(f"  [!] FAIL: Found nested .git metadata in sentinel-ml:")
        for ng in nested_git:
            print(f"      - {ng}")
        all_passed = False
    else:
        print("  • Clean: Zero nested .git repositories found inside sentinel-ml.")

    # 4. Check Key Repository Paths
    print("\n[4/4] Verifying Key Repository Structural Paths...")
    expected_dirs = [
        "URL-ml",
        "Messages-ml",
        "android-runtime",
        "shared",
        "scripts",
        "docs",
        "reports",
    ]
    for d in expected_dirs:
        dp = repo_root / d
        if dp.is_dir():
            print(f"  • Directory '{d}/': Present")
        else:
            print(f"  • Directory '{d}/': Missing")
            all_passed = False

    print("\n" + "=" * 70)
    if all_passed:
        print("RESULT: SUCCESS — sentinel-ml environment & artifacts are verified!")
        print("=" * 70)
        return 0
    else:
        print("RESULT: WARNING/INCOMPLETE — Review missing artifacts or packages above.")
        print("=" * 70)
        return 1


if __name__ == "__main__":
    sys.exit(main())
