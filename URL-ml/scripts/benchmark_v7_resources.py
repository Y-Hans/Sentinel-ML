"""V7 Android / Mobile Resource & Latency Benchmark Script.

Measures:
1. Feature extraction latency (p50, p90, p95, p99, mean) across 2,000 URLs.
2. Model inference latency (p50, p90, p95, p99, mean).
3. End-to-end evaluation latency per URL.
4. Memory footprint (baseline, peak during inference, resident size).
5. Single-threaded throughput (URLs/second).
6. Serialized model size vs budget.
"""
from __future__ import annotations
import gc
import io
import json
import os
from pathlib import Path
import sys
import time
import joblib
import numpy as np
import pandas as pd
import tracemalloc

HERE = Path(__file__).resolve()
ROOT = HERE.parents[1]
DATA = ROOT / "data"
MODELS = ROOT / "models"
REPORTS = ROOT / "reports"

sys.path.insert(0, str(HERE.parent))
from v7_features import extract_v7_features, vectorize_v7, V7_FEATURE_NAMES
from reproduce_v7_champion import V7GatedURLClassifier


def benchmark():
    print("=================================================================")
    print("RUNNING V7 ANDROID / MOBILE RESOURCE & LATENCY BENCHMARK")
    print("=================================================================")

    # Load 2,000 diverse URLs from test and hard splits
    clean = pd.read_csv(DATA / "cleaned_dataset.csv", usecols=["url"])
    hard = pd.read_csv(DATA / "hard_dataset.csv", usecols=["url"])
    
    sample_clean = clean.url.sample(n=1000, random_state=42).tolist()
    sample_hard = hard.url.sample(n=1000, random_state=42).tolist()
    urls = sample_clean + sample_hard
    print(f"Benchmarking suite loaded: {len(urls)} diverse URLs.")

    # Load trained champion model
    model_path = MODELS / "v7_champion.joblib"
    clf: V7GatedURLClassifier = joblib.load(model_path)
    bundle_size_bytes = model_path.stat().st_size
    bundle_size_mb = bundle_size_bytes / (1024 * 1024)

    # Start tracemalloc
    tracemalloc.start()
    gc.collect()

    # 1. Benchmark Single-URL Feature Extraction Latency
    feat_latencies_ms = []
    # Warmup
    for u in urls[:50]:
        _ = extract_v7_features(u)

    for u in urls:
        t0 = time.perf_counter()
        _ = extract_v7_features(u)
        t1 = time.perf_counter()
        feat_latencies_ms.append((t1 - t0) * 1000.0)

    # 2. Benchmark Feature Vector Pre-computation + Model Inference Latency
    X_mat, _ = vectorize_v7(urls)
    inf_latencies_ms = []
    
    # Warmup
    for i in range(50):
        _ = clf.predict_proba(X_mat[i:i+1])

    for i in range(len(urls)):
        row = X_mat[i:i+1]
        t0 = time.perf_counter()
        _ = clf.predict_proba(row)
        t1 = time.perf_counter()
        inf_latencies_ms.append((t1 - t0) * 1000.0)

    # 3. Benchmark End-to-End Latency per URL (Extract -> Predict)
    e2e_latencies_ms = []
    for u in urls:
        t0 = time.perf_counter()
        feat_dict = extract_v7_features(u)
        vec = np.array([[feat_dict[n] for n in clf.feature_names]], dtype=np.float32)
        _ = clf.predict_proba(vec)
        t1 = time.perf_counter()
        e2e_latencies_ms.append((t1 - t0) * 1000.0)

    # Memory peak during inference
    current_mem, peak_mem = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    mem_current_mb = current_mem / (1024 * 1024)
    mem_peak_mb = peak_mem / (1024 * 1024)

    # Throughput test (Batch 2000)
    t0 = time.perf_counter()
    _ = clf.predict_proba(X_mat)
    batch_time = time.perf_counter() - t0
    batch_throughput = len(urls) / batch_time

    # Compute Statistics
    def stats(arr):
        return {
            "mean_ms": float(np.mean(arr)),
            "p50_ms": float(np.percentile(arr, 50)),
            "p90_ms": float(np.percentile(arr, 90)),
            "p95_ms": float(np.percentile(arr, 95)),
            "p99_ms": float(np.percentile(arr, 99)),
            "max_ms": float(np.max(arr)),
            "min_ms": float(np.min(arr))
        }

    feat_stats = stats(feat_latencies_ms)
    inf_stats = stats(inf_latencies_ms)
    e2e_stats = stats(e2e_latencies_ms)

    report_data = {
        "model_bundle_size_bytes": bundle_size_bytes,
        "model_bundle_size_mb": bundle_size_mb,
        "memory_current_mb": mem_current_mb,
        "memory_peak_mb": mem_peak_mb,
        "batch_inference_throughput_urls_per_sec": batch_throughput,
        "feature_extraction_latency_ms": feat_stats,
        "model_inference_latency_ms": inf_stats,
        "end_to_end_latency_ms": e2e_stats,
        "meets_mobile_sla": (e2e_stats["p95_ms"] < 2.0 and bundle_size_mb < 10.0 and mem_peak_mb < 50.0)
    }

    print("\n--- LATENCY BENCHMARK RESULTS (2,000 URLs) ---")
    print(f"Feature Extraction Latency : Mean={feat_stats['mean_ms']:.3f}ms | p50={feat_stats['p50_ms']:.3f}ms | p95={feat_stats['p95_ms']:.3f}ms | p99={feat_stats['p99_ms']:.3f}ms")
    print(f"Model Inference Latency    : Mean={inf_stats['mean_ms']:.3f}ms | p50={inf_stats['p50_ms']:.3f}ms | p95={inf_stats['p95_ms']:.3f}ms | p99={inf_stats['p99_ms']:.3f}ms")
    print(f"End-to-End Total Latency   : Mean={e2e_stats['mean_ms']:.3f}ms | p50={e2e_stats['p50_ms']:.3f}ms | p95={e2e_stats['p95_ms']:.3f}ms | p99={e2e_stats['p99_ms']:.3f}ms")
    print(f"Batch Inference Throughput : {batch_throughput:,.1f} URLs / second")
    print(f"Heap Memory Footprint      : Current={mem_current_mb:.2f}MB | Peak Traced={mem_peak_mb:.2f}MB")
    print(f"Serialized Model Size      : {bundle_size_mb:.2f} MB (Budget: <= 10.00 MB)")
    print(f"Meets Mobile SLA (<2ms, <10MB, <50MB RAM): {report_data['meets_mobile_sla']}")
    print("=================================================================")

    json_path = REPORTS / "URL_V7_ANDROID_RESOURCE_BENCHMARK.json"
    json_path.write_text(json.dumps(report_data, indent=2), encoding="utf-8")
    return report_data


if __name__ == "__main__":
    benchmark()
