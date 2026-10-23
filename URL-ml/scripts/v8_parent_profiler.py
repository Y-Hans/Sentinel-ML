"""V8 Parent Profiler & Offline Knowledge Base Builder.

STRICT DATA INTEGRITY & ZERO LEAKAGE RULES:
1. Parent statistics, priors, and morphology distributions are fitted STRICTLY
   on the training split (Train split of cleaned_dataset.csv + v7_structural_benign.csv).
2. Zero validation, test, hard-source, or adversarial labels are ever observed.
3. Smoothing: Low-frequency or unseen domains gracefully back off to the empirical global
   training baseline (neutral prior).
4. No whitelist: A domain prior is continuous and bounded; never 0.0 or 1.0.
5. Exportable to compact, zero-dependency JSON for Android / Kotlin deployment.
"""
from __future__ import annotations
import json
import math
from pathlib import Path
from typing import Any
import numpy as np
import pandas as pd
from v8_normalization import parse_v8_url, extract_parent_domain

FINANCIAL_DOMAINS_SUBSTR = (
    "bank", "pay", "chase", "wellsfargo", "citibank", "capitalone", "barclays",
    "hsbc", "usbank", "pnc", "fidelity", "schwab", "vanguard", "americanexpress",
    "discover", "mastercard", "visa", "binance", "coinbase", "kraken", "metamask",
    "gemini", "crypto", "blockchain", "stripe", "square", "paypal"
)

DEV_DOMAINS_SUBSTR = (
    "github", "gitlab", "bitbucket", "stackoverflow", "docker", "kubernetes",
    "npmjs", "pypi", "atlassian", "trello", "cloudflare", "fastly", "digitalocean",
    "heroku", "vercel", "netlify"
)

MEDIA_DOMAINS_SUBSTR = (
    "youtube", "youtu.be", "twitch", "vimeo", "spotify", "netflix", "hulu",
    "disney", "soundcloud", "dailymotion"
)

GAMING_DOMAINS_SUBSTR = (
    "crazygames", "codenames", "chessigma", "itch.io", "miniclip", "poki",
    "roblox", "steam", "epicgames", "chess.com", "lichess"
)


def categorize_parent_domain(parent_domain: str) -> dict[str, float]:
    """Categorize domain into structural site families."""
    p_lower = parent_domain.lower()
    
    is_fin = float(any(w in p_lower for w in FINANCIAL_DOMAINS_SUBSTR))
    is_dev = float(any(w in p_lower for w in DEV_DOMAINS_SUBSTR))
    is_media = float(any(w in p_lower for w in MEDIA_DOMAINS_SUBSTR))
    is_gaming = float(any(w in p_lower for w in GAMING_DOMAINS_SUBSTR))
    
    return {
        "is_financial": is_fin,
        "is_dev": is_dev,
        "is_media": is_media,
        "is_gaming": is_gaming,
        "is_general": float(not (is_fin or is_dev or is_media or is_gaming))
    }


class V8ParentProfiler:
    """Manages train-fitted parent domain priors and morphology profiles."""

    def __init__(self, smoothing_alpha: float = 10.0):
        self.smoothing_alpha = smoothing_alpha
        self.global_prior_malicious = 0.12  # fallback default
        self.global_morphology: dict[str, float] = {}
        self.domain_profiles: dict[str, dict[str, Any]] = {}

    def fit_from_training_data(
        self,
        train_urls: list[str],
        train_labels: np.ndarray,
        syn_urls: list[str] | None = None,
        syn_labels: np.ndarray | None = None
    ) -> None:
        """Fit profiles strictly from training URLs and labels."""
        all_urls = list(train_urls)
        all_labels = list(train_labels)
        if syn_urls and syn_labels is not None:
            all_urls.extend(syn_urls)
            all_labels.extend(syn_labels)

        n_total = len(all_urls)
        n_mal = sum(all_labels)
        self.global_prior_malicious = float(n_mal / max(1, n_total))

        # Collect observations per parent
        records: dict[str, dict[str, Any]] = {}
        lengths, path_lens, path_depths, query_lens = [], [], [], []

        for url, lbl in zip(all_urls, all_labels):
            p = parse_v8_url(url)
            parent = p.parent_domain
            u_len = len(p.raw)
            p_len = len(p.clean_path)
            p_depth = len(p.path_segments)
            q_len = len(p.query)

            lengths.append(u_len)
            path_lens.append(p_len)
            path_depths.append(p_depth)
            query_lens.append(q_len)

            if parent not in records:
                records[parent] = {
                    "total": 0,
                    "mal": 0,
                    "lengths": [],
                    "path_lens": [],
                    "path_depths": [],
                    "query_lens": [],
                    "has_hex": 0,
                }
            rec = records[parent]
            rec["total"] += 1
            if lbl == 1:
                rec["mal"] += 1
            rec["lengths"].append(u_len)
            rec["path_lens"].append(p_len)
            rec["path_depths"].append(p_depth)
            rec["query_lens"].append(q_len)
            if any(len(seg) >= 16 and all(c in "0123456789abcdefABCDEF" for c in seg) for seg in p.path_segments):
                rec["has_hex"] += 1

        # Global morphology medians
        self.global_morphology = {
            "p50_len": float(np.median(lengths)) if lengths else 45.0,
            "p90_len": float(np.percentile(lengths, 90)) if lengths else 95.0,
            "p50_path_len": float(np.median(path_lens)) if path_lens else 15.0,
            "p90_path_len": float(np.percentile(path_lens, 90)) if path_lens else 50.0,
            "p50_path_depth": float(np.median(path_depths)) if path_depths else 2.0,
            "p90_path_depth": float(np.percentile(path_depths, 90)) if path_depths else 4.0,
            "p50_query_len": float(np.median(query_lens)) if query_lens else 0.0,
            "p90_query_len": float(np.percentile(query_lens, 90)) if query_lens else 20.0,
            "hex_prevalence": 0.01,
        }

        # Fit profiles for each parent
        alpha = self.smoothing_alpha
        p_glob = self.global_prior_malicious

        for parent, rec in records.items():
            tot = rec["total"]
            mal = rec["mal"]
            smoothed_mal_p = float((mal + alpha * p_glob) / (tot + alpha))

            # Morphology: if at least 3 observations, use domain percentiles, else fallback
            lens = rec["lengths"]
            p_lens = rec["path_lens"]
            depths = rec["path_depths"]
            qlens = rec["query_lens"]

            if tot >= 3:
                p50_l = float(np.median(lens))
                p90_l = float(np.percentile(lens, 90))
                p50_pl = float(np.median(p_lens))
                p90_pl = float(np.percentile(p_lens, 90))
                p50_d = float(np.median(depths))
                p90_d = float(np.percentile(depths, 90))
                p50_ql = float(np.median(qlens))
                p90_ql = float(np.percentile(qlens, 90))
                hex_prev = float(rec["has_hex"] / tot)
            else:
                p50_l = self.global_morphology["p50_len"]
                p90_l = self.global_morphology["p90_len"]
                p50_pl = self.global_morphology["p50_path_len"]
                p90_pl = self.global_morphology["p90_path_len"]
                p50_d = self.global_morphology["p50_path_depth"]
                p90_d = self.global_morphology["p90_path_depth"]
                p50_ql = self.global_morphology["p50_query_len"]
                p90_ql = self.global_morphology["p90_query_len"]
                hex_prev = self.global_morphology["hex_prevalence"]

            cats = categorize_parent_domain(parent)

            # Special financial invariant: on financial sites, enforce conservative prior floor
            if cats["is_financial"] == 1.0:
                smoothed_mal_p = max(smoothed_mal_p, 0.40)

            self.domain_profiles[parent] = {
                "obs_count": tot,
                "mal_count": mal,
                "mal_prior": round(smoothed_mal_p, 4),
                "p50_len": round(p50_l, 1),
                "p90_len": round(p90_l, 1),
                "p50_path_len": round(p50_pl, 1),
                "p90_path_len": round(p90_pl, 1),
                "p50_path_depth": round(p50_d, 1),
                "p90_path_depth": round(p90_d, 1),
                "p50_query_len": round(p50_ql, 1),
                "p90_query_len": round(p90_ql, 1),
                "hex_prevalence": round(hex_prev, 3),
                **cats
            }

    def get_parent_features(self, parent_domain: str) -> dict[str, float]:
        """Get Group B parent features for any domain (known or unknown)."""
        cats = categorize_parent_domain(parent_domain)

        if parent_domain in self.domain_profiles:
            prof = self.domain_profiles[parent_domain]
            tot = float(prof["obs_count"])
            mal_prior = float(prof["mal_prior"])
            p50_l = float(prof["p50_len"])
            p90_l = float(prof["p90_len"])
            p50_pl = float(prof["p50_path_len"])
            p90_pl = float(prof["p90_path_len"])
            p50_d = float(prof["p50_path_depth"])
            p90_d = float(prof["p90_path_depth"])
            p50_ql = float(prof["p50_query_len"])
            p90_ql = float(prof["p90_query_len"])
            hex_prev = float(prof["hex_prevalence"])
            is_known = 1.0
        else:
            # Neutral fallback for unknown domains
            tot = 0.0
            mal_prior = float(self.global_prior_malicious)
            # If unknown domain has financial name, retain conservative prior
            if cats["is_financial"] == 1.0:
                mal_prior = max(mal_prior, 0.40)
            p50_l = float(self.global_morphology.get("p50_len", 45.0))
            p90_l = float(self.global_morphology.get("p90_len", 95.0))
            p50_pl = float(self.global_morphology.get("p50_path_len", 15.0))
            p90_pl = float(self.global_morphology.get("p90_path_len", 50.0))
            p50_d = float(self.global_morphology.get("p50_path_depth", 2.0))
            p90_d = float(self.global_morphology.get("p90_path_depth", 4.0))
            p50_ql = float(self.global_morphology.get("p50_query_len", 0.0))
            p90_ql = float(self.global_morphology.get("p90_query_len", 20.0))
            hex_prev = float(self.global_morphology.get("hex_prevalence", 0.01))
            is_known = 0.0

        return {
            "Parent_LogObsCount": float(math.log1p(tot)),
            "Parent_MaliciousPrior": float(mal_prior),
            "Parent_IsKnownDomain": float(is_known),
            "Parent_IsFinancial": float(cats["is_financial"]),
            "Parent_IsDeveloper": float(cats["is_dev"]),
            "Parent_IsMedia": float(cats["is_media"]),
            "Parent_IsGaming": float(cats["is_gaming"]),
            "Parent_IsGeneral": float(cats["is_general"]),
            "Parent_P50Length": float(p50_l),
            "Parent_P90Length": float(p90_l),
            "Parent_P50PathDepth": float(p50_d),
            "Parent_P90PathDepth": float(p90_d),
            "Parent_P50QueryLength": float(p50_ql),
            "Parent_HexPrevalence": float(hex_prev),
        }

    def export_json(self, filepath: Path) -> None:
        """Export parent profiles to a portable JSON bundle."""
        bundle = {
            "version": "8.0.0",
            "global_prior_malicious": self.global_prior_malicious,
            "global_morphology": self.global_morphology,
            "domain_profiles": self.domain_profiles
        }
        filepath.write_text(json.dumps(bundle, separators=(",", ":")), encoding="utf-8")

    @classmethod
    def load_json(cls, filepath: Path) -> V8ParentProfiler:
        """Load parent profiles from a portable JSON bundle."""
        bundle = json.loads(filepath.read_text(encoding="utf-8"))
        instance = cls()
        instance.global_prior_malicious = bundle["global_prior_malicious"]
        instance.global_morphology = bundle["global_morphology"]
        instance.domain_profiles = bundle["domain_profiles"]
        return instance
