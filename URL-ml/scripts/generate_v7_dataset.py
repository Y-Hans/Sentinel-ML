"""Generate high-diversity, domain-disjoint legitimate URL expansion for V7.

Strictly preserves evaluation protection: zero domain overlap with TEST, validation,
or hard_dataset. Sourced across training-split domains and synthetic provider archetypes.
"""
from __future__ import annotations
import hashlib
import json
from pathlib import Path
import numpy as np
import pandas as pd
import sys

HERE = Path(__file__).resolve()
ROOT = HERE.parents[1]
DATA = ROOT / "data"
sys.path.insert(0, str(HERE.parent))
from url_features import domain_group
from sklearn.model_selection import GroupShuffleSplit

TEMPLATES = {
    "cdn_assets": [
        "/assets/js/bundle.min.js",
        "/static/css/main.v2.css",
        "/cdn-cgi/scripts/telemetry.js",
        "/dist/vendor/runtime.js?v=4.1.0",
        "/images/brand/logo.svg",
        "/fonts/inter-regular.woff2",
        "/media/uploads/2026/hero-banner.jpg",
        "/favicon.ico",
        "/robots.txt",
        "/sitemap.xml",
    ],
    "account_auth": [
        "/account/profile",
        "/account/security/settings",
        "/auth/sso/callback?code=AUTH_CODE_8471&state=sess_9281",
        "/user/preferences/notifications",
        "/member/dashboard/home",
        "/portal/identity-management",
        "/security/two-factor-setup",
        "/oauth2/authorize?client_id=client_9482&scope=read_profile",
        "/login",
        "/signin",
        "/register",
        "/password/reset",
    ],
    "payment_commerce": [
        "/checkout/review-order",
        "/billing/invoices/2026/INV-84920",
        "/pricing/plans/enterprise",
        "/cart/view",
        "/payments/methods/manage",
        "/orders/track/94821039",
        "/store/products/item-8472?ref=category_shelf",
        "/items/detail/48192",
        "/subscriptions",
        "/api/v2/products?page=2",
    ],
    "documentation_api": [
        "/docs/v2/getting-started",
        "/api/v1/endpoints/users?limit=25",
        "/api/v1/users",
        "/api/v2/products?page=2",
        "/reference/sdk/python/quickstart",
        "/help/articles/10492/troubleshooting-guide",
        "/knowledge-base/article/4821",
        "/releases/tag/v3.4.1",
        "/wiki/Category:Documentation",
        "/swagger/ui/index.html",
        "/docs/api/reference",
        "/developer/portal",
        "/pull/2031",
        "/issues/1042",
        "/item/98213",
        "/library/3.12",
        "/tree/main/src",
    ],
    "media_editorial": [
        "/news/2026/08/technology-breakthroughs",
        "/blog/engineering/scaling-distributed-systems",
        "/articles/deep-dive-into-machine-learning",
        "/watch?v=9B5c2K90La",
        "/episodes/podcast-season-4-episode-12",
        "/community/forum/topics/general-discussion",
        "/events/2026/global-developer-conference",
        "/posts/2026/05/company-milestone",
    ],
    "localized_navigation": [
        "/en-us/products/catalog",
        "/de-de/unternehmen/ueber-uns",
        "/fr-fr/solutions/entreprises",
        "/ja-jp/support/faq",
        "/es-es/servicios/informacion-general",
        "/it-it/assistenza/contatti",
        "/pt-br/produtos/categorias",
        "/en-gb/services",
    ],
    "search_tracking_queries": [
        "/search?q=machine+learning+deployment&sort=relevance",
        "/catalog/browse?category=software&sort=rating&page=2&limit=50",
        "/newsletter/archive?utm_source=email&utm_medium=weekly_digest&utm_campaign=august2026",
        "/explore?filter=recent&view=grid&theme=dark",
        "/topics/browse?tag=security&tab=popular",
        "/find?location=new-york&radius=25",
    ],
    "internal_redirects": [
        "/redirect?target=%2Fdashboard%2Foverview",
        "/out?dest=https%3A%2F%2Fpartner-portal.org%2Fresource",
        "/goto?url=help-center",
        "/link?ref=footer_nav",
    ],
    "general_pages": [
        "/",
        "/about",
        "/contact",
        "/services",
        "/solutions",
        "/features",
        "/careers/jobs",
        "/legal/terms-of-service",
        "/legal/privacy-policy",
        "/company/leadership",
        "/faq",
        "/help",
        "/blog",
        "/business",
        "/world",
    ]
}


def build_v7_dataset():
    clean = pd.read_csv(DATA / "cleaned_dataset.csv", usecols=["url", "label"])
    clean["label"] = 1 - clean.label.astype(int)
    groups = clean.url.map(domain_group)
    y = clean.label.to_numpy()
    idx = np.arange(len(clean))

    tr, rest = next(GroupShuffleSplit(n_splits=1, test_size=0.4, random_state=42).split(idx, y, groups))
    vr, te_r = next(GroupShuffleSplit(n_splits=1, test_size=0.5, random_state=43).split(rest, y[rest], groups.iloc[rest]))
    va, te = rest[vr], rest[te_r]

    val_domains = set(groups.iloc[va])
    test_domains = set(groups.iloc[te])
    hard = pd.read_csv(DATA / "hard_dataset.csv")
    hard_domains = set(hard.url.map(domain_group))
    protected_domains = val_domains | test_domains | hard_domains

    train_benign_mask = (y[tr] == 0)
    train_benign_indices = tr[train_benign_mask]
    train_benign_urls = clean.url.iloc[train_benign_indices].tolist()
    train_benign_domains = [domain_group(u) for u in train_benign_urls]
    
    valid_train_domains = [d for d in sorted(set(train_benign_domains)) if d not in protected_domains]
    print(f"Total available valid training benign domains: {len(valid_train_domains)}")

    np.random.seed(42)
    rows = []
    seen_urls = set()
    all_categories = list(TEMPLATES.keys())
    
    selected_domains = valid_train_domains.copy()
    np.random.shuffle(selected_domains)
    domain_sample = selected_domains[:15000]

    for i, d in enumerate(domain_sample):
        cats = np.random.choice(all_categories, size=3, replace=False)
        for cat in cats:
            tmpl = np.random.choice(TEMPLATES[cat])
            scheme = "http" if (i % 5 == 0) else "https"
            sub_choice = (i + len(cat)) % 6
            if sub_choice == 0:
                host = "www." + d
            elif sub_choice == 1:
                host = "portal." + d
            elif sub_choice == 2:
                host = "docs." + d
            elif sub_choice == 3:
                host = "api." + d
            elif sub_choice == 4:
                host = "app." + d
            else:
                host = d

            url = f"{scheme}://{host}{tmpl}"
            if url not in seen_urls:
                seen_urls.add(url)
                rows.append({
                    "url": url,
                    "label": 0,
                    "source_family": f"v7_structural_{cat}",
                    "registrable_domain": d
                })

    rem3 = pd.read_csv(DATA / "remediation_hard_negatives_v3.csv")
    for _, r in rem3.iterrows():
        d = domain_group(r["url"])
        if d not in protected_domains and r["url"] not in seen_urls:
            seen_urls.add(r["url"])
            rows.append({
                "url": r["url"],
                "label": 0,
                "source_family": r["source_family"],
                "registrable_domain": d
            })

    df_out = pd.DataFrame(rows).drop_duplicates("url").reset_index(drop=True)
    out_path = DATA / "v7_structural_benign.csv"
    df_out.to_csv(out_path, index=False)
    
    sha256 = hashlib.sha256(out_path.read_bytes()).hexdigest()
    stats = {
        "dataset_name": "v7_structural_benign.csv",
        "sha256": sha256,
        "total_rows": len(df_out),
        "unique_registrable_domains": int(df_out["registrable_domain"].nunique()),
        "http_ratio": float((df_out["url"].str.startswith("http://")).mean()),
        "categories_distribution": df_out["source_family"].value_counts().to_dict(),
        "protected_domain_overlap": 0,
        "validation_domain_overlap": 0,
        "test_domain_overlap": 0,
        "hard_dataset_domain_overlap": 0,
    }
    (DATA / "v7_structural_benign.json").write_text(json.dumps(stats, indent=2), encoding="utf-8")
    print(json.dumps(stats, indent=2))
    return df_out


if __name__ == "__main__":
    build_v7_dataset()
