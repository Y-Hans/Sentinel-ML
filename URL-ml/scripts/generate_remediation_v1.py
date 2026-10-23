"""Create a source-diverse, non-overlapping URL hard-negative remediation set."""
from __future__ import annotations
import hashlib, json
from pathlib import Path
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "data"
domains = [
    "airbnb.com", "asana.com", "atlassian.com", "autodesk.com", "canva.com", "cisco.com",
    "cloudflare.com", "coursera.org", "docusign.com", "dropbox.com", "duolingo.com", "evernote.com",
    "fidelity.com", "figma.com", "gofundme.com", "grammarly.com", "hubspot.com", "indeed.com",
    "intuit.com", "jetblue.com", "kayak.com", "khanacademy.org", "lyft.com", "mailchimp.com",
    "masterclass.com", "medium.com", "mercury.com", "nasa.gov", "nordstrom.com", "notion.so",
    "npmjs.com", "okta.com", "patreon.com", "plaid.com", "proton.me", "qantas.com", "quickbooks.intuit.com",
    "reddit.com", "salesforce.com", "samsclub.com", "schwab.com", "shopify.com", "signal.org",
    "skillshare.com", "southwest.com", "squareup.com", "stripe.com", "target.com", "tax.service.gov.uk",
    "ticketmaster.com", "udemy.com", "united.com", "usps.com", "verizon.com", "wellsfargo.com",
    "wikipedia.org", "wise.com", "workday.com", "zoom.us", "bbc.co.uk", "bloomberg.com",
    "calendly.com", "capitalone.com", "consumerfinance.gov", "creativecommons.org", "dhl.com",
    "discover.com", "doordash.com", "fedex.com", "gsa.gov", "hdfcbank.com", "hulu.com",
    "irs.gov", "jpmorganchase.com", "lendingtree.com", "linkedin.com", "medicare.gov", "metlife.com",
    "nyc.gov", "paypal.com", "pinterest.com", "redcross.org", "sba.gov", "spotify.com",
    "stanford.edu", "statefarm.com", "tesla.com", "travel.state.gov", "tripadvisor.com", "twitch.tv",
    "unicef.org", "vanguard.com", "venmo.com", "walmart.com", "washingtonpost.com", "whatsapp.com",
]
templates = [
    "/", "/about", "/contact", "/help", "/support", "/account", "/account/settings",
    "/login", "/signin", "/security", "/security/overview", "/privacy", "/terms",
    "/order/confirmation/2026", "/payment/status?id=84721", "/search?q=account+security",
    "/reset-password", "/verify-email", "/billing/invoices/2026-08", "/docs/api?version=2",
]
existing = pd.read_csv(DATA / "final_dataset.csv", usecols=["url"])
existing_urls = set(existing.url.astype(str))
existing_domains = set(existing.url.astype(str).str.extract(r"https?://([^/]+)", expand=False).str.lower().str.replace(r"^www\.", "", regex=True).str.rstrip("."))
rows = []
for domain in domains:
    bare = domain.lower().removeprefix("www.")
    if bare in existing_domains:
        continue
    for i, path in enumerate(templates):
        host = bare if i % 3 else "www." + bare
        scheme = "https" if i != 5 else "http"
        url = scheme + "://" + host + path
        if url not in existing_urls:
            rows.append({"url": url, "label": 0, "source_family": "remediation_legitimate_provider", "registrable_domain": bare})
out = pd.DataFrame(rows).drop_duplicates("url").reset_index(drop=True)
out_path = DATA / "remediation_hard_negatives_v1.csv"
out.to_csv(out_path, index=False)
report = {
    "dataset_version": hashlib.sha256(out_path.read_bytes()).hexdigest(), "path": str(out_path),
    "rows": int(len(out)), "label_counts": {str(k): int(v) for k, v in out.label.value_counts().items()},
    "registrable_domains": int(out.registrable_domain.nunique()), "source_families": out.source_family.value_counts().to_dict(),
    "domain_overlap_with_final_dataset": int(bool(set(out.registrable_domain) & set(existing_domains))),
    "url_overlap_with_final_dataset": int(bool(set(out.url) & existing_urls)),
    "failure_family": "legitimate provider URLs with security/account/payment/query semantics",
    "generation": "fixed templates over previously unseen providers; no TEST/OOD/hard-source row was copied or transformed",
}
(DATA / "remediation_hard_negatives_v1.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
print(json.dumps(report, indent=2))
