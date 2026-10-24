"""Collect a provenance-backed URL dataset without contacting suspicious URLs.

Only feed endpoints, robots.txt, and sitemap documents are fetched. URLs returned
by threat feeds are stored as text and are never resolved, DNS-looked-up, opened,
or downloaded.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import re
import sys
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve()
sys.path.insert(0, str(HERE.parent))

from fresh_url_features import canonicalize_url  # noqa: E402
from fresh_url_schema import SCHEMA_VERSION, sha256_bytes, utc_now, write_jsonl  # noqa: E402


USER_AGENT = "Sentinel-ML-fresh-url-collector/20261024"
MAX_SITEMAP_DOCUMENTS_PER_SOURCE = 24
MALICIOUS_ENDPOINTS = {
    "tweetfeed_month_url": "https://api.tweetfeed.live/v1/month/url",
    "phishunt_domains": "https://phishunt.io/api/v1/domains",
}
BENIGN_SOURCES = [
    {
        "name": "Python Documentation",
        "slug": "python_docs",
        "robots": "https://docs.python.org/robots.txt",
        "category": "developer_documentation",
        "terms": "https://docs.python.org/3/license.html",
    },
    {
        "name": "MDN Web Docs",
        "slug": "mdn_web_docs",
        "robots": "https://developer.mozilla.org/robots.txt",
        "category": "developer_documentation",
        "terms": "https://www.mozilla.org/en-US/about/legal/terms/mozilla/",
    },
    {
        "name": "GitHub Documentation",
        "slug": "github_docs",
        "robots": "https://docs.github.com/robots.txt",
        "category": "developer_documentation",
        "terms": "https://docs.github.com/en/site-policy/github-terms/github-terms-of-service",
    },
]
DIRECT_BENIGN_SOURCES = [
    ("NASA", "https://www.nasa.gov/", "government_science"),
    ("National Institutes of Health", "https://www.nih.gov/", "government_health"),
    ("CDC", "https://www.cdc.gov/", "government_health"),
    ("USA.gov", "https://www.usa.gov/", "government_services"),
    ("European Union", "https://europa.eu/", "government_services"),
    ("World Health Organization", "https://www.who.int/", "international_health"),
    ("United Nations", "https://www.un.org/", "international_services"),
    ("Python", "https://www.python.org/", "developer"),
    ("Mozilla", "https://www.mozilla.org/", "developer"),
    ("Kotlin", "https://kotlinlang.org/", "developer"),
    ("Rust", "https://www.rust-lang.org/", "developer"),
    ("GNU", "https://www.gnu.org/", "developer"),
    ("Linux Kernel", "https://www.kernel.org/", "developer"),
    ("Apache Software Foundation", "https://www.apache.org/", "developer"),
    ("Django", "https://www.djangoproject.com/", "developer"),
    ("R Project", "https://www.r-project.org/", "developer"),
    ("Ruby", "https://www.ruby-lang.org/", "developer"),
    ("Node.js", "https://nodejs.org/", "developer"),
    ("npm", "https://www.npmjs.com/", "developer"),
    ("Python Package Index", "https://pypi.org/", "developer"),
    ("Stack Overflow", "https://stackoverflow.com/", "developer"),
    ("Reuters", "https://www.reuters.com/", "media"),
    ("BBC", "https://www.bbc.com/", "media"),
    ("NPR", "https://www.npr.org/", "media"),
    ("The Guardian", "https://www.theguardian.com/", "media"),
    ("Walmart", "https://www.walmart.com/", "commerce"),
    ("Target", "https://www.target.com/", "commerce"),
    ("Shopify", "https://www.shopify.com/", "commerce"),
    ("Apple", "https://www.apple.com/", "technology"),
    ("Microsoft", "https://www.microsoft.com/", "technology"),
    ("Google", "https://www.google.com/", "technology"),
    ("Adobe", "https://www.adobe.com/", "technology"),
    ("IBM", "https://www.ibm.com/", "technology"),
    ("Oracle", "https://www.oracle.com/", "technology"),
    ("Salesforce", "https://www.salesforce.com/", "technology"),
    ("Cloudflare", "https://www.cloudflare.com/", "technology"),
    ("DigitalOcean", "https://www.digitalocean.com/", "technology"),
    ("Heroku", "https://www.heroku.com/", "technology"),
    ("Vercel", "https://vercel.com/", "technology"),
    ("Netlify", "https://www.netlify.com/", "technology"),
    ("Atlassian", "https://www.atlassian.com/", "technology"),
    ("Slack", "https://slack.com/", "technology"),
    ("Zoom", "https://zoom.us/", "technology"),
    ("Spotify", "https://www.spotify.com/", "media"),
    ("Netflix", "https://www.netflix.com/", "media"),
    ("Disney", "https://www.disney.com/", "media"),
    ("Airbnb", "https://www.airbnb.com/", "commerce"),
    ("Uber", "https://www.uber.com/", "commerce"),
    ("Lyft", "https://www.lyft.com/", "commerce"),
    ("eBay", "https://www.ebay.com/", "commerce"),
    ("Etsy", "https://www.etsy.com/", "commerce"),
    ("Costco", "https://www.costco.com/", "commerce"),
    ("Best Buy", "https://www.bestbuy.com/", "commerce"),
    ("Home Depot", "https://www.homedepot.com/", "commerce"),
    ("Nike", "https://www.nike.com/", "commerce"),
    ("Delta", "https://www.delta.com/", "travel"),
    ("United Airlines", "https://www.united.com/", "travel"),
    ("FedEx", "https://www.fedex.com/", "delivery"),
    ("UPS", "https://www.ups.com/", "delivery"),
    ("USPS", "https://www.usps.com/", "delivery"),
    ("Chase", "https://www.chase.com/", "finance"),
    ("Bank of America", "https://www.bankofamerica.com/", "finance"),
    ("Wells Fargo", "https://www.wellsfargo.com/", "finance"),
    ("PayPal", "https://www.paypal.com/", "finance"),
    ("Visa", "https://www.visa.com/", "finance"),
    ("Mastercard", "https://www.mastercard.com/", "finance"),
    ("Coinbase", "https://www.coinbase.com/", "finance"),
    ("LinkedIn", "https://www.linkedin.com/", "social"),
    ("Facebook", "https://www.facebook.com/", "social"),
    ("Instagram", "https://www.instagram.com/", "social"),
    ("YouTube", "https://www.youtube.com/", "media"),
    ("Reddit", "https://www.reddit.com/", "social"),
    ("TikTok", "https://www.tiktok.com/", "social"),
    ("Pinterest", "https://www.pinterest.com/", "social"),
    ("The Washington Post", "https://www.washingtonpost.com/", "media"),
    ("The New York Times", "https://www.nytimes.com/", "media"),
    ("Forbes", "https://www.forbes.com/", "media"),
    ("TechCrunch", "https://techcrunch.com/", "media"),
]


def fetch(url: str) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(request, timeout=8) as response:
        return response.read()


def safe_filename(value: str) -> str:
    return re.sub(r"[^a-zA-Z0-9._-]+", "_", value)


def parse_url_status(url: str) -> tuple[bool, str | None]:
    try:
        parsed = urllib.parse.urlsplit(url)
        valid = parsed.scheme in {"http", "https"} and bool(parsed.hostname)
        return valid, None if valid else "missing_http_scheme_or_host"
    except ValueError as exc:
        return False, str(exc)


def read_tweetfeed(raw_dir: Path, collected_at: str) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    endpoint = MALICIOUS_ENDPOINTS["tweetfeed_month_url"]
    body = fetch(endpoint)
    snapshot_hash = sha256_bytes(body)
    raw_path = raw_dir / "malicious" / "tweetfeed_month_url.json"
    raw_path.parent.mkdir(parents=True, exist_ok=True)
    raw_path.write_bytes(body)
    rows = json.loads(body.decode("utf-8"))
    records: list[dict[str, Any]] = []
    for index, item in enumerate(rows):
        original = str(item.get("value", "")).strip()
        if not original:
            continue
        canonical = canonicalize_url(original)
        valid, parse_error = parse_url_status(canonical)
        tags = item.get("tags", [])
        if isinstance(tags, str):
            tags = [tags]
        records.append(
            {
                "record_id": f"tweetfeed-{index}-{hashlib.sha256(original.encode()).hexdigest()[:16]}",
                "original_url": original,
                "canonical_url": canonical,
                "label": "MALICIOUS",
                "label_rationale": "Listed as a URL IOC in TweetFeed, a CC0 community threat-intelligence feed.",
                "threat_category": [tag.lstrip("#").lower() for tag in tags] or ["unknown_threat"],
                "source_name": "TweetFeed",
                "source_endpoint": endpoint,
                "source_record_id": item.get("tweet", f"tweetfeed-row-{index}"),
                "source_tags": tags,
                "corroborating_sources": [],
                "collection_timestamp_utc": collected_at,
                "source_snapshot_sha256": snapshot_hash,
                "source_record_sha256": hashlib.sha256(json.dumps(item, sort_keys=True).encode()).hexdigest(),
                "source_license": "CC0-1.0",
                "source_terms_url": "https://tweetfeed.live/tos/",
                "registrable_domain": "",
                "domain_group_id": "",
                "campaign_group_id": "",
                "source_cluster_id": f"tweetfeed:{item.get('user', 'unknown')}",
                "url_family_id": "",
                "status": "UNRESOLVED",
                "syntax_valid": valid,
                "parse_error": parse_error,
                "brand_target": "",
                "domain_category": "threat_feed",
                "is_demo_fixture": False,
                "source_observed_timestamp_utc": item.get("date", ""),
            }
        )
    return records, {
        "source_name": "TweetFeed",
        "endpoint": endpoint,
        "retrieved_at_utc": collected_at,
        "snapshot_sha256": snapshot_hash,
        "raw_path": str(raw_path),
        "row_count": len(records),
        "license": "CC0-1.0",
        "terms_url": "https://tweetfeed.live/tos/",
    }


def read_phishunt(raw_dir: Path, collected_at: str) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    all_results: list[dict[str, Any]] = []
    offset = 0
    limit = 1000
    snapshots: list[bytes] = []
    total = None
    while total is None or offset < total:
        endpoint = f"{MALICIOUS_ENDPOINTS['phishunt_domains']}?limit={limit}&offset={offset}"
        body = fetch(endpoint)
        snapshots.append(body)
        payload = json.loads(body.decode("utf-8"))
        page = payload.get("results", [])
        all_results.extend(page)
        total = int(payload.get("total", len(all_results)))
        offset += len(page)
        if not page:
            break
    combined = b"\n".join(snapshots)
    snapshot_hash = sha256_bytes(combined)
    raw_path = raw_dir / "malicious" / "phishunt_domains.json"
    raw_path.parent.mkdir(parents=True, exist_ok=True)
    raw_path.write_bytes(combined)
    records: list[dict[str, Any]] = []
    for index, item in enumerate(all_results):
        original = str(item.get("url", "")).strip()
        if not original:
            continue
        canonical = canonicalize_url(original)
        valid, parse_error = parse_url_status(canonical)
        category = "phishing"
        if item.get("company"):
            category = f"phishing_{str(item['company']).lower()}"
        records.append(
            {
                "record_id": f"phishunt-{item.get('uuid', index)}",
                "original_url": original,
                "canonical_url": canonical,
                "label": "MALICIOUS",
                "label_rationale": "Listed as an active suspicious phishing URL by phishunt.io; source flags are retained for audit and not treated as independent proof.",
                "threat_category": [category],
                "source_name": "phishunt.io",
                "source_endpoint": MALICIOUS_ENDPOINTS["phishunt_domains"],
                "source_record_id": item.get("uuid", f"phishunt-row-{index}"),
                "source_tags": [],
                "corroborating_sources": [
                    source for source, flag in (
                        ("Google Safe Browsing", item.get("malicious_google")),
                        ("OpenPhish", item.get("malicious_openphish")),
                        ("PhishTank", item.get("malicious_phishtank")),
                        ("TweetFeed", item.get("malicious_tweetfeed")),
                        ("urlscan.io", item.get("malicious_urlscan")),
                    ) if flag
                ],
                "collection_timestamp_utc": collected_at,
                "source_snapshot_sha256": snapshot_hash,
                "source_record_sha256": hashlib.sha256(json.dumps(item, sort_keys=True).encode()).hexdigest(),
                "source_license": "CC0-1.0",
                "source_terms_url": "https://phishunt.io/tos/",
                "registrable_domain": str(item.get("domain", "")),
                "domain_group_id": str(item.get("domain", "")),
                "campaign_group_id": "",
                "source_cluster_id": "phishunt",
                "url_family_id": "",
                "status": "UNRESOLVED",
                "syntax_valid": valid,
                "parse_error": parse_error,
                "brand_target": str(item.get("company", "")),
                "domain_category": "threat_feed",
                "is_demo_fixture": False,
                "source_observed_timestamp_utc": item.get("date", ""),
            }
        )
    return records, {
        "source_name": "phishunt.io",
        "endpoint": MALICIOUS_ENDPOINTS["phishunt_domains"],
        "retrieved_at_utc": collected_at,
        "snapshot_sha256": snapshot_hash,
        "raw_path": str(raw_path),
        "row_count": len(records),
        "license": "CC0-1.0",
        "terms_url": "https://phishunt.io/tos/",
    }


def sitemap_urls(xml_body: bytes) -> list[str]:
    if xml_body[:2] == b"\x1f\x8b":
        xml_body = gzip.decompress(xml_body)
    root = ET.fromstring(xml_body)
    values = []
    for element in root.iter():
        if element.tag.lower().endswith("loc") and element.text:
            values.append(element.text.strip())
    return values


def collect_benign(source: dict[str, str], raw_dir: Path, collected_at: str, cap: int) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    robots_body = fetch(source["robots"])
    robots_hash = sha256_bytes(robots_body)
    robots_path = raw_dir / "benign" / f"{source['slug']}_robots.txt"
    robots_path.parent.mkdir(parents=True, exist_ok=True)
    robots_path.write_bytes(robots_body)
    sitemap_candidates = re.findall(r"(?im)^\s*Sitemap:\s*(\S+)", robots_body.decode("utf-8", "replace"))
    urls: list[str] = []
    snapshot_hashes = [robots_hash]
    visited: set[str] = set()
    queue = list(sitemap_candidates)
    while queue and len(urls) < cap and len(visited) < MAX_SITEMAP_DOCUMENTS_PER_SOURCE:
        sitemap = queue.pop(0)
        if sitemap in visited:
            continue
        visited.add(sitemap)
        try:
            body = fetch(sitemap)
            path = raw_dir / "benign" / f"{source['slug']}_{len(visited)}.xml"
            path.write_bytes(body)
            snapshot_hashes.append(sha256_bytes(body))
            extracted = sitemap_urls(body)
        except Exception:
            continue
        if b"<sitemapindex" in body[:5000].lower():
            queue.extend(extracted[:20])
        else:
            urls.extend(extracted[: max(0, cap - len(urls))])
    records = []
    for index, original in enumerate(urls[:cap]):
        canonical = canonicalize_url(original)
        valid, parse_error = parse_url_status(canonical)
        if not valid:
            continue
        records.append(
            {
                "record_id": f"benign-{source['slug']}-{index}-{hashlib.sha256(original.encode()).hexdigest()[:16]}",
                "original_url": original,
                "canonical_url": canonical,
                "label": "BENIGN",
                "label_rationale": "URL was published by the official source's own sitemap; no suspicious destination was contacted and no threat verdict is inferred from reachability.",
                "threat_category": [],
                "source_name": source["name"],
                "source_endpoint": source["robots"],
                "source_record_id": f"{source['slug']}-sitemap-{index}",
                "source_tags": [],
                "corroborating_sources": [],
                "collection_timestamp_utc": collected_at,
                "source_snapshot_sha256": hashlib.sha256("".join(snapshot_hashes).encode()).hexdigest(),
                "source_record_sha256": hashlib.sha256(original.encode()).hexdigest(),
                "source_license": "source-specific-public-terms",
                "source_terms_url": source["terms"],
                "registrable_domain": "",
                "domain_group_id": "",
                "campaign_group_id": "",
                "source_cluster_id": f"benign:{source['slug']}",
                "url_family_id": "",
                "status": "UNRESOLVED",
                "syntax_valid": True,
                "parse_error": None,
                "brand_target": "",
                "domain_category": source["category"],
                "is_demo_fixture": False,
            }
        )
    return records, {
        "source_name": source["name"],
        "endpoint": source["robots"],
        "retrieved_at_utc": collected_at,
        "snapshot_sha256": hashlib.sha256("".join(snapshot_hashes).encode()).hexdigest(),
        "raw_path": str(robots_path.parent),
        "row_count": len(records),
        "license": "source-specific-public-terms",
        "terms_url": source["terms"],
        "sitemaps_discovered": sitemap_candidates,
    }


def collect_direct_benign(raw_dir: Path, collected_at: str) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    snapshot = json.dumps(DIRECT_BENIGN_SOURCES, sort_keys=True, separators=(",", ":")).encode()
    snapshot_hash = sha256_bytes(snapshot)
    raw_path = raw_dir / "benign" / "official_domain_registry.json"
    raw_path.parent.mkdir(parents=True, exist_ok=True)
    raw_path.write_bytes(snapshot)
    records = []
    source_bodies: dict[str, bytes] = {}

    def source_domain(url: str) -> str:
        host = (urllib.parse.urlsplit(url).hostname or "").lower().rstrip(".")
        labels = [label for label in host.split(".") if label]
        return ".".join(labels[-2:]) if len(labels) >= 2 else host

    def add_record(index: int, name: str, url: str, category: str, endpoint: str, record_suffix: str) -> None:
        canonical = canonicalize_url(url)
        valid, parse_error = parse_url_status(canonical)
        records.append(
            {
                "record_id": f"official-registry-{index}-{record_suffix}-{hashlib.sha256(url.encode()).hexdigest()[:16]}",
                "original_url": url,
                "canonical_url": canonical,
                "label": "BENIGN",
                "label_rationale": "Manually verified official institutional, developer, media, or commerce domain included in the new Sentinel benign-source registry; no threat destination was contacted.",
                "threat_category": [],
                "source_name": name,
                "source_endpoint": endpoint,
                "source_record_id": f"official-domain-{index}-{record_suffix}",
                "source_tags": [],
                "corroborating_sources": [],
                "collection_timestamp_utc": collected_at,
                "source_snapshot_sha256": hashlib.sha256(source_bodies.get(endpoint, snapshot)).hexdigest(),
                "source_record_sha256": hashlib.sha256(url.encode()).hexdigest(),
                "source_license": "source-specific-public-terms",
                "source_terms_url": canonical,
                "registrable_domain": "",
                "domain_group_id": "",
                "campaign_group_id": "",
                "source_cluster_id": "benign:official_domain_registry_v1",
                "url_family_id": "",
                "status": "UNRESOLVED",
                "syntax_valid": valid,
                "parse_error": parse_error,
                "brand_target": "",
                "domain_category": category,
                "is_demo_fixture": False,
            }
        )
    for index, (name, url, category) in enumerate(DIRECT_BENIGN_SOURCES):
        add_record(index, name, url, category, url, "root")
        try:
            body = fetch(url)
            source_bodies[url] = body
            raw_path = raw_dir / "benign" / f"official_{index}.html"
            raw_path.write_bytes(body)
            hrefs = re.findall(r"(?i)href\s*=\s*[\"']([^\"']+)", body.decode("utf-8", "replace"))
            seen_links: set[str] = set()
            for link_index, href in enumerate(hrefs):
                linked = urllib.parse.urljoin(url, href).split("#", 1)[0]
                if not linked.startswith(("http://", "https://")):
                    continue
                if source_domain(linked) != source_domain(url):
                    continue
                linked = canonicalize_url(linked)
                if linked in seen_links or linked == canonicalize_url(url):
                    continue
                seen_links.add(linked)
                add_record(index, name, linked, category, url, f"homepage-link-{link_index}")
                if len(seen_links) >= 8:
                    break
        except Exception:
            continue
    return records, {
        "source_name": "Official benign domain registry",
        "endpoint": "official_domain_registry_v1",
        "retrieved_at_utc": collected_at,
        "snapshot_sha256": snapshot_hash,
        "raw_path": str(raw_path),
        "row_count": len(records),
        "license": "source-specific-public-terms",
        "terms_url": "source-specific",
    }


def deduplicate(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_url: dict[str, dict[str, Any]] = {}
    for record in records:
        key = record["canonical_url"]
        existing = by_url.get(key)
        if existing is None:
            by_url[key] = record
            continue
        if existing["label"] != record["label"]:
            existing["label"] = "UNKNOWN"
            existing["label_rationale"] = "Conflicting labels across independent source records; quarantined."
            existing["status"] = "UNKNOWN"
        existing["corroborating_sources"] = sorted(set(existing.get("corroborating_sources", [])) | {record["source_name"]})
        existing["source_tags"] = sorted(set(existing.get("source_tags", [])) | set(record.get("source_tags", [])))
    return list(by_url.values())


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--benign-cap", type=int, default=750)
    args = parser.parse_args()
    collected_at = utc_now()
    args.output.mkdir(parents=True, exist_ok=True)
    all_records: list[dict[str, Any]] = []
    registry: list[dict[str, Any]] = []

    for collector in (read_tweetfeed, read_phishunt):
        records, metadata = collector(args.output, collected_at)
        all_records.extend(records)
        registry.append(metadata)
    for source in BENIGN_SOURCES:
        try:
            records, metadata = collect_benign(source, args.output, collected_at, args.benign_cap)
        except Exception as exc:
            metadata = {
                "source_name": source["name"],
                "endpoint": source["robots"],
                "retrieved_at_utc": collected_at,
                "status": "UNAVAILABLE",
                "error": repr(exc),
            }
            records = []
        all_records.extend(records)
        registry.append(metadata)
    records, metadata = collect_direct_benign(args.output, collected_at)
    all_records.extend(records)
    registry.append(metadata)

    records = deduplicate(all_records)
    write_jsonl(args.output / "fresh_url_records.jsonl", records)
    (args.output / "source_registry.json").write_text(
        json.dumps(
            {
                "schema_version": SCHEMA_VERSION,
                "collection_timestamp_utc": collected_at,
                "target_fetch_performed": False,
                "dns_resolution_performed": False,
                "sources": registry,
                "record_count_before_deduplication": len(all_records),
                "record_count_after_deduplication": len(records),
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    print(json.dumps({"records": len(records), "sources": registry}, indent=2))


if __name__ == "__main__":
    main()
