from pathlib import Path
import sys
sys.path.insert(0, "scripts")
from v7_features import _registrable_label, _brand_impersonation_score, COMMON_BRANDS

test_hosts = [
    "www.gov.uk", "gov.uk", "news.bbc.co.uk", "bbc.co.uk", "www.amazon.com",
    "arstechnica.com", "blogger.com", "epicgames.com", "mozilla.org", "developer.mozilla.org"
]

print("COMMON_BRANDS contains:")
for h in test_hosts:
    lbl = _registrable_label(h)
    print(f"Host: {h:<30} -> Registrable Label: {lbl:<15} In COMMON_BRANDS: {lbl in COMMON_BRANDS}")
