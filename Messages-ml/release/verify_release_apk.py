from pathlib import Path
import hashlib, json, sys, zipfile

base=Path(__file__).resolve().parent
manifest=json.loads((base/"SENTINEL_MESSAGE_RELEASE_MANIFEST.json").read_text(encoding="utf-8"))
apk=Path(sys.argv[1]) if len(sys.argv)>1 else base/manifest["apk_path"].split("release/",1)[-1]
if not apk.is_absolute(): apk=(base/apk).resolve()
actual=hashlib.sha256(apk.read_bytes()).hexdigest()
assert actual==manifest["apk_sha256"], f"APK hash mismatch: {actual}"
with zipfile.ZipFile(apk) as z:
    for name,digest in manifest["android_asset_hashes"].items():
        data=z.read("assets/"+name)
        got=hashlib.sha256(data).hexdigest()
        assert got==digest, f"Asset hash mismatch for {name}: {got}"
    legacy=[n for n in z.namelist() if n.startswith("assets/") and ("messages_v4_4" in n or "champion_v2_" in n)]
    assert not legacy, f"Unexpected legacy message assets: {legacy}"
print("PASS: APK and declared asset SHA-256 hashes verified")
