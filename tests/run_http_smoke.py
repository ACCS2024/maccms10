#!/usr/bin/env python3
"""Exercise actual frontend/API actions and require fixture content in their responses."""
from pathlib import Path
import os
import subprocess
import sys

root = Path(__file__).resolve().parents[1]
php = os.environ.get("PHP_BINARY", "php")
cases = [
    ("index", "/", "AuditFixture"),
    ("index", "/vod/type/id/6.html", 'data-list-mode="ajax"'),
    ("index", "/vod/detail/id/1.html", "CI Smoke Vod"),
    ("index", "/vod/play/id/1/sid/1/nid/1.html", "CI Smoke Vod"),
    ("index", "/vod/search.html?wd=CI", "CI Smoke Vod"),
    ("index", "/art/detail/id/1.html", "CI Smoke Art"),
    ("index", "/actor/detail/id/1.html", 'data-detail-id="1"'),
    ("index", "/topic/detail/id/1.html", 'data-detail-id="1"'),
    ("api", "/type/get_list", '"code":1'),
    ("api", "/vod/get_list", "CI Smoke Vod"),
    ("api", "/vod/get_detail?vod_id=1", "CI Smoke Vod"),
    ("api", "/vod/suggest?wd=CI", "CI Smoke Vod"),
    ("api", "/art/get_list", "CI Smoke Art"),
    ("api", "/actor/get_list", "CI Actor"),
    ("api", "/actor/get_detail?actor_id=1", "CI Actor"),
    ("api", "/topic/get_list", "CI Topic"),
    ("api", "/topic/get_detail?topic_id=1", "CI Topic"),
    ("api", "/config/get_config", '"code":1'),
    ("api", "/provide/vod?at=json&ac=list", "CI Smoke Vod"),
]
failed = 0
for app, url, text in cases:
    result = subprocess.run([php, str(root / "tests/http_smoke.php"), app, url, "200", text], cwd=root, timeout=45)
    failed += result.returncode != 0
# The checker must continue rejecting a wrong body contract and an empty index action.
for app, url, text in [("api", "/provide/vod?at=json&ac=list", "MISSING-FIXTURE-MARKER"), ("api", "/vod", "")]:
    result = subprocess.run([php, str(root / "tests/http_smoke.php"), app, url, "200", text], cwd=root, timeout=45)
    if result.returncode != 1:
        print("FAIL: HTTP negative control did not produce exit 1", file=sys.stderr)
        failed += 1
print(f"HTTP fixture: {len(cases)} positive routes, 2 negative controls, {failed} failures.")
sys.exit(1 if failed else 0)
