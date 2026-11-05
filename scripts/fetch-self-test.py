#!/usr/bin/env python3
"""Fetch the same pinned workload image for Linux and Windows builds."""
import hashlib
from pathlib import Path
import urllib.request

root = Path(__file__).resolve().parents[1]
path = root / "build/guest/self-test.gvmi"
path.parent.mkdir(parents=True, exist_ok=True)
url = "https://github.com/golemfactory/ya-self-test-img/releases/download/v0.1.4/self-test.gvmi"
with urllib.request.urlopen(url, timeout=60) as response:
    data = response.read()
if hashlib.sha256(data).hexdigest() != "c957b25eefe1870adc7ac7e18cd012fbd0e30bede3b6730cf67e21a5ee5dbfe8":
    raise SystemExit("Self-test image checksum verification failed")
if data[:4] != b"hsqs":
    raise SystemExit("Downloaded self-test image is not squashfs")
path.write_bytes(data)
print(f"Self-test image: {path}")
