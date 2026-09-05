#!/usr/bin/env python3
"""Build-time DB-IP snapshot acquisition and verified packaging. Never imported by the app."""
from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import re
import shutil
import tempfile
from pathlib import Path
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[1]
LOCK_PATH = ROOT / "scripts" / "geoip-lock.json"
CACHE = ROOT / ".cache" / "geoip"
SOURCE_PAGE = "https://db-ip.com/db/download/ip-to-country-lite"
ATTRIBUTION = "IP Geolocation by DB-IP (https://db-ip.com). DB-IP Country Lite, CC BY 4.0 (https://creativecommons.org/licenses/by/4.0/).\n"


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def fetch(url, destination):
    request = Request(url, headers={"User-Agent": "ZapretKVN-build/1"})
    with urlopen(request, timeout=90) as response, destination.open("wb") as target:
        shutil.copyfileobj(response, target)


def verify_database(path):
    import maxminddb
    codes = set()
    with maxminddb.open_database(str(path)) as reader:
        if reader.metadata().ip_version != 6:
            raise ValueError("GeoIP snapshot must support IPv4 and IPv6")
        for _network, record in reader:
            code = (record.get("country") or {}).get("iso_code", "")
            if not re.fullmatch("[A-Z]{2}", code):
                raise ValueError("Invalid country record in GeoIP snapshot")
            if code != "ZZ":
                codes.add(code)
        if len(codes) < 100:
            raise ValueError("Incomplete GeoIP snapshot")
    return sorted(codes)


def verify_lock(lock):
    if lock.get("schema") != 1 or lock.get("provider") != "DB-IP Country Lite":
        raise ValueError("Invalid GeoIP lock")
    if not re.fullmatch(r"https://download\.db-ip\.com/free/dbip-country-lite-\d{4}-\d{2}\.mmdb\.gz", lock.get("url", "")):
        raise ValueError("Unexpected GeoIP download source")
    for key in ("archive_sha256", "sha256"):
        if not re.fullmatch("[0-9a-f]{64}", lock.get(key, "")):
            raise ValueError("Invalid GeoIP digest")


def obtain(lock):
    verify_lock(lock)
    CACHE.mkdir(parents=True, exist_ok=True)
    target = CACHE / (lock["sha256"] + ".mmdb")
    if target.exists() and digest(target) == lock["sha256"]:
        return target
    with tempfile.TemporaryDirectory(dir=CACHE) as temporary:
        archive = Path(temporary) / "country.gz"
        fetch(lock["url"], archive)
        if digest(archive) != lock["archive_sha256"]:
            raise ValueError("GeoIP archive does not match release lock")
        unpacked = Path(temporary) / "country.mmdb"
        with gzip.open(archive, "rb") as source, unpacked.open("wb") as dest:
            shutil.copyfileobj(source, dest)
        if digest(unpacked) != lock["sha256"]:
            raise ValueError("GeoIP database does not match release lock")
        verify_database(unpacked)
        unpacked.replace(target)
    return target


def refresh():
    CACHE.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=CACHE) as temporary:
        page = Path(temporary) / "index.html"
        fetch(SOURCE_PAGE, page)
        urls = re.findall(r'https://download\.db-ip\.com/free/dbip-country-lite-(\d{4}-\d{2})\.mmdb\.gz', page.read_text())
        if not urls:
            raise ValueError("Official page contains no Country Lite MMDB release")
        version = max(urls)
        url = f"https://download.db-ip.com/free/dbip-country-lite-{version}.mmdb.gz"
        archive = Path(temporary) / "country.gz"
        fetch(url, archive)
        unpacked = Path(temporary) / "country.mmdb"
        with gzip.open(archive, "rb") as source, unpacked.open("wb") as dest:
            shutil.copyfileobj(source, dest)
        codes = verify_database(unpacked)
        lock = {"schema": 1, "provider": "DB-IP Country Lite", "version": version,
                "url": url, "archive_sha256": digest(archive), "sha256": digest(unpacked),
                "size": unpacked.stat().st_size, "country_codes": codes}
        target = CACHE / (lock["sha256"] + ".mmdb")
        unpacked.replace(target)
        pending = LOCK_PATH.with_suffix(".tmp")
        pending.write_text(json.dumps(lock, indent=2) + "\n", encoding="utf-8")
        pending.replace(LOCK_PATH)
    return lock


def stage(assets_dir):
    lock = json.loads(LOCK_PATH.read_text(encoding="utf-8"))
    source = obtain(lock)
    destination = Path(assets_dir) / "geoip"
    destination.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, destination / "country.mmdb")
    (destination / "manifest.json").write_text(json.dumps(lock, indent=2) + "\n", encoding="utf-8")
    (destination / "ATTRIBUTION.txt").write_text(ATTRIBUTION, encoding="utf-8")
    verify_payload(assets_dir)
    return lock


def verify_payload(assets_dir):
    assets_dir = Path(assets_dir)
    lock = json.loads(LOCK_PATH.read_text(encoding="utf-8"))
    verify_lock(lock)
    path = assets_dir / "geoip" / "country.mmdb"
    if digest(path) != lock["sha256"]:
        raise ValueError("Packaged GeoIP database differs from lock")
    codes = verify_database(path)
    missing = [code for code in codes if not (assets_dir / "flags" / f"{code.lower()}.png").is_file()]
    if missing:
        raise ValueError("Missing real flag PNGs: " + ", ".join(missing))
    for code in codes:
        content = (assets_dir / "flags" / f"{code.lower()}.png").read_bytes()
        if len(content) < 24 or not content.startswith(b"\x89PNG\r\n\x1a\n"):
            raise ValueError("Invalid flag PNG: " + code)
    return {"version": lock["version"], "sha256": lock["sha256"], "size": path.stat().st_size}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument("--refresh", action="store_true")
    modes.add_argument("--stage", type=Path)
    modes.add_argument("--verify", type=Path)
    modes.add_argument("--check", action="store_true")
    args = parser.parse_args()
    if args.refresh:
        result = refresh()
    elif args.stage:
        result = stage(args.stage)
    elif args.verify:
        result = verify_payload(args.verify)
    else:
        result = json.loads(LOCK_PATH.read_text(encoding="utf-8"))
        verify_lock(result)
    print(json.dumps(result))


if __name__ == "__main__":
    main()
