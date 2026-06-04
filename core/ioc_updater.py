import json
import os
import time
import urllib.parse
from typing import Optional
from urllib.request import Request, urlopen
from urllib.error import URLError

from core.display import console

DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")
IOCS_FILE = os.path.join(DATA_DIR, "iocs.json")

MALWAREBAZAAR_URL = "https://mb-api.abuse.ch/api/v1/"
CISA_KNOWN_EXPLOITED = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

MB_API_KEY = os.environ.get("MB_API_KEY", "")
OTX_API_KEY = os.environ.get("OTX_API_KEY", "")


def _ensure_data_dir():
    os.makedirs(DATA_DIR, exist_ok=True)


def _fetch_json(url: str, data: Optional[dict] = None, form: bool = False, headers: Optional[dict] = None, timeout: int = 30) -> Optional[dict]:
    try:
        req_headers = {"User-Agent": "CellInspector/1.0"}
        if headers:
            req_headers.update(headers)
        if data:
            if form:
                body = urllib.parse.urlencode(data).encode()
                req = Request(url, data=body, headers={**req_headers, "Content-Type": "application/x-www-form-urlencoded"})
            else:
                body = json.dumps(data).encode()
                req = Request(url, data=body, headers={**req_headers, "Content-Type": "application/json"})
        else:
            req = Request(url, headers=req_headers)
        with urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read())
    except (URLError, json.JSONDecodeError, OSError) as e:
        console.print(f"[red]Error fetching {url}: {e}[/]")
        return None


def _fetch_malwarebazaar() -> dict:
    merged = {"packages": [], "hashes": [], "domains": [], "ips": []}
    if not MB_API_KEY:
        console.print("[yellow]  Skipping MalwareBazaar (set MB_API_KEY env var)[/]")
        return merged

    console.print("[cyan]Fetching MalwareBazaar recent Android malware...[/]")
    payload = {"query": "get_recent", "selector": "time", "limit": 100}
    headers = {"API-KEY": MB_API_KEY}
    result = _fetch_json(MALWAREBAZAAR_URL, data=payload, form=True, headers=headers)
    if not result or result.get("query_status") != "ok":
        console.print("[yellow]  MalwareBazaar returned no data.[/]")
        return merged

    samples = result.get("data", [])
    android_count = 0
    for sample in samples:
        tags = [t.lower() for t in sample.get("tags", [])]
        file_type = (sample.get("file_type_mime", "") or "").lower()
        if "android" not in tags and "apk" not in file_type:
            continue
        android_count += 1
        sha256 = sample.get("sha256_hash", "").lower()
        if sha256 and sha256 not in merged["hashes"]:
            merged["hashes"].append(sha256)
        signatures = sample.get("signature", "") or ""
        if signatures:
            for sig in signatures.split(","):
                sig = sig.strip().lower().replace(" ", ".").replace("_", ".")
                if sig and sig not in merged["packages"] and len(sig) > 5:
                    merged["packages"].append(sig)

    console.print(f"[green]  Found {android_count} Android samples, {len(merged['hashes'])} hashes[/]")
    return merged


def _fetch_alienvault_otx() -> dict:
    merged = {"packages": [], "hashes": [], "domains": [], "ips": []}
    if not OTX_API_KEY:
        console.print("[yellow]  Skipping AlienVault OTX (set OTX_API_KEY env var)[/]")
        return merged

    console.print("[cyan]Fetching AlienVault OTX Android pulses...[/]")
    url = "https://otx.alienvault.com/api/v1/pulses/subscribed?page=1&limit=20"
    result = _fetch_json(url, headers={"X-OTX-API-KEY": OTX_API_KEY})
    if not result:
        console.print("[yellow]  OTX returned no data.[/]")
        return merged

    pulses = result.get("results", [])
    android_count = 0
    for pulse in pulses:
        tags = [t.lower() for t in pulse.get("tags", [])]
        name_lower = pulse.get("name", "").lower()
        if "android" not in tags and "android" not in name_lower and "mobile" not in name_lower:
            continue
        android_count += 1
        for indicator in pulse.get("indicators", []):
            ioc_type = indicator.get("type", "")
            content = indicator.get("indicator", "")
            if ioc_type == "SHA256" and content:
                if content not in merged["hashes"]:
                    merged["hashes"].append(content.lower())
            elif ioc_type in ("domain", "hostname") and content:
                if content not in merged["domains"]:
                    merged["domains"].append(content)
            elif ioc_type == "IPv4" and content:
                if content not in merged["ips"]:
                    merged["ips"].append(content)

    console.print(f"[green]  Found {android_count} Android pulses, {len(merged['hashes'])} hashes[/]")
    return merged


def _fetch_cisa_feed() -> dict:
    console.print("[cyan]Fetching CISA Known Exploited Vulnerabilities...[/]")
    merged = {"cves": []}

    result = _fetch_json(CISA_KNOWN_EXPLOITED)
    if not result:
        return merged

    vulns = result.get("vulnerabilities", [])
    for v in vulns:
        if "android" in json.dumps(v).lower():
            merged["cves"].append({
                "cve": v.get("cveID", ""),
                "vendor": v.get("vendorProject", ""),
                "product": v.get("product", ""),
                "date_added": v.get("dateAdded", ""),
                "description": v.get("shortDescription", ""),
            })

    console.print(f"[green]  Found {len(merged['cves'])} Android-related CVEs[/]")
    return merged


def load_dynamic_iocs() -> dict:
    if not os.path.exists(IOCS_FILE):
        return {}
    try:
        with open(IOCS_FILE, "r") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return {}


def save_iocs(data: dict):
    _ensure_data_dir()
    existing = load_dynamic_iocs()
    for key in ("hashes", "packages", "domains", "ips"):
        existing_set = set(existing.get(key, []))
        new_set = set(data.get(key, []))
        existing[key] = sorted(existing_set | new_set)
    if "cves" in data:
        existing_cves = {c["cve"] for c in existing.get("cves", [])}
        for cve in data["cves"]:
            if cve["cve"] not in existing_cves:
                existing.setdefault("cves", []).append(cve)
    existing["last_updated"] = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())
    existing["source_count"] = len(existing.get("hashes", [])) + len(existing.get("cves", []))
    with open(IOCS_FILE, "w") as f:
        json.dump(existing, f, indent=2)
    return existing


def run_update_iocs():
    console.print("\n[bold cyan]\U0001f504 Updating IOC Database[/]")
    console.print("[dim]Fetching threat intelligence feeds...[/]\n")

    mb_data = _fetch_malwarebazaar()
    otx_data = _fetch_alienvault_otx()
    cisa_data = _fetch_cisa_feed()

    merged = {}
    for d in (mb_data, otx_data, cisa_data):
        for k, v in d.items():
            if isinstance(v, list):
                merged.setdefault(k, []).extend(v)
            else:
                merged.setdefault(k, v)

    result = save_iocs(merged)
    total_hashes = len(result.get("hashes", []))
    total_packages = len(result.get("packages", []))
    total_cves = len(result.get("cves", []))
    total_domains = len(result.get("domains", []))
    total_ips = len(result.get("ips", []))

    console.print(f"\n[bold green]\u2705 IOC update complete![/]")
    console.print(f"  \u2022 [cyan]{total_hashes}[/] malware hashes")
    console.print(f"  \u2022 [cyan]{total_packages}[/] package names")
    console.print(f"  \u2022 [cyan]{total_domains}[/] malicious domains")
    console.print(f"  \u2022 [cyan]{total_ips}[/] malicious IPs")
    console.print(f"  \u2022 [cyan]{total_cves}[/] Android-related CVEs")
    console.print(f"  \u2022 Last updated: {result.get('last_updated', '?')}")
    console.print(f"\n[dim]IOCs saved to: {IOCS_FILE}[/]")
    console.print("[dim]Set MB_API_KEY and/or OTX_API_KEY env vars for more complete feeds[/]")


def get_dynamic_packages() -> list:
    data = load_dynamic_iocs()
    return data.get("packages", [])


def get_dynamic_hashes() -> list:
    data = load_dynamic_iocs()
    return data.get("hashes", [])


def get_dynamic_cves() -> list:
    data = load_dynamic_iocs()
    return data.get("cves", [])


def get_dynamic_domains() -> list:
    data = load_dynamic_iocs()
    return data.get("domains", [])


def get_dynamic_ips() -> list:
    data = load_dynamic_iocs()
    return data.get("ips", [])
