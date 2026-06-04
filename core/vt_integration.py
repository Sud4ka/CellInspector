import json
import os
import time
from typing import Optional
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError

from core.display import console

VT_API_KEY = os.environ.get("VT_API_KEY", "")
VT_BASE = "https://www.virustotal.com/api/v3"

_last_request_time = 0
_MIN_INTERVAL = 15.0


def _rate_limit():
    global _last_request_time
    now = time.time()
    elapsed = now - _last_request_time
    if elapsed < _MIN_INTERVAL:
        wait = _MIN_INTERVAL - elapsed
        time.sleep(wait)
    _last_request_time = time.time()


def _vt_request(path: str) -> Optional[dict]:
    global _last_request_time
    if not VT_API_KEY:
        return None
    _rate_limit()
    url = f"{VT_BASE}/{path}"
    try:
        req = Request(url, headers={"x-apikey": VT_API_KEY, "User-Agent": "CellInspector/1.0"})
        with urlopen(req, timeout=20) as resp:
            return json.loads(resp.read())
    except HTTPError as e:
        if e.code == 404:
            return None
        if e.code == 429:
            console.print("[yellow]VT rate limit hit. Waiting 60s...[/]")
            time.sleep(60)
            return _vt_request(path)
        return None
    except (URLError, OSError, json.JSONDecodeError):
        return None


def lookup_hash(file_hash: str) -> Optional[dict]:
    if not VT_API_KEY:
        return None
    result = _vt_request(f"files/{file_hash}")
    if not result:
        return None
    data = result.get("data", {})
    attributes = data.get("attributes", {})
    stats = attributes.get("last_analysis_stats", {})
    names = attributes.get("names", [])
    meaning = attributes.get("meaningful_name", "")
    return {
        "hash": file_hash,
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "harmless": stats.get("harmless", 0),
        "undetected": stats.get("undetected", 0),
        "total": sum(stats.values()),
        "names": names[:5],
        "meaningful_name": meaning,
    }


def format_vt_result(data: Optional[dict]) -> str:
    if data is None:
        return ""
    malicious = data["malicious"]
    total = data["total"]
    if malicious > 0:
        return f"[red]\u2622 {malicious}/{total} VT[/]"
    return f"[green]\u2713 0/{total} VT[/]"


def check_vt_api_key() -> bool:
    if not VT_API_KEY:
        return False
    result = _vt_request("api/usage")
    return result is not None
