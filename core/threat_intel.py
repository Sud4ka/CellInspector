"""
core/threat_intel.py

Unified threat-intelligence clients for CellInspector.

Each IntelSource:
    * exposes a stable name and a simple `fetch(query, **kwargs) -> list[IntelItem]`
    * degrades gracefully on failure (returns [] and logs once)
    * caches results in-process to avoid hammering public APIs
    * requires nothing but stdlib (urllib) — matches the rest of the project

Sources implemented:
    * GitHubCodeIntel    — /search/code  (PoC code, requires GITHUB_TOKEN)
    * GitHubRepoIntel    — /search/repositories (general PoC repos)
    * NvdCveIntel        — NVD CVE 2.0 (official CVEs, optional NVD_API_KEY)
    * CisaKevIntel       — CISA Known Exploited Vulnerabilities catalog
    * ExploitDbIntel     — Exploit-DB public CSV from GitLab mirror
    * RedditJsonIntel    — Reddit .json search endpoint (no auth)

The deep-scan entry-point `run_deep_intel(...)` fans out to all enabled sources
in parallel (ThreadPoolExecutor) and returns the merged result list.
"""

import csv
import io
import json
import os
import re
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field, asdict
from typing import Iterable, List, Optional
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError

from core.display import console


DEFAULT_TIMEOUT = 15
USER_AGENT = "CellInspector/1.2 (+https://github.com/Sud4ka/CellInspector)"


@dataclass
class IntelItem:
    title: str
    url: str
    snippet: str = ""
    source: str = ""
    published: str = ""
    extra: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)


def _http_get(url: str, headers: Optional[dict] = None, timeout: int = DEFAULT_TIMEOUT) -> Optional[bytes]:
    h = {"User-Agent": USER_AGENT, "Accept": "*/*"}
    if headers:
        h.update(headers)
    try:
        with urlopen(Request(url, headers=h), timeout=timeout) as resp:
            return resp.read()
    except (URLError, HTTPError, OSError) as e:
        console.print(f"  [dim]network error {url[:60]}... : {e.__class__.__name__}[/]")
        return None


# ---------------------------------------------------------------------------
# GitHub
# ---------------------------------------------------------------------------

class _GitHubBase:
    name = "github"
    GITHUB_API = "https://api.github.com"

    def __init__(self):
        self.token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN") or ""

    def _headers(self, accept: str = "application/vnd.github.v3+json") -> dict:
        h = {"Accept": accept}
        if self.token:
            h["Authorization"] = f"token {self.token}"
        return h

    def is_available(self) -> bool:
        return True  # works without token (just rate-limited)

    def _search(self, path: str, query: str, per_page: int = 10, accept: str = None) -> Optional[dict]:
        url = f"{self.GITHUB_API}{path}?q={urllib.parse.quote(query, safe='+')}&per_page={per_page}"
        data = _http_get(url, headers=self._headers(accept or "application/vnd.github.v3+json"))
        if not data:
            return None
        try:
            return json.loads(data)
        except json.JSONDecodeError:
            return None


class GitHubCodeIntel(_GitHubBase):
    """Searches actual code on GitHub. Most useful for PoC code matches.

    IMPORTANT: GitHub Code Search requires authentication.
    Without GITHUB_TOKEN the endpoint returns 404.
    """

    name = "github_code"

    def is_available(self) -> bool:
        return bool(self.token)

    def fetch(self, query: str, per_page: int = 8) -> List[IntelItem]:
        if not self.token:
            return []
        path = "/search/code"
        data = self._search(
            path, query, per_page=per_page,
            accept="application/vnd.github.v3.text-match+json",
        )
        items: List[IntelItem] = []
        if not data:
            return items
        for it in data.get("items", []):
            repo = it.get("repository", {}) or {}
            repo_full = repo.get("full_name", "")
            html_url = it.get("html_url", "")
            text_matches = it.get("text_matches", [])
            snippet = ""
            if text_matches:
                snippet = " | ".join(
                    frag.get("fragment", "")[:160] for frag in text_matches[:2]
                )
            items.append(IntelItem(
                title=f"{repo_full}: {it.get('name', '')}",
                url=html_url,
                snippet=snippet,
                source="GitHub Code",
                published="",
                extra={"repo": repo_full, "path": it.get("path", "")},
            ))
        return items


class GitHubRepoIntel(_GitHubBase):
    """Repository-level search. Works without a token, but 60 req/h limit."""

    name = "github_repo"

    def fetch(self, query: str, per_page: int = 8) -> List[IntelItem]:
        data = self._search("/search/repositories", query, per_page=per_page)
        items: List[IntelItem] = []
        if not data:
            return items
        for it in data.get("items", []):
            desc = (it.get("description") or "").strip()
            if not desc:
                continue
            items.append(IntelItem(
                title=it.get("full_name", ""),
                url=it.get("html_url", ""),
                snippet=desc[:240],
                source="GitHub Repo",
                published=(it.get("updated_at") or "")[:10],
                extra={
                    "stars": it.get("stargazers_count", 0),
                    "language": it.get("language") or "",
                },
            ))
        return items


# ---------------------------------------------------------------------------
# NVD
# ---------------------------------------------------------------------------

class NvdCveIntel:
    """NVD CVE 2.0 API.

    Without NVD_API_KEY: 5 req / 30 s
    With    NVD_API_KEY: 50 req / 30 s
    Docs: https://nvd.nist.gov/developers/vulnerabilities
    """

    name = "nvd_cve"
    NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    def __init__(self):
        self.api_key = os.environ.get("NVD_API_KEY", "")

    def is_available(self) -> bool:
        return True

    def fetch(self, query: str, per_page: int = 10) -> List[IntelItem]:
        params = {
            "keywordSearch": query,
            "resultsPerPage": str(per_page),
        }
        if self.api_key:
            params["apiKey"] = self.api_key
        url = f"{self.NVD_API}?{urllib.parse.urlencode(params)}"
        data = _http_get(url, timeout=20)
        if not data:
            return []
        try:
            blob = json.loads(data)
        except json.JSONDecodeError:
            return []
        items: List[IntelItem] = []
        for v in blob.get("vulnerabilities", []):
            cve = v.get("cve", {}) or {}
            cve_id = cve.get("id", "")
            descs = cve.get("descriptions", []) or []
            en_desc = next((d.get("value", "") for d in descs if d.get("lang") == "en"), "")
            metrics = cve.get("metrics", {}) or {}
            cvss = ""
            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                arr = metrics.get(key) or []
                if arr:
                    cvss = (arr[0].get("cvssData") or {}).get("baseScore", "")
                    break
            published = (cve.get("published") or "")[:10]
            items.append(IntelItem(
                title=cve_id,
                url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                snippet=en_desc[:280],
                source="NVD",
                published=published,
                extra={"cvss": cvss},
            ))
        return items


# ---------------------------------------------------------------------------
# CISA KEV
# ---------------------------------------------------------------------------

class CisaKevIntel:
    """CISA Known Exploited Vulnerabilities catalog.

    Static JSON, no auth, ~3 MB. We cache for 24h.
    """

    name = "cisa_kev"
    KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    CACHE_PATH = os.path.expanduser("~/.cache/cellinspector/cisa_kev.json")
    CACHE_TTL = 86400

    def __init__(self):
        self._cache: dict = {}
        self._load_cache()

    def _load_cache(self):
        try:
            if os.path.exists(self.CACHE_PATH):
                age = time.time() - os.path.getmtime(self.CACHE_PATH)
                if age < self.CACHE_TTL:
                    with open(self.CACHE_PATH, "r", encoding="utf-8") as f:
                        self._cache = json.load(f)
        except (OSError, json.JSONDecodeError):
            self._cache = {}

    def _save_cache(self):
        try:
            os.makedirs(os.path.dirname(self.CACHE_PATH), exist_ok=True)
            with open(self.CACHE_PATH, "w", encoding="utf-8") as f:
                json.dump(self._cache, f)
        except OSError:
            pass

    def _ensure_catalog(self) -> dict:
        if self._cache.get("vulnerabilities"):
            return self._cache
        raw = _http_get(self.KEV_URL, timeout=30)
        if not raw:
            return {}
        try:
            self._cache = json.loads(raw)
            self._save_cache()
        except json.JSONDecodeError:
            return {}
        return self._cache

    def is_available(self) -> bool:
        return bool(self._ensure_catalog().get("vulnerabilities"))

    def fetch(self, query: str, per_page: int = 10) -> List[IntelItem]:
        catalog = self._ensure_catalog()
        vulns = catalog.get("vulnerabilities", []) or []
        q = query.lower()
        keywords = [w for w in re.split(r"\W+", q) if len(w) > 2]
        scored = []
        for v in vulns:
            text = " ".join([
                v.get("cveID", ""),
                v.get("shortDescription", "") or v.get("vulnerabilityName", ""),
                v.get("product", ""),
                v.get("vendorProject", ""),
            ]).lower()
            score = sum(1 for kw in keywords if kw in text)
            if score == 0:
                continue
            scored.append((score, v))
        scored.sort(key=lambda x: -x[0])
        items: List[IntelItem] = []
        for score, v in scored[:per_page]:
            items.append(IntelItem(
                title=v.get("cveID", ""),
                url=f"https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve={v.get('cveID','')}",
                snippet=(v.get("shortDescription") or v.get("vulnerabilityName", ""))[:240],
                source="CISA KEV",
                published=v.get("dateAdded", ""),
                extra={
                    "vendor": v.get("vendorProject", ""),
                    "product": v.get("product", ""),
                    "required_action": v.get("requiredAction", ""),
                },
            ))
        return items


# ---------------------------------------------------------------------------
# Exploit-DB (CSV mirror)
# ---------------------------------------------------------------------------

class ExploitDbIntel:
    """Exploit-DB public CSV from the GitLab mirror.

    File is ~6 MB; we cache locally for 24 h and filter in memory.
    """

    name = "exploitdb"
    CSV_URL = "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv"
    CACHE_PATH = os.path.expanduser("~/.cache/cellinspector/exploitdb.csv")
    CACHE_TTL = 86400

    def __init__(self):
        self._rows: List[dict] = []
        self._load_cache()

    def _load_cache(self):
        try:
            if os.path.exists(self.CACHE_PATH):
                age = time.time() - os.path.getmtime(self.CACHE_PATH)
                if age < self.CACHE_TTL:
                    with open(self.CACHE_PATH, "r", encoding="utf-8", errors="replace") as f:
                        self._rows = list(csv.DictReader(f))
        except (OSError, UnicodeDecodeError):
            self._rows = []

    def _ensure_csv(self) -> List[dict]:
        if self._rows:
            return self._rows
        raw = _http_get(self.CSV_URL, timeout=30)
        if not raw:
            return []
        try:
            text = raw.decode("utf-8", errors="replace")
            self._rows = list(csv.DictReader(io.StringIO(text)))
            os.makedirs(os.path.dirname(self.CACHE_PATH), exist_ok=True)
            with open(self.CACHE_PATH, "w", encoding="utf-8") as f:
                f.write(text)
        except (OSError, csv.Error):
            return []
        return self._rows

    def is_available(self) -> bool:
        return bool(self._ensure_csv())

    def fetch(self, query: str, per_page: int = 10) -> List[IntelItem]:
        rows = self._ensure_csv()
        keywords = [w.lower() for w in re.split(r"\W+", query) if len(w) > 2]
        if not keywords:
            return []
        scored = []
        for row in rows:
            haystack = " ".join([
                row.get("description", "") or "",
                row.get("file", "") or "",
                row.get("platform", "") or "",
                row.get("type", "") or "",
                row.get("author", "") or "",
            ]).lower()
            if not all(kw in haystack for kw in keywords[:2]):
                continue
            score = sum(haystack.count(kw) for kw in keywords)
            scored.append((score, row))
        scored.sort(key=lambda x: -x[0])
        items: List[IntelItem] = []
        for _, row in scored[:per_page]:
            edb_id = row.get("id", "")
            file_ = row.get("file", "")
            url = f"https://www.exploit-db.com/exploits/{edb_id}" if edb_id else ""
            items.append(IntelItem(
                title=f"EDB-{edb_id}: {row.get('description', '').strip()[:120]}",
                url=url,
                snippet=f"{row.get('type','')} / {row.get('platform','')} - {row.get('file','')}",
                source="Exploit-DB",
                published=row.get("date_published", "") or row.get("date", ""),
                extra={"edb_id": edb_id, "author": row.get("author", "")},
            ))
        return items


# ---------------------------------------------------------------------------
# Reddit (no auth)
# ---------------------------------------------------------------------------

class RedditJsonIntel:
    """Reddit .json search endpoint. No auth, but they rate-limit ~10 req/min
    per IP aggressively. We use a short set of high-signal subreddits and a
    generous cache."""

    name = "reddit"
    DEFAULT_SUBS = ("netsec", "ReverseEngineering", "AndroidSecurity", "androiddev")

    def __init__(self, subs: Iterable[str] = DEFAULT_SUBS):
        self.subs = tuple(subs)

    def is_available(self) -> bool:
        return True

    def fetch(self, query: str, per_page: int = 8) -> List[IntelItem]:
        items: List[IntelItem] = []
        per_sub = max(1, per_page // max(1, len(self.subs)))
        for sub in self.subs:
            url = (
                f"https://www.reddit.com/r/{sub}/search.json"
                f"?q={urllib.parse.quote(query, safe='+')}"
                f"&restrict_sr=on&sort=relevance&t=year&limit={per_sub}"
            )
            raw = _http_get(url, headers={"User-Agent": USER_AGENT}, timeout=10)
            if not raw:
                continue
            try:
                blob = json.loads(raw)
            except json.JSONDecodeError:
                continue
            for child in (blob.get("data") or {}).get("children", []):
                d = child.get("data", {}) or {}
                permalink = d.get("permalink", "")
                items.append(IntelItem(
                    title=d.get("title", ""),
                    url=f"https://www.reddit.com{permalink}" if permalink else "",
                    snippet=(d.get("selftext") or "")[:200],
                    source=f"Reddit r/{sub}",
                    published=time.strftime(
                        "%Y-%m-%d", time.gmtime(d.get("created_utc", 0))
                    ) if d.get("created_utc") else "",
                    extra={"score": d.get("score", 0), "num_comments": d.get("num_comments", 0)},
                ))
            time.sleep(0.3)  # be polite
        return items


# ---------------------------------------------------------------------------
# Aggregator
# ---------------------------------------------------------------------------

ALL_SOURCES = (
    GitHubRepoIntel,    # works without token, gives the most breadth
    GitHubCodeIntel,    # requires token, gives actual PoC code
    NvdCveIntel,
    CisaKevIntel,
    ExploitDbIntel,
    RedditJsonIntel,
)


def _dedupe(items: List[IntelItem]) -> List[IntelItem]:
    seen = set()
    out: List[IntelItem] = []
    for it in items:
        key = (it.source, it.url)
        if not it.url or key in seen:
            continue
        seen.add(key)
        out.append(it)
    return out


def run_deep_intel(
    queries: List[str],
    per_source: int = 8,
    enabled: Optional[List[str]] = None,
) -> List[IntelItem]:
    """Fan out to all enabled sources in parallel for each query.

    queries     — list of dork queries (we will run them all, not just the first)
    per_source  — max items per (source, query) pair
    enabled     — optional whitelist of source names; default = all that report is_available()
    """

    sources = []
    for cls in ALL_SOURCES:
        inst = cls()
        if enabled and inst.name not in enabled:
            continue
        if not inst.is_available():
            console.print(f"  [dim]skip {inst.name} (not available)[/]")
            continue
        sources.append(inst)

    if not sources:
        console.print("  [yellow]No deep-intel sources available.[/]")
        return []

    console.print(f"  [dim]deep sources: {', '.join(s.name for s in sources)}[/]")

    all_items: List[IntelItem] = []

    def _run(src, q):
        try:
            return src.fetch(q, per_page=per_source)
        except Exception as e:
            console.print(f"  [dim]{src.name} failed: {e.__class__.__name__}[/]")
            return []

    with ThreadPoolExecutor(max_workers=max(2, len(sources) * 2)) as pool:
        futures = []
        for src in sources:
            for q in queries:
                futures.append(pool.submit(_run, src, q))
        for fut in as_completed(futures):
            try:
                all_items.extend(fut.result() or [])
            except Exception:
                continue

    return _dedupe(all_items)


def build_dorks(device_info: dict) -> List[str]:
    """Build a comprehensive set of dork queries for the device.

    Unlike the previous version, we do NOT slice `keywords[:1]`. Every keyword
    is combined with every language-specific dork template.
    """

    model = (device_info.get("Model") or "").strip()
    product = (device_info.get("Product Name") or "").strip()
    manufacturer = (device_info.get("Manufacturer") or "").strip()
    android_ver = (device_info.get("Android Version") or "").strip()

    def _clean(s: str) -> str:
        return re.sub(r"[^a-zA-Z0-9]+", " ", s).strip()

    keywords: List[str] = []
    if android_ver:
        keywords.append(f"android {android_ver}")
    for raw in (model, product, manufacturer):
        c = _clean(raw)
        if c and c.lower() not in (k.lower() for k in keywords):
            keywords.append(c)

    suffixes = [
        "exploit poc",
        "CVE poc",
        "kernel exploit",
        "root exploit",
        "0day poc",
        "privilege escalation",
        "android rce",
        "use after free android",
    ]
    queries: List[str] = []
    for kw in keywords:
        for s in suffixes:
            queries.append(f"{kw} {s}")
    return queries
