"""
modules/zero_day_checker.py

Zero-Day / PoC scanner for CellInspector.

Sources
=======

* Base scan (always run when internet is available):
    - GitHubRepoIntel   — repository-level search for PoC repos

* Deep scan (only with --deep):
    - GitHubCodeIntel   — /search/code, finds the actual PoC code
                          (requires GITHUB_TOKEN; gracefully skipped otherwise)
    - NvdCveIntel       — NVD CVE 2.0 with the device's keywords
    - CisaKevIntel      — actively-exploited CVE catalog (filtered by query)
    - ExploitDbIntel    — Exploit-DB public CSV (downloaded once and cached)
    - RedditJsonIntel   — Reddit r/netsec, r/ReverseEngineering,
                          r/AndroidSecurity, r/androiddev via .json endpoint

Why we no longer scrape DuckDuckGo HTML
=======================================

DuckDuckGo's HTML endpoint has been returning CAPTCHA or empty pages for
years. The previous deep scan relied on it and almost always produced
zero results. v1.2.0 replaces the HTML scraper with five structured
sources that all have public, documented endpoints and a sensible rate
limit (which we respect).
"""

import re
import time
from typing import List, Optional, Set

from core.display import console
from core.adb_client import get_device_info
from core.severity import Severity
from core.threat_intel import (
    GitHubRepoIntel,
    run_deep_intel,
    build_dorks,
    IntelItem,
)


# ---------------------------------------------------------------------------
# Relevance scoring for the noisy GitHub repo feed.
# ---------------------------------------------------------------------------

_RELEVANT_KW = [
    "cve", "exploit", "poc", "rce", "root", "privilege escalation",
    "vulnerability", "buffer overflow", "use after free", "uaf",
    "heap overflow", "integer overflow", "out of bounds",
    "arbitrary code", "memory corruption", "denial of service",
    "elevation of privilege", "information disclosure",
    "bypass", "sandbox escape", "kernel exploit",
    "bootloader unlock", "oem unlock", "firmware",
    "0day", "zero day", "0-day",
    "malware", "trojan", "backdoor", "spyware", "rat",
    "reverse shell", "code execution",
]


def _repo_relevance(repo: IntelItem, device_info: dict) -> int:
    text = f"{repo.title} {repo.snippet}".lower()
    score = sum(1 for kw in _RELEVANT_KW if kw in text)
    model = (device_info.get("Model") or "").lower()
    product = (device_info.get("Product Name") or "").lower()
    android_ver = (device_info.get("Android Version") or "").lower()
    if model and model in text:
        score += 3
    if product and product in text:
        score += 2
    if android_ver and android_ver in text:
        score += 2
    if "android" in text:
        score += 1
    return score


def _is_relevant_repo(repo: IntelItem, device_info: dict, threshold: int = 2) -> bool:
    return _repo_relevance(repo, device_info) >= threshold


# ---------------------------------------------------------------------------
# GitHub repo search (base scan)
# ---------------------------------------------------------------------------

def _fetch_github_repos(device_info: dict) -> List[IntelItem]:
    src = GitHubRepoIntel()
    queries = build_dorks(device_info)[:12]  # 12 dorks for the base scan
    if not queries:
        return []
    all_items: List[IntelItem] = []
    seen = set()
    for q in queries:
        try:
            results = src.fetch(q, per_page=8)
        except Exception as e:
            console.print(f"  [dim]github_repo error: {e}[/]")
            continue
        for it in results:
            if it.url in seen:
                continue
            seen.add(it.url)
            all_items.append(it)
        if len(all_items) >= 40:
            break
        time.sleep(0.4)  # respect the 60 req/h unauthenticated limit
    # sort by stars descending (a coarse relevance signal)
    all_items.sort(key=lambda r: -int(r.extra.get("stars", 0)))
    return all_items


# ---------------------------------------------------------------------------
# Display
# ---------------------------------------------------------------------------

def _display_github_repos(repos: List[IntelItem], title: str = "GitHub PoC Repositories") -> None:
    if not repos:
        console.print(f"[bold green]\u2705 {title}: no relevant repositories found.[/]")
        return

    from rich.panel import Panel
    from rich import box

    console.print(f"\n[bold red]\U0001f6a8 {len(repos)} relevant repos[/]\n")
    for i, repo in enumerate(repos[:8], 1):
        stars = int(repo.extra.get("stars", 0) or 0)
        lang = repo.extra.get("language", "")
        stars_str = f"  \u2b50 {stars}" if stars else ""
        lang_str = f"  \U0001f4c1 {lang}" if lang else ""
        panel = Panel(
            f"[bold cyan]{repo.title}[/]\n"
            f"[dim]{repo.snippet[:160]}[/]\n\n"
            f"[link={repo.url}]\U0001f517 {repo.url}[/]\n"
            f"[yellow]{stars_str}[/]{lang_str}  [dim]\U0001f4c5 {repo.published}[/]",
            title=f"[bold red]GitHub PoC #{i}[/]",
            border_style="red",
            box=box.ROUNDED,
            padding=(1, 2),
        )
        console.print(panel)
        console.print()


def _display_deep_results(items: List[IntelItem]) -> None:
    if not items:
        console.print("\n[bold yellow]\U0001f50d Deep scan: no results from any source.[/]")
        return

    from collections import defaultdict
    from rich.panel import Panel
    from rich import box

    by_source: dict = defaultdict(list)
    for it in items:
        by_source[it.source].append(it)

    console.print(f"\n[bold magenta]\U0001f4e1 Deep Scan Results ({len(items)} total, "
                  f"{len(by_source)} source(s))[/]\n")

    color_for = {
        "GitHub Code": "red",
        "GitHub Repo": "red",
        "NVD":         "orange_red1",
        "CISA KEV":    "red",
        "Exploit-DB":  "orange1",
    }
    default_color = "cyan"
    sub_color_for = {
        "Reddit r/netsec":             "orange1",
        "Reddit r/ReverseEngineering": "magenta",
        "Reddit r/AndroidSecurity":    "yellow",
        "Reddit r/androiddev":         "blue",
    }

    # Non-Reddit sources first
    priority = ("CISA KEV", "NVD", "Exploit-DB", "GitHub Code", "GitHub Repo")
    ordered = []
    for p in priority:
        if p in by_source:
            ordered.append((p, by_source.pop(p)))
    for k, v in by_source.items():
        ordered.append((k, v))

    for source, group in ordered:
        color = color_for.get(source) or sub_color_for.get(source) or default_color
        console.print(f"[bold {color}]\u25b8 {source} ({len(group)})[/]")
        for i, it in enumerate(group[:5], 1):
            snippet = f"\n[dim]{it.snippet[:160]}[/]" if it.snippet else ""
            cvss = it.extra.get("cvss", "")
            cvss_str = f"  [bold red]CVSS {cvss}[/]" if cvss else ""
            edb_id = it.extra.get("edb_id", "")
            edb_str = f"  [bold]EDB-{edb_id}[/]" if edb_id else ""
            cve_id = it.title if source == "NVD" else ""
            cve_str = f"  [bold]{cve_id}[/]" if cve_id else ""
            extra = " ".join(filter(None, [cve_str, cvss_str, edb_str]))
            extra_line = f"\n  {extra}" if extra else ""
            url_line = f"\n  [link={it.url}]\U0001f517 {it.url}[/]" if it.url else ""
            panel = Panel(
                f"[bold]{it.title}[/]{snippet}{extra_line}{url_line}",
                title=f"{source} #{i}",
                border_style=color,
                box=box.ROUNDED,
                padding=(1, 2),
            )
            console.print(panel)
            console.print()


# ---------------------------------------------------------------------------
# Entry points
# ---------------------------------------------------------------------------

def check_zero_days(device_info: Optional[dict] = None) -> List[IntelItem]:
    """Lightweight entry point used by `run_scan()`: returns relevant repos."""
    if device_info is None:
        device_info = get_device_info()
    repos = _fetch_github_repos(device_info)
    if not repos:
        return []
    return [r for r in repos if _is_relevant_repo(r, device_info)]


def run_zero_day_check(deep: bool = False, offline: bool = False) -> None:
    console.print("\n[bold cyan]\U0001f50d Zero-Day / PoC Scanner[/]")
    console.print("[dim]Looking for active exploits and CVEs relevant to your device...[/]\n")

    device_info = get_device_info()
    console.print(f"  [cyan]\u2022 Model:[/] {device_info.get('Model', 'Unknown')}")
    console.print(f"  [cyan]\u2022 Android:[/] {device_info.get('Android Version', 'Unknown')}\n")

    # --- Base scan: GitHub repo search -------------------------------------
    repos = _fetch_github_repos(device_info)
    relevant = [r for r in repos if _is_relevant_repo(r, device_info)]
    display_repos = relevant if relevant else (repos[:3] if repos else [])
    _display_github_repos(display_repos)

    if not deep:
        console.print("\n[dim]\u26a0\ufe0f Always verify PoC code before running it on your device.[/]")
        console.print("[dim]CellInspector does not endorse or guarantee any of these exploits.[/]")
        console.print("[dim]Tip: use --deep for NVD, CISA KEV, Exploit-DB, GitHub Code and Reddit.[/]")
        return

    # --- Deep scan ---------------------------------------------------------
    if offline:
        console.print("\n[yellow]--offline set: skipping deep-scan sources that require "
                      "internet (NVD, CISA KEV, Exploit-DB, Reddit).[/]")
        console.print("\n[dim]\u26a0\ufe0f Always verify PoC code before running it on your device.[/]")
        return

    queries = build_dorks(device_info)
    if not queries:
        console.print("[yellow]No search keywords derived from device info.[/]")
        return

    console.print(f"  [dim]Building {len(queries)} dork queries from device info...[/]")
    items = run_deep_intel(queries, per_source=8)
    _display_deep_results(items)

    console.print("\n[dim]\u26a0\ufe0f Always verify PoC code before running it on your device.[/]")
    console.print("[dim]CellInspector does not endorse or guarantee any of these exploits.[/]")
