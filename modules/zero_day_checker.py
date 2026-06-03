import json
import time
import re
from typing import List, Optional
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError

from core.display import console
from core.adb_client import get_device_info, shell_command
from core.severity import Severity


GITHUB_API = "https://api.github.com/search/repositories"
CACHE: List[dict] = []
CACHE_TIME = 0


def _github_search(query: str, max_results: int = 8) -> Optional[dict]:
    url = f"{GITHUB_API}?q={query}+poc+exploit&sort=updated&order=desc&per_page={max_results}"
    req = Request(url, headers={"User-Agent": "CellInspector/1.0", "Accept": "application/vnd.github.v3+json"})
    try:
        with urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read())
            return data
    except HTTPError as e:
        if e.code == 403:
            body = e.read().decode()
            if "rate limit" in body.lower():
                return None
        return None
    except (URLError, OSError, json.JSONDecodeError):
        return None


def _parse_repos(data: dict) -> List[dict]:
    repos = []
    for item in data.get("items", []):
        desc = (item.get("description") or "").strip()
        if not desc:
            continue
        name = item.get("full_name", "")
        html_url = item.get("html_url", "")
        stars = item.get("stargazers_count", 0)
        updated = item.get("updated_at", "")[:10]
        language = item.get("language") or ""
        repos.append({
            "name": name,
            "url": html_url,
            "description": desc,
            "stars": stars,
            "updated": updated,
            "language": language,
        })
    return repos


def _fetch_github_results(device_info: dict) -> List[dict]:
    global CACHE, CACHE_TIME
    now = time.time()
    if CACHE and (now - CACHE_TIME) < 300:
        return CACHE

    model = device_info.get("Model", "")
    android_ver = device_info.get("Android Version", "")
    api_level = device_info.get("API Level", "")
    security_patch = device_info.get("Security Patch", "")
    product_name = device_info.get("Product Name", "")
    manufacturer = device_info.get("Manufacturer", "")

    queries = set()

    if model:
        clean_model = re.sub(r"[^a-zA-Z0-9]", "", model)
        queries.add(f"{manufacturer}+{clean_model}+android+{android_ver}")
        queries.add(f"{clean_model}+cve")

    if product_name:
        clean_product = re.sub(r"[^a-zA-Z0-9]", "", product_name)
        queries.add(f"{clean_product}+exploit")

    if api_level:
        queries.add(f"android+{api_level}+cve+poc")

    if security_patch and security_patch != "Unknown":
        year = security_patch[:4]
        month = security_patch[5:7]
        queries.add(f"android+security+bulletin+{year}+{month}+cve")

    queries.add(f"android+{android_ver}+exploit+poc")

    all_repos = []
    seen_urls = set()

    for query in list(queries)[:4]:
        console.print(f"  [dim]Searching: {query}...[/]")
        data = _github_search(query)
        if data is None:
            console.print("  [yellow]GitHub API rate limit reached or unavailable.[/]")
            break
        repos = _parse_repos(data)
        for r in repos:
            if r["url"] not in seen_urls:
                seen_urls.add(r["url"])
                all_repos.append(r)
        time.sleep(1.5)

    all_repos.sort(key=lambda x: -x["stars"])
    CACHE = all_repos
    CACHE_TIME = now
    return all_repos


def _is_relevant(repo: dict, device_info: dict) -> bool:
    desc = repo["description"].lower()
    name = repo["name"].lower()
    combined = f"{desc} {name}"
    model = (device_info.get("Model", "") or "").lower()
    product = (device_info.get("Product Name", "") or "").lower()
    android_ver = (device_info.get("Android Version", "") or "").lower()
    api_level = (device_info.get("API Level", "") or "").lower()
    manufacturer = (device_info.get("Manufacturer", "") or "").lower()

    keywords = ["cve", "exploit", "poc", "rce", "root", "privilege escalation",
                "vulnerability", "buffer overflow", "use after free", "uaf",
                "heap overflow", "integer overflow", "out of bounds",
                "arbitrary code", "memory corruption", "denial of service",
                "elevation of privilege", "information disclosure",
                "bypass", "sandbox escape", "kernel exploit",
                "bootloader unlock", "oem unlock", "firmware"]

    has_keyword = any(kw in combined for kw in keywords)

    device_terms = [t for t in [model, product, manufacturer, android_ver, api_level] if t]
    matches_device = any(term and term in combined for term in device_terms) if device_terms else True

    if has_keyword and matches_device:
        return True

    if not device_terms:
        return has_keyword

    if matches_device and repo["stars"] >= 5:
        return True

    return False


def check_zero_days() -> List[dict]:
    console.print("\n[bold cyan]\U0001f50d Scanning GitHub for active exploits...[/]")
    device_info = get_device_info()

    model = device_info.get("Model", "Unknown")
    android_ver = device_info.get("Android Version", "Unknown")
    console.print(f"  [dim]Device: {model} | Android: {android_ver}[/]\n")

    repos = _fetch_github_results(device_info)
    if repos is None:
        return []

    relevant = [r for r in repos if _is_relevant(r, device_info)]

    if not relevant:
        relevant = repos[:3]

    return relevant


def run_zero_day_check():
    console.print("\n[bold cyan]\U0001f50d Zero-Day / PoC Scanner[/]")
    console.print("[dim]Searching GitHub for active exploits targeting your device...[/]\n")

    info = get_device_info()
    model = info.get("Model", "Unknown")
    android_ver = info.get("Android Version", "Unknown")
    console.print(f"  [cyan]\u2022 Model:[/] {model}")
    console.print(f"  [cyan]\u2022 Android:[/] {android_ver}")
    console.print()

    repos = _fetch_github_results(info)

    if repos is None:
        console.print("[red]\u274c GitHub API error. Check your internet connection.[/]")
        return

    relevant = [r for r in repos if _is_relevant(r, info)]
    display_repos = relevant if relevant else repos[:3]

    if not display_repos:
        console.print("[bold green]\u2705 No se encontro ningun exploit disponible en Github.[/]")
        return

    console.print(f"\n[bold red]\U0001f6a8 {len(display_repos)} exploit(s) activo(s) con PoC detectado(s)![/]\n")

    from rich.panel import Panel
    from rich import box

    for i, repo in enumerate(display_repos[:6], 1):
        stars_str = f"\u2b50 {repo['stars']}" if repo["stars"] else ""
        lang_str = f"  \U0001f4c1 {repo['language']}" if repo["language"] else ""
        panel = Panel(
            f"[bold cyan]{repo['name']}[/]\n"
            f"[dim]{repo['description'][:120]}[/]\n\n"
            f"[link={repo['url']}]\U0001f517 {repo['url']}[/]\n"
            f"[yellow]{stars_str}[/]{lang_str}  [dim]\U0001f4c5 {repo['updated']}[/]",
            title=f"[bold red]\U0001f4a5 Exploit #{i}[/]",
            border_style="red",
            box=box.ROUNDED,
            padding=(1, 2),
        )
        console.print(panel)
        console.print()

    console.print("[dim]Always verify PoC code before running it on your device.[/]")
    console.print("[dim]CellInspector does not endorse or guarantee any of these exploits.[/]")
