import json
import time
import re
import os
import urllib.parse
import concurrent.futures
from typing import List, Optional, Tuple
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError


from core.display import console
from core.adb_client import get_device_info, shell_command
from core.severity import Severity


GITHUB_API = "https://api.github.com/search/repositories"
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN") or ""
CACHE: List[dict] = []
CACHE_TIME = 0
DEEP_CACHE: dict = {}
DEEP_CACHE_TIME = 0
MAX_TOTAL_REPOS = 20

DORK_TEMPLATES = [
    "{term}+exploit",
    "{term}+poc",
    "{term}+cve",
    "{term}+rce",
    "{term}+vulnerability+poc",
    "{term}+kernel+exploit",
    "{term}+0day+poc",
    "{term}+root+exploit",
    "{term}+exploit+vulnerabilidade",
    "{term}+poc+vulnerabilidad",
    "{term}+exploit+vulnérabilité",
    "{term}+exploit+vulnerabilità",
    "{term}+эксплойт+уязвимость",
    "{term}+poc+взлом",
    "{term}+漏洞+exploit",
    "{term}+利用+poc",
    "{term}+脆弱性+exploit",
    "{term}+エクスプロイト+poc",
    "{term}+취약점+exploit",
    "{term}+익스플로잇+poc",
]


def _github_search(query: str, max_results: int = 8) -> Optional[dict]:
    encoded_q = urllib.parse.quote(query, safe="+")
    url = f"{GITHUB_API}?q={encoded_q}&sort=updated&order=desc&per_page={max_results}"
    headers = {"User-Agent": "CellInspector/1.0", "Accept": "application/vnd.github.v3+json"}
    if GITHUB_TOKEN:
        headers["Authorization"] = f"token {GITHUB_TOKEN}"
    req = Request(url, headers=headers)
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
            "source": "GitHub",
        })
    return repos


def _build_queries(device_info: dict) -> list:
    model = device_info.get("Model", "")
    android_ver = device_info.get("Android Version", "")
    product_name = device_info.get("Product Name", "")
    manufacturer = device_info.get("Manufacturer", "")

    clean_model = re.sub(r"[^a-zA-Z0-9]", "", model) if model else ""
    clean_product = re.sub(r"[^a-zA-Z0-9]", "", product_name) if product_name else ""
    clean_manufacturer = re.sub(r"[^a-zA-Z0-9]", "", manufacturer) if manufacturer else ""

    terms = []
    if android_ver:
        terms.append(f"android+{android_ver}")
    if clean_model:
        terms.append(clean_model)
    if clean_product and clean_product != clean_model:
        terms.append(clean_product)
    if clean_manufacturer and clean_manufacturer.lower() not in (clean_model.lower(), clean_product.lower()):
        terms.append(clean_manufacturer)

    queries = []
    for term in terms:
        for template in DORK_TEMPLATES:
            queries.append(template.format(term=term))

    return queries


def _verify_url(url: str, timeout: int = 5) -> bool:
    req = Request(url, method="HEAD",
                  headers={"User-Agent": "CellInspector/1.0"})
    try:
        with urlopen(req, timeout=timeout) as resp:
            return resp.status == 200
    except (URLError, HTTPError, OSError):
        return False


def _verify_repos(repos: List[dict]) -> List[dict]:
    if not repos:
        return repos
    console.print(f"  [dim]Verifying {len(repos)} repository URLs...[/]")
    urls = [r["url"] for r in repos]
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as pool:
        results = list(pool.map(_verify_url, urls))
    verified = [r for r, ok in zip(repos, results) if ok]
    failed = len(repos) - len(verified)
    if failed:
        console.print(f"  [dim]Descartados {failed} repo(s) inaccesibles (404/error).[/]")
    return verified


def _fetch_github_results(device_info: dict) -> List[dict]:
    global CACHE, CACHE_TIME
    now = time.time()
    if CACHE and (now - CACHE_TIME) < 300:
        return CACHE

    all_queries = _build_queries(device_info)

    if not all_queries:
        return []

    step = max(1, len(all_queries) // 12)
    sampled = [all_queries[i] for i in range(0, len(all_queries), step)][:12]

    auth_status = "[green]autenticado[/]" if GITHUB_TOKEN else "[yellow]sin token[/]"
    console.print(f"  [dim]GitHub API: {auth_status} ({len(sampled)} dorks)[/]")

    all_repos = []
    seen_urls = set()

    for query in sampled:
        console.print(f"  [dim]Searching: {query}...[/]")
        data = _github_search(query)
        if data is None:
            remaining = getattr(data, "ratelimit_remaining", None)
            console.print("  [yellow]Límite de API de GitHub alcanzado. Usa GITHUB_TOKEN para más.[/]")
            break
        repos = _parse_repos(data)
        for r in repos:
            if r["url"] not in seen_urls:
                seen_urls.add(r["url"])
                all_repos.append(r)
        if len(all_repos) >= MAX_TOTAL_REPOS:
            console.print(f"  [dim]Suficientes repos encontrados ({len(all_repos)}), pasando a verificación...[/]")
            break
        time.sleep(1)

    all_repos.sort(key=lambda x: -x["stars"])

    all_repos = _verify_repos(all_repos)

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
                "bootloader unlock", "oem unlock", "firmware",
                "vulnerabilidade", "vulnérabilité", "vulnerabilidad",
                "vulnerabilità", "уязвимость", "漏洞", "脆弱性", "취약점",
                "эксплойт", "エクスプロイト", "익스플로잇", "взлом",
                "malware", "trojan", "backdoor", "spyware", "rat",
                "reverse shell", "code execution", "dos", "ddos"]

    has_keyword = any(kw in combined for kw in keywords)

    device_terms = [t for t in [model, product, manufacturer, android_ver, api_level] if t]
    matches_device = any(term and term in combined for term in device_terms) if device_terms else True

    if has_keyword and "android" in combined:
        return True

    if has_keyword and matches_device:
        return True

    if has_keyword:
        return True

    if matches_device and repo["stars"] >= 3:
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


def _fetch_json(url: str, headers: dict = None, timeout: int = 15) -> Optional[dict]:
    if headers is None:
        headers = {"User-Agent": "CellInspector/1.0"}
    req = Request(url, headers=headers)
    try:
        with urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read())
    except (URLError, HTTPError, OSError, json.JSONDecodeError):
        return None


def _fetch_text(url: str, headers: dict = None, timeout: int = 15) -> Optional[str]:
    if headers is None:
        headers = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0"}
    req = Request(url, headers=headers)
    try:
        with urlopen(req, timeout=timeout) as resp:
            return resp.read().decode("utf-8", errors="replace")
    except (URLError, HTTPError, OSError):
        return None


DEEP_DORKS = [
    ("site:reddit.com {term} exploit poc OR rce OR CVE", "Reddit"),
    ("site:reddit.com {term} vulnerability OR 0day OR kernel", "Reddit"),
    ("site:pastebin.com {term} exploit OR poc OR CVE", "Pastebin"),
    ("site:pastebin.com {term} android OR hack OR root", "Pastebin"),
    ("site:breachforums.is OR site:exploit.in OR site:xss.is {term} exploit", "Forum"),
    ("site:hackforums.net OR site:antichat.ru {term} android OR exploit", "Forum"),
    ("{term} exploit poc CVE", "Web"),
    ("{term} vulnerability 0day android", "Web"),
]


def _parse_ddg_results(html: str) -> List[tuple]:
    results = []
    link_pattern = re.compile(
        r'class="result__a"[^>]*href="([^"]+)"[^>]*>(.*?)</a>',
        re.DOTALL
    )
    snippet_pattern = re.compile(
        r'class="result__snippet"[^>]*>(.*?)</(?:a|div)',
        re.DOTALL
    )
    alt_link = re.compile(
        r'<a[^>]+class="result__a"[^>]+href="([^"]+)"[^>]*>(.*?)</a>',
        re.DOTALL
    )

    links = link_pattern.findall(html) or alt_link.findall(html)
    snippets = [re.sub(r'<[^>]+>', '', s).strip() for s in snippet_pattern.findall(html)]

    for idx, (href, title_text) in enumerate(links):
        clean_title = re.sub(r'<[^>]+>', '', title_text).strip()
        snippet = snippets[idx] if idx < len(snippets) else ""
        if clean_title:
            results.append((href, clean_title, snippet))

    return results


def _deep_search(device_info: dict) -> dict:
    global DEEP_CACHE, DEEP_CACHE_TIME
    now = time.time()
    if DEEP_CACHE and (now - DEEP_CACHE_TIME) < 300:
        return DEEP_CACHE

    model = device_info.get("Model", "")
    android_ver = device_info.get("Android Version", "")
    manufacturer = device_info.get("Manufacturer", "")
    product = device_info.get("Product Name", "")

    clean_model = re.sub(r"[^a-zA-Z0-9\s]", "", model).strip() if model else ""
    clean_product = re.sub(r"[^a-zA-Z0-9\s]", "", product).strip() if product else ""

    keywords = [t for t in [f"android {android_ver}", clean_model, manufacturer, clean_product] if t]

    console.print(f"\n[bold yellow]\U0001f50d Deep Internet Search[/]")
    console.print(f"  [dim]Searching web, Reddit, Pastebin, and forums for: {model} / Android {android_ver}[/]\n")

    test_html = _fetch_text("https://html.duckduckgo.com/html/?q=test", timeout=4)
    if not test_html:
        console.print("  [yellow]Web search no disponible (DuckDuckGo bloqueado), saltando...[/]")
        DEEP_CACHE = {"Reddit": [], "Pastebin": [], "Forum": [], "Web": []}
        DEEP_CACHE_TIME = now
        return DEEP_CACHE

    categorized = {"Reddit": [], "Pastebin": [], "Forum": [], "Web": []}
    seen_urls = set()

    for dork, dork_cat in DEEP_DORKS:
        for keyword in keywords[:1]:
            q = dork.format(term=keyword)
            query = urllib.parse.quote(q)
            url = f"https://html.duckduckgo.com/html/?q={query}"
            try:
                html = _fetch_text(url, timeout=5)
                if not html:
                    continue
                results = _parse_ddg_results(html)
                for href, title, snippet in results:
                    if href in seen_urls:
                        continue
                    seen_urls.add(href)
                    for pat, label in [("reddit", "Reddit"), ("pastebin", "Pastebin"),
                                       ("breachforums", "Forum"), ("exploit.in", "Forum"),
                                       ("xss.is", "Forum"), ("hackforums", "Forum")]:
                        if pat in href.lower():
                            target_cat = label
                            break
                    else:
                        target_cat = dork_cat
                    categorized[target_cat].append({
                        "title": title,
                        "url": href,
                        "snippet": snippet,
                        "source": target_cat,
                        "is_forum": target_cat == "Forum",
                    })
            except Exception:
                pass
            time.sleep(0.5)

    for cat in categorized:
        categorized[cat].sort(key=lambda x: x["title"])
        categorized[cat] = categorized[cat][:6]

    total = sum(len(v) for v in categorized.values())
    console.print(f"  [dim]Total: {total} resultados (Reddit: {len(categorized['Reddit'])}, "
                  f"Pastebin: {len(categorized['Pastebin'])}, "
                  f"Foros: {len(categorized['Forum'])}, "
                  f"Web: {len(categorized['Web'])})[/]")

    DEEP_CACHE = categorized
    DEEP_CACHE_TIME = now
    return categorized


def _display_github_results(display_repos: List[dict]):
    if not display_repos:
        console.print("[bold green]\u2705 No GitHub exploits found for your device.[/]")
        return

    console.print(f"\n[bold red]\U0001f6a8 {len(display_repos)} GitHub PoC(s) encontrados![/]\n")

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
            title=f"[bold red]\U0001f4a5 GitHub Exploit #{i}[/]",
            border_style="red",
            box=box.ROUNDED,
            padding=(1, 2),
        )
        console.print(panel)
        console.print()


def _display_deep_results(deep: dict):
    from rich.panel import Panel
    from rich import box

    categories = [
        ("Reddit", "\U0001f4dd", "orange1"),
        ("Pastebin", "\U0001f4cb", "yellow"),
        ("Forum", "\U0001f6e1", "red"),
        ("Web", "\U0001f310", "blue"),
    ]

    total = sum(len(deep.get(cat, [])) for cat, _, _ in categories)
    if total == 0:
        console.print("\n[bold yellow]\U0001f50d Deep scan: no se encontraron resultados adicionales.[/]")
        return

    console.print(f"\n[bold magenta]\U0001f4e1 Deep Scan Results ({total} encontrados)[/]\n")

    for cat, icon, color in categories:
        items = deep.get(cat, [])
        if not items:
            continue
        console.print(f"[bold {color}]{icon} {cat} ({len(items)})[/]")
        for i, item in enumerate(items[:5], 1):
            snippet = f"\n[dim]{item.get('snippet', '')[:150]}[/]" if item.get("snippet") else ""
            panel = Panel(
                f"[bold]{item['title']}[/]{snippet}\n"
                f"[link={item['url']}]\U0001f517 {item['url']}[/]",
                title=f"{cat} #{i}",
                border_style=color,
                box=box.ROUNDED,
                padding=(1, 2),
            )
            console.print(panel)
            console.print()


def run_zero_day_check(deep: bool = False):
    console.print("\n[bold cyan]\U0001f50d Zero-Day / PoC Scanner[/]")
    console.print("[dim]Buscando exploits activos para tu dispositivo...[/]\n")

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

    _display_github_results(display_repos)

    if deep:
        deep_results = _deep_search(info)
        _display_deep_results(deep_results)

    console.print("\n[dim]\u26a0\ufe0f Always verify PoC code before running it on your device.[/]")
    console.print("[dim]CellInspector does not endorse or guarantee any of these exploits.[/]")
