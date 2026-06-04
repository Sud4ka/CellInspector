import json
import time
import re
import urllib.parse
from typing import List, Optional
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError

from core.display import console
from core.adb_client import get_device_info, shell_command
from core.severity import Severity


GITHUB_API = "https://api.github.com/search/repositories"
CACHE: List[dict] = []
CACHE_TIME = 0
DEEP_CACHE: List[dict] = []
DEEP_CACHE_TIME = 0


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
            "source": "GitHub",
        })
    return repos


def _build_queries(device_info: dict) -> set:
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

    return queries


def _fetch_github_results(device_info: dict) -> List[dict]:
    global CACHE, CACHE_TIME
    now = time.time()
    if CACHE and (now - CACHE_TIME) < 300:
        return CACHE

    queries = _build_queries(device_info)

    all_repos = []
    seen_urls = set()

    for query in list(queries)[:4]:
        console.print(f"  [dim]Searching GitHub: {query}...[/]")
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


def _build_search_terms(device_info: dict) -> List[str]:
    model = device_info.get("Model", "")
    manufacturer = device_info.get("Manufacturer", "")
    android_ver = device_info.get("Android Version", "")
    product = device_info.get("Product Name", "")
    terms = set()

    if model:
        clean_model = re.sub(r"[^a-zA-Z0-9\s]", "", model).strip()
        terms.add(clean_model)
    if manufacturer:
        terms.add(manufacturer)
    if product:
        terms.add(re.sub(r"[^a-zA-Z0-9\s]", "", product).strip())

    return [t for t in terms if t]


def _reddit_search(device_info: dict, max_results: int = 8) -> List[dict]:
    results = []
    seen_urls = set()
    terms = _build_search_terms(device_info)

    for term in terms:
        query = urllib.parse.quote(f"{term} exploit poc CVE")
        url = f"https://www.reddit.com/search.json?q={query}&limit=5&sort=new&t=year&restrict_sr=on"
        data = _fetch_json(url, headers={"User-Agent": "CellInspector/1.0 (Reddit Deep Scan)"})
        if not data:
            continue

        for child in data.get("data", {}).get("children", []):
            item = child.get("data", {})
            link = item.get("permalink", "")
            full_url = f"https://www.reddit.com{link}"
            if full_url in seen_urls:
                continue
            seen_urls.add(full_url)
            title = (item.get("title") or "").strip()
            if not title:
                continue
            subreddit = item.get("subreddit", "")
            score = item.get("score", 0)
            num_comments = item.get("num_comments", 0)
            selftext = (item.get("selftext") or "")[:200]

            results.append({
                "title": title,
                "url": full_url,
                "subreddit": subreddit,
                "score": score,
                "comments": num_comments,
                "snippet": selftext,
                "source": "Reddit",
            })
        time.sleep(1)

    results.sort(key=lambda x: -x["score"])
    return results[:max_results]


def _pastebin_search(device_info: dict, max_results: int = 8) -> List[dict]:
    results = []
    seen_urls = set()
    terms = _build_search_terms(device_info)

    for term in terms:
        query = urllib.parse.quote(f"{term} exploit")
        url = f"https://psbdmp.ws/api/search/{query}"
        data = _fetch_json(url)
        if not data:
            time.sleep(1)
            continue

        items = data if isinstance(data, list) else data.get("data", []) if isinstance(data, dict) else []
        for item in items[:5]:
            if isinstance(item, dict):
                mp_id = item.get("id", "")
                if not mp_id:
                    continue
                full_url = f"https://pastebin.com/{mp_id}"
                if full_url in seen_urls:
                    continue
                seen_urls.add(full_url)
                results.append({
                    "id": mp_id,
                    "url": full_url,
                    "title": item.get("title", f"Paste #{mp_id}"),
                    "snippet": (item.get("content", "") or "")[:200] if isinstance(item.get("content"), str) else "",
                    "source": "Pastebin",
                })
        time.sleep(1.5)

    return results[:max_results]


def _web_deep_search(device_info: dict, max_results: int = 8) -> List[dict]:
    results = []
    seen_urls = set()
    terms = _build_search_terms(device_info)
    android_ver = device_info.get("Android Version", "")

    for term in terms:
        for extra in ["exploit poc CVE", "exploit breach", "vulnerability 0day"]:
            query = urllib.parse.quote(f"{term} {android_ver} {extra}")
            url = f"https://html.duckduckgo.com/html/?q={query}"
            html = _fetch_text(url)
            if not html:
                time.sleep(2)
                continue

            link_pattern = re.compile(
                r'class="result__a"[^>]*href="([^"]+)"[^>]*>(.*?)</a>',
                re.DOTALL
            )
            snippet_pattern = re.compile(
                r'class="result__snippet"[^>]*>(.*?)</(?:a|div)',
                re.DOTALL
            )

            links = link_pattern.findall(html)
            snippets = [re.sub(r'<[^>]+>', '', s).strip() for s in snippet_pattern.findall(html)]

            for idx, (href, title_text) in enumerate(links):
                clean_title = re.sub(r'<[^>]+>', '', title_text).strip()
                if href in seen_urls or not clean_title:
                    continue
                seen_urls.add(href)
                snippet = snippets[idx] if idx < len(snippets) else ""

                is_forum = any(d in href.lower() for d in
                    ["breachforum", "exploit.in", "raidforum", "xss.is",
                     "cracking", "sinister", "cybercrime", "darkweb",
                     "0dayforum", "hackforums", "antichat", "infraud"])
                is_reddit = "reddit.com" in href.lower()
                is_pastebin = "pastebin.com" in href.lower()

                if is_reddit or is_pastebin:
                    continue

                source_label = "Forum" if is_forum else "Web"

                results.append({
                    "title": clean_title,
                    "url": href,
                    "snippet": snippet,
                    "source": source_label,
                    "is_forum": is_forum,
                })

            time.sleep(2)

    results.sort(key=lambda x: (0 if x.get("is_forum") else 1, x["title"]))
    return results[:max_results]


def _deep_search(device_info: dict) -> dict:
    global DEEP_CACHE, DEEP_CACHE_TIME
    now = time.time()
    if DEEP_CACHE and (now - DEEP_CACHE_TIME) < 300:
        return {"reddit": DEEP_CACHE.get("reddit", []),
                "pastebin": DEEP_CACHE.get("pastebin", []),
                "web": DEEP_CACHE.get("web", [])}

    model = device_info.get("Model", "Unknown")
    android_ver = device_info.get("Android Version", "Unknown")

    console.print(f"\n[bold yellow]\U0001f50d Deep Internet Search[/]")
    console.print(f"  [dim]Searching Reddit, Pastebin, and web forums for: {model} / Android {android_ver}[/]\n")

    console.print("  [dim]Searching Reddit...[/]")
    reddit = _reddit_search(device_info)

    console.print("  [dim]Searching Pastebin...[/]")
    pastebin = _pastebin_search(device_info)

    console.print("  [dim]Searching web & breach forums...[/]")
    web = _web_deep_search(device_info)

    DEEP_CACHE = {"reddit": reddit, "pastebin": pastebin, "web": web}
    DEEP_CACHE_TIME = now

    return {"reddit": reddit, "pastebin": pastebin, "web": web}


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

    reddit = deep.get("reddit", [])
    pastebin = deep.get("pastebin", [])
    web = deep.get("web", [])

    total = len(reddit) + len(pastebin) + len(web)
    if total == 0:
        console.print("\n[bold yellow]\U0001f50d Deep scan: no se encontraron resultados adicionales.[/]")
        return

    console.print(f"\n[bold magenta]\U0001f4e1 Deep Scan Results ({total} encontrados)[/]\n")

    if reddit:
        console.print(f"[bold orange1]\U0001f4dd Reddit ({len(reddit)})[/]")
        for i, post in enumerate(reddit[:5], 1):
            panel = Panel(
                f"[bold]{post['title']}[/]\n"
                f"[dim]r/{post['subreddit']}  \u2b50 {post['score']}  \U0001f4ac {post['comments']}[/]\n"
                f"[link={post['url']}]\U0001f517 {post['url']}[/]",
                title=f"Reddit #{i}",
                border_style="orange1",
                box=box.ROUNDED,
                padding=(1, 2),
            )
            console.print(panel)
            console.print()

    if pastebin:
        console.print(f"[bold yellow]\U0001f4cb Pastebin ({len(pastebin)})[/]")
        for i, p in enumerate(pastebin[:5], 1):
            panel = Panel(
                f"[bold]{p['title']}[/]\n"
                f"[link={p['url']}]\U0001f517 {p['url']}[/]",
                title=f"Pastebin #{i}",
                border_style="yellow",
                box=box.ROUNDED,
                padding=(1, 2),
            )
            console.print(panel)
            console.print()

    if web:
        console.print(f"[bold blue]\U0001f310 Web & Forums ({len(web)})[/]")
        for i, w in enumerate(web[:5], 1):
            source_tag = "[red]\U0001f6e1 Forum[/]" if w.get("is_forum") else "[blue]\U0001f310 Web[/]"
            snippet = f"\n[dim]{w['snippet'][:150]}[/]" if w.get("snippet") else ""
            panel = Panel(
                f"{source_tag} [bold]{w['title']}[/]{snippet}\n"
                f"[link={w['url']}]\U0001f517 {w['url']}[/]",
                title=f"Web #{i}",
                border_style="blue",
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
