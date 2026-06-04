import json
import os
import re
import time
from typing import Optional
from urllib.request import Request, urlopen
from urllib.error import URLError

from rich.progress import (
    Progress,
    BarColumn,
    TextColumn,
    TimeElapsedColumn,
    SpinnerColumn,
)

from core.display import console
from core.adb_client import shell_command
from core.severity import Severity
from core.confidence import (
    classify_ioc_type, compute_confidence, should_skip,
    format_confidence_badge, confidence_from_result, get_recommendation,
    KNOWN_ANDROID_PROCESSES,
)

DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")
MVT_DIR = os.path.join(DATA_DIR, "mvt_indicators")

STIX2_REPOS = [
    {
        "name": "Pegasus (NSO Group)",
        "url": "https://raw.githubusercontent.com/AmnestyTech/investigations/master/2021-07-18_nso/pegasus.stix2",
        "local": "pegasus.stix2",
    },
    {
        "name": "Predator (Intellexa)",
        "url": "https://raw.githubusercontent.com/mvt-project/mvt-indicators/main/intellexa_predator/predator.stix2",
        "local": "predator.stix2",
    },
    {
        "name": "RCS Lab",
        "url": "https://raw.githubusercontent.com/mvt-project/mvt-indicators/main/2022-06-23_rcs_lab/rcs.stix2",
        "local": "rcs.stix2",
    },
    {
        "name": "KingSpawn (Quadream)",
        "url": "https://raw.githubusercontent.com/mvt-project/mvt-indicators/main/2023-04-11_quadream/kingspawn.stix2",
        "local": "kingspawn.stix2",
    },
    {
        "name": "Operation Triangulation",
        "url": "https://raw.githubusercontent.com/mvt-project/mvt-indicators/main/2023-06_01_operation_triangulation/operation_triangulation.stix2",
        "local": "triangulation.stix2",
    },
    {
        "name": "WyrmSpy / DragonEgg",
        "url": "https://raw.githubusercontent.com/mvt-project/mvt-indicators/main/2023-07-25_wyrmspy_dragonegg/wyrmspy_dragonegg.stix2",
        "local": "wyrmspy.stix2",
    },
    {
        "name": "Candiru (DevilsTongue)",
        "url": "https://raw.githubusercontent.com/mvt-project/mvt-indicators/main/candiru/candiru.stix2",
        "local": "candiru.stix2",
    },
    {
        "name": "ResidentBat",
        "url": "https://raw.githubusercontent.com/mvt-project/mvt-indicators/main/ResidentBat/residentbat.stix2",
        "local": "residentbat.stix2",
    },
    {
        "name": "Cellebrite",
        "url": "https://raw.githubusercontent.com/mvt-project/mvt-indicators/main/cellebrite/cellebrite.stix2",
        "local": "cellebrite.stix2",
    },
    {
        "name": "DarkSword",
        "url": "https://raw.githubusercontent.com/mvt-project/mvt-indicators/main/2026-03-30_darksword/darksword.stix2",
        "local": "darksword.stix2",
    },
    {
        "name": "Coruna (CryptoWaters)",
        "url": "https://raw.githubusercontent.com/mvt-project/mvt-indicators/main/2026-03-03_coruna_cryptowaters/coruna.stix2",
        "local": "coruna.stix2",
    },
    {
        "name": "Stalkerware (ECHAP)",
        "url": "https://raw.githubusercontent.com/AssoEchap/stalkerware-indicators/master/generated/stalkerware.stix2",
        "local": "stalkerware.stix2",
    },
    {
        "name": "Android Campaign (Amnesty)",
        "url": "https://raw.githubusercontent.com/AmnestyTech/investigations/master/2023-03-29_android_campaign/malware.stix2",
        "local": "android_campaign.stix2",
    },
    {
        "name": "Wintego Helios",
        "url": "https://raw.githubusercontent.com/AmnestyTech/investigations/master/2024-05-02_wintego_helios/wintego_helios.stix2",
        "local": "wintego.stix2",
    },
    {
        "name": "NoviSpy (Serbia)",
        "url": "https://raw.githubusercontent.com/AmnestyTech/investigations/master/2024-12-16_serbia_novispy/novispy.stix2",
        "local": "novispy.stix2",
    },
]

PATTERN_DOMAIN = re.compile(r"\[domain-name:value='([^']+)'\]")
PATTERN_IP = re.compile(r"\[ipv4-addr:value='([^']+)'\]")
PATTERN_SHA256 = re.compile(r"\[file:hashes\.sha256='([^']+)'\]")
PATTERN_MD5 = re.compile(r"\[file:hashes\.md5='([^']+)'\]")
PATTERN_SHA1 = re.compile(r"\[file:hashes\.sha1='([^']+)'\]")
PATTERN_APP_ID = re.compile(r"\[app:id='([^']+)'\]")
PATTERN_PROCESS = re.compile(r"\[process:name='([^']+)'\]")
PATTERN_FILE_NAME = re.compile(r"\[file:name='([^']+)'\]")
PATTERN_FILE_PATH = re.compile(r"\[file:path='([^']+)'\]")
PATTERN_URL = re.compile(r"\[url:value='([^']+)'\]")
PATTERN_ANDROID_PROP = re.compile(r"\[android-property:name='([^']+)'\]")

PROCESS_PATTERNS = [
    ("process_name", PATTERN_PROCESS),
    ("app_id_exact", PATTERN_APP_ID),
    ("sha256", PATTERN_SHA256),
    ("sha1", PATTERN_SHA1),
    ("md5", PATTERN_MD5),
    ("domain_exact", PATTERN_DOMAIN),
    ("ip_exact", PATTERN_IP),
    ("file_path", PATTERN_FILE_PATH),
    ("file_name", PATTERN_FILE_NAME),
    ("url", PATTERN_URL),
    ("android_property", PATTERN_ANDROID_PROP),
]


def _ensure_dir():
    os.makedirs(MVT_DIR, exist_ok=True)


def _fetch_url(url: str, timeout: int = 60) -> Optional[bytes]:
    try:
        req = Request(url, headers={"User-Agent": "CellInspector/1.0"})
        with urlopen(req, timeout=timeout) as resp:
            return resp.read()
    except (URLError, OSError) as e:
        console.print(f"  [yellow]Failed: {url[:60]}... ({e})[/]")
        return None


def _download_stix2(source: dict) -> Optional[str]:
    local_path = os.path.join(MVT_DIR, source["local"])
    if os.path.exists(local_path):
        age = time.time() - os.path.getmtime(local_path)
        if age < 86400:
            return local_path

    console.print(f"  [cyan]Downloading {source['name']}...[/]")
    data = _fetch_url(source["url"], timeout=60)
    if not data:
        if os.path.exists(local_path):
            console.print(f"  [yellow]  Using cached version[/]")
            return local_path
        return None

    _ensure_dir()
    with open(local_path, "wb") as f:
        f.write(data)
    return local_path


def _parse_stix2(filepath: str) -> Optional[dict]:
    result = {
        "malware_name": "Unknown",
        "indicators": [],
        "total_parsed": 0,
    }

    try:
        with open(filepath, "rb") as f:
            raw = f.read()
        bundle = json.loads(raw)
    except (json.JSONDecodeError, OSError) as e:
        console.print(f"  [red]Error parsing {filepath}: {e}[/]")
        return None

    objects = bundle.get("objects", [])

    for obj in objects:
        if obj.get("type") == "malware":
            result["malware_name"] = obj.get("name", "Unknown")
            continue

        if obj.get("type") != "indicator":
            continue

        pattern = obj.get("pattern", "")
        if not pattern:
            continue

        matched = False
        for ioc_type, regex in PROCESS_PATTERNS:
            m = regex.search(pattern)
            if m:
                value = m.group(1)
                score, label = compute_confidence(ioc_type, value)
                if label == "SKIP":
                    matched = True
                    break
                result["indicators"].append({
                    "type": ioc_type,
                    "value": value,
                    "pattern": pattern,
                    "confidence_score": score,
                    "confidence_label": label,
                })
                matched = True
                break

        if matched:
            result["total_parsed"] += 1

    result["by_type"] = {}
    for ind in result["indicators"]:
        t = ind["type"]
        result["by_type"][t] = result["by_type"].get(t, 0) + 1

    return result


def _classify_findings(findings: list) -> tuple:
    if not findings:
        return ("CLEAN", 100)

    max_score = max(f["confidence_score"] for f in findings)
    high_count = sum(1 for f in findings if f["confidence_label"] in ("HIGH", "CRITICAL"))
    medium_count = sum(1 for f in findings if f["confidence_label"] == "MEDIUM")
    low_count = sum(1 for f in findings if f["confidence_label"] == "LOW")

    if high_count > 0:
        return ("CRITICAL" if max_score >= 90 else "HIGH", max_score)
    if medium_count > 0:
        return ("MEDIUM", max_score)
    if low_count > 0:
        return ("LOW", max_score)
    return ("INFO", max_score)


def run_mvt_check():
    console.print("\n[bold red]\u2699\ufe0f MVT-Powered Spyware Detection[/]")
    console.print("[dim]Using STIX2 indicators from MVT project (Amnesty International)[/]\n")

    _ensure_dir()

    needs_download = any(
        not os.path.exists(os.path.join(MVT_DIR, s["local"]))
        for s in STIX2_REPOS
    )
    if needs_download:
        console.print("[bold]Downloading STIX2 indicator files...[/]")
        dl_progress = Progress(
            SpinnerColumn(spinner_name="dots"),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(bar_width=None),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            console=console,
        )
        with dl_progress:
            dl_task = dl_progress.add_task(
                "[cyan]Downloading indicators...",
                total=len(STIX2_REPOS),
            )
            for src in STIX2_REPOS:
                dl_progress.update(
                    dl_task,
                    description=f"[cyan]Downloading {src['name']}...[/]",
                )
                _download_stix2(src)
                dl_progress.update(dl_task, advance=1)
        console.print()

    ioc_sources = []
    parse_progress = Progress(
        SpinnerColumn(spinner_name="dots"),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(bar_width=None),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        console=console,
    )
    with parse_progress:
        parse_task = parse_progress.add_task(
            "[cyan]Parsing STIX2 indicators...",
            total=len(STIX2_REPOS),
        )
        for src in STIX2_REPOS:
            local_path = os.path.join(MVT_DIR, src["local"])
            if os.path.exists(local_path):
                parsed = _parse_stix2(local_path)
                if parsed and parsed["total_parsed"] > 0:
                    ioc_sources.append(parsed)
                    by_type = parsed.get("by_type", {})
                    details = ", ".join(f"{k}: {v}" for k, v in sorted(by_type.items()))
                    console.print(f"  [green]\u2713[/] {parsed['malware_name']}: {parsed['total_parsed']} IOCs ({details})")
                else:
                    console.print(f"  [yellow]\u2717[/] {src['name']}: no usable indicators")
            parse_progress.update(parse_task, advance=1)

    if not ioc_sources:
        console.print("[red]\u274c No STIX2 indicators loaded.[/]")
        console.print("[yellow]Run again or check internet connectivity.[/]")
        return

    total_iocs = sum(s["total_parsed"] for s in ioc_sources)
    total_high = sum(1 for s in ioc_sources for i in s["indicators"] if i["confidence_label"] in ("HIGH", "CRITICAL"))
    console.print(f"\n[bold]Loaded {len(ioc_sources)} malware families, {total_iocs} IOCs ({total_high} high confidence)[/]\n")

    with console.status("[bold cyan]Fetching device data (processes, packages)...[/]"):
        raw_processes = shell_command("ps -A 2>/dev/null || ps 2>/dev/null") or ""
        raw_packages = shell_command("pm list packages 2>/dev/null") or ""
        process_list = raw_processes.lower().split("\n")
        package_list = raw_packages.lower().split("\n")
        paths_to_hash = [
            "/system/bin/app_process",
            "/system/bin/app_process32",
            "/system/bin/app_process64",
        ]
        hash_cache = {}
        for path in paths_to_hash:
            raw = shell_command(f"sha256sum {path} 2>/dev/null")
            if raw and raw.strip().split():
                hash_cache[path] = raw.strip().split()[0].lower()

    matched = []

    progress = Progress(
        SpinnerColumn(spinner_name="dots"),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(bar_width=None),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TimeElapsedColumn(),
        console=console,
    )

    with progress:
        total_ioc_count = sum(len(s["indicators"]) for s in ioc_sources)
        main_task = progress.add_task(
            "[cyan]Checking device against MVT indicators...",
            total=total_ioc_count,
        )

        for source in ioc_sources:
            family_name = source["malware_name"]
            indicators = source["indicators"]

            progress.update(
                main_task,
                description=f"[cyan]{family_name}[/]",
            )

            for idx, ind in enumerate(indicators):
                value = ind["value"]
                ioc_type = ind["type"]

                if ioc_type == "process_name" and not should_skip(ioc_type, value):
                    for line in process_list:
                        if value in line:
                            matched.append({
                                "malware": family_name,
                                "type": ioc_type,
                                "value": value,
                                "confidence_score": ind["confidence_score"],
                                "confidence_label": ind["confidence_label"],
                                "detail": f"Process '{value}' running on device",
                            })
                            break

                elif ioc_type == "app_id_exact":
                    exact = f"package:{value.lower()}"
                    if any(exact == p.strip() for p in package_list):
                        matched.append({
                            "malware": family_name,
                            "type": ioc_type,
                            "value": value,
                            "confidence_score": ind["confidence_score"],
                            "confidence_label": ind["confidence_label"],
                            "detail": f"Package '{value}' installed on device",
                        })

                elif ioc_type in ("sha256", "sha1", "md5"):
                    for path, cached_hash in hash_cache.items():
                        if cached_hash == value:
                            matched.append({
                                "malware": family_name,
                                "type": ioc_type,
                                "value": value[:16] + "...",
                                "confidence_score": ind["confidence_score"],
                                "confidence_label": ind["confidence_label"],
                                "detail": f"SHA256 of '{path}' matches indicator",
                            })
                            break

                elif ioc_type == "domain_exact":
                    try:
                        raw = shell_command(
                            f"nslookup {value} 2>/dev/null || ping -c 1 -W 1 {value} 2>/dev/null",
                            timeout=5,
                        )
                        if raw and ("Address" in raw or "bytes from" in raw):
                            matched.append({
                                "malware": family_name,
                                "type": ioc_type,
                                "value": value,
                                "confidence_score": ind["confidence_score"],
                                "confidence_label": ind["confidence_label"],
                                "detail": f"C2 domain '{value}' resolves from device",
                            })
                    except Exception:
                        continue

                progress.update(main_task, advance=1)

    if not matched:
        console.print("\n[bold green]\u2705 No MVT indicators matched this device.[/]")
        console.print("[dim]Note: an absence of indicators does not guarantee the device is clean.[/]")
        return

    overall_label, overall_score = _classify_findings(matched)

    console.print(f"\n{'='*60}")
    console.print(f"  [bold]Overall Confidence:[/] {format_confidence_badge(overall_score, overall_label)}")
    console.print(f"{'='*60}\n")

    for src_name in sorted(set(m["malware"] for m in matched)):
        src_matches = [m for m in matched if m["malware"] == src_name]
        high_m = sum(1 for m in src_matches if m["confidence_label"] in ("HIGH", "CRITICAL"))
        low_m = sum(1 for m in src_matches if m["confidence_label"] == "LOW")

        label = f"[red]{src_name}[/]" if high_m > 0 else f"[yellow]{src_name}[/]"
        console.print(f"  {label}: {len(src_matches)} match(es) ({high_m} high conf, {low_m} low conf)")

    console.print(f"\n[bold]Findings ({len(matched)} total):[/]")
    for m in sorted(matched, key=lambda x: -x["confidence_score"]):
        badge = format_confidence_badge(m["confidence_score"], m["confidence_label"])
        console.print(f"  {badge} [bold]{m['value']}[/]")
        console.print(f"         {m['detail']}")
        console.print(f"         Family: {m['malware']}")

    console.print(f"\n[bold]Recommendation:[/] {get_recommendation(overall_label)}")

    if overall_label in ("CRITICAL", "HIGH"):
        console.print("\n[bold red]\U0001f6a8 High confidence indicators detected. Immediate action recommended.[/]")
    elif overall_label == "MEDIUM":
        console.print("\n[bold orange1]\u26a0\ufe0f Medium confidence. Investigate further before concluding infection.[/]")
    elif overall_label == "LOW":
        console.print("\n[bold yellow]\u26a0\ufe0f Low confidence only. These may be false positives or legitimate system components.[/]")
        console.print("[yellow]Look for corroborating evidence (unusual data usage, battery drain, unexpected behavior).[/]")

    console.print("\n[dim]\u2699\ufe0f Indicators from MVT project (Amnesty International) - MIT licensed[/]")
