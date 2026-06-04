import json
import os
import re
import time
from typing import Optional
from urllib.request import Request, urlopen
from urllib.error import URLError

from core.display import console
from core.adb_client import shell_command
from core.severity import Severity

DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")
MVT_DIR = os.path.join(DATA_DIR, "mvt_indicators")
INDICATORS_YAML_URL = "https://raw.githubusercontent.com/mvt-project/mvt-indicators/main/indicators.yaml"

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


def _ensure_dir():
    os.makedirs(MVT_DIR, exist_ok=True)


def _fetch_url(url: str, timeout: int = 30) -> Optional[bytes]:
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


def _parse_stix2(filepath: str) -> dict:
    result = {
        "malware_name": "Unknown",
        "domains": [],
        "ips": [],
        "sha256": [],
        "md5": [],
        "sha1": [],
        "app_ids": [],
        "processes": [],
        "file_names": [],
        "file_paths": [],
        "urls": [],
        "android_properties": [],
        "total_indicators": 0,
    }

    try:
        with open(filepath, "rb") as f:
            raw = f.read()
        bundle = json.loads(raw)
    except (json.JSONDecodeError, OSError) as e:
        console.print(f"  [red]Error parsing {filepath}: {e}[/]")
        return result

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

        result["total_indicators"] += 1

        m = PATTERN_DOMAIN.search(pattern)
        if m:
            result["domains"].append(m.group(1).lower())
            continue

        m = PATTERN_IP.search(pattern)
        if m:
            result["ips"].append(m.group(1))
            continue

        m = PATTERN_SHA256.search(pattern)
        if m:
            result["sha256"].append(m.group(1).lower())
            continue

        m = PATTERN_MD5.search(pattern)
        if m:
            result["md5"].append(m.group(1).lower())
            continue

        m = PATTERN_SHA1.search(pattern)
        if m:
            result["sha1"].append(m.group(1).lower())
            continue

        m = PATTERN_APP_ID.search(pattern)
        if m:
            result["app_ids"].append(m.group(1))
            continue

        m = PATTERN_PROCESS.search(pattern)
        if m:
            result["processes"].append(m.group(1).lower())
            continue

        m = PATTERN_FILE_NAME.search(pattern)
        if m:
            result["file_names"].append(m.group(1))
            continue

        m = PATTERN_FILE_PATH.search(pattern)
        if m:
            result["file_paths"].append(m.group(1))
            continue

        m = PATTERN_URL.search(pattern)
        if m:
            result["urls"].append(m.group(1))
            continue

        m = PATTERN_ANDROID_PROP.search(pattern)
        if m:
            result["android_properties"].append(m.group(1))
            continue

    result["domains"] = list(set(result["domains"]))
    result["ips"] = list(set(result["ips"]))
    result["sha256"] = list(set(result["sha256"]))
    result["app_ids"] = list(set(result["app_ids"]))

    return result


def _check_processes(iocs: list) -> list:
    findings = []
    raw = shell_command("ps -A 2>/dev/null || ps 2>/dev/null")
    if not raw:
        return findings
    raw_lower = raw.lower()
    for source in iocs:
        for proc in source.get("processes", []):
            if proc in raw_lower:
                findings.append((
                    Severity.CRITICAL,
                    f"[MVT] Process match: {proc}",
                    f"Process '{proc}' matches indicator from {source['malware_name']}",
                    f"MVT-{source['malware_name']}",
                ))
    return findings


def _check_packages(iocs: list) -> list:
    findings = []
    raw = shell_command("pm list packages 2>/dev/null")
    if not raw:
        return findings
    raw_lower = raw.lower()
    for source in iocs:
        for pkg in source.get("app_ids", []):
            if pkg.lower() in raw_lower:
                findings.append((
                    Severity.CRITICAL,
                    f"[MVT] Package match: {pkg}",
                    f"Package '{pkg}' matches indicator from {source['malware_name']}",
                    f"MVT-{source['malware_name']}",
                ))
    return findings


def _check_file_paths(iocs: list) -> list:
    findings = []
    for source in iocs:
        for fpath in source.get("file_paths", []):
            try:
                raw = shell_command(f"ls -la {fpath} 2>/dev/null")
                if raw and "No such file" not in raw:
                    findings.append((
                        Severity.CRITICAL,
                        f"[MVT] File path match: {fpath}",
                        f"Path '{fpath}' exists and matches indicator from {source['malware_name']}",
                        f"MVT-{source['malware_name']}",
                    ))
            except Exception:
                continue
    return findings


def _check_files(iocs: list) -> list:
    findings = []
    for source in iocs:
        for fname in source.get("file_names", []):
            try:
                raw = shell_command(f"find /data /system /vendor -name '{fname}' 2>/dev/null | head -3")
                if raw and raw.strip():
                    findings.append((
                        Severity.CRITICAL,
                        f"[MVT] File name match: {fname}",
                        f"File '{fname}' found on device, matches {source['malware_name']}",
                        f"MVT-{source['malware_name']}",
                    ))
            except Exception:
                continue
    return findings


def _check_hashes(iocs: list) -> list:
    findings = []
    all_hashes = {}
    for source in iocs:
        for h in source.get("sha256", []):
            all_hashes[h] = source["malware_name"]

    paths_to_check = [
        "/system/bin/app_process",
        "/system/bin/app_process32",
        "/system/bin/app_process64",
    ]
    for path in paths_to_check:
        try:
            raw = shell_command(f"sha256sum {path} 2>/dev/null")
            if not raw:
                continue
            parts = raw.strip().split()
            if not parts:
                continue
            file_hash = parts[0].lower()
            if file_hash in all_hashes:
                findings.append((
                    Severity.CRITICAL,
                    f"[MVT] Hash match: {path}",
                    f"SHA256 of '{path}' matches {all_hashes[file_hash]} indicator",
                    f"MVT-{all_hashes[file_hash]}",
                ))
        except Exception:
            continue

    return findings


def run_mvt_check(force_download: bool = False):
    console.print("\n[bold red]\U0001f575\ufe0f MVT-Powered Spyware Detection[/]")
    console.print("[dim]Using indicators from Mobile Verification Toolkit (Amnesty International)[/]\n")

    if not os.path.exists(MVT_DIR) or force_download:
        console.print("[bold]Downloading STIX2 indicator files...[/]")
        _ensure_dir()
        for src in STIX2_REPOS:
            _download_stix2(src)
        console.print()

    ioc_sources = []
    for src in STIX2_REPOS:
        local_path = os.path.join(MVT_DIR, src["local"])
        if os.path.exists(local_path):
            parsed = _parse_stix2(local_path)
            if parsed["total_indicators"] > 0:
                ioc_sources.append(parsed)
                console.print(f"  [green]\u2713[/] {parsed['malware_name']}: {parsed['total_indicators']} indicators "
                              f"({len(parsed['domains'])} domains, {len(parsed['app_ids'])} apps, "
                              f"{len(parsed['sha256'])} hashes)")
            else:
                console.print(f"  [yellow]\u2717[/] {src['name']}: failed to parse or empty")

    if not ioc_sources:
        console.print("[red]\u274c No STIX2 indicators loaded.[/]")
        console.print("[yellow]Try running the command again for fresh downloads.[/]")
        return

    total_iocs = sum(s["total_indicators"] for s in ioc_sources)
    console.print(f"\n[bold]Loaded {len(ioc_sources)} malware families, {total_iocs} total IOCs[/]\n")

    all_findings = []
    checks = [
        ("Processes", _check_processes),
        ("Packages", _check_packages),
        ("File paths", _check_file_paths),
        ("File names", _check_files),
        ("Hash matching", _check_hashes),
    ]

    for name, func in checks:
        with console.status(f"[cyan]Checking {name}...[/]"):
            findings = func(ioc_sources)
            all_findings.extend(findings)

    malware_hits = {}
    for f in all_findings:
        category = f[3]
        malware_hits.setdefault(category, 0)
        malware_hits[category] += 1

    if not all_findings:
        console.print("\n[bold green]\u2705 No MVT indicators matched this device.[/]")
        console.print("[dim]This does not guarantee the device is clean. Spyware uses advanced hiding techniques.[/]")
        return

    console.print(f"\n[bold red]\U0001f6a8 {len(all_findings)} MVT indicator match(es) found![/]\n")

    for malware, count in sorted(malware_hits.items(), key=lambda x: -x[1]):
        console.print(f"  [red]\u26a0[/] [bold]{malware}[/]: {count} match(es)")

    console.print("\n[bold]Detailed findings:[/]")
    for finding in all_findings:
        sev, title, desc, category = finding
        console.print(f"  \u2022 [bold]{title}[/]")
        console.print(f"    {desc}")

    console.print("\n[bold yellow]\U0001f4a1 Recommended actions:[/]")
    console.print("  \u2022 Immediately disconnect the device from any network")
    console.print("  \u2022 Factory reset the device from recovery mode (not from settings)")
    console.print("  \u2022 After reset, change all passwords from a trusted device")
    console.print("  \u2022 Enable two-factor authentication on all accounts")
    console.print("\n[dim]\u26a0\ufe0f Indicators from MVT project (Amnesty International) - MIT licensed[/]")
    console.print("[dim]MVT: https://github.com/mvt-project/mvt[/]")
