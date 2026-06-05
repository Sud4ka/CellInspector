"""
modules/mvt_check.py

MVT-powered multi-family spyware detection using STIX2 indicators from
Amnesty International's MVT project and partners.

Major changes vs v1.1.0
=======================

* Process name matching is now an EXACT match against the NAME column of
  `ps -A`. The old `value in line` substring search was the single most
  important source of false positives (any short indicator could collide
  with any longer process name on the device).

* Domain indicators no longer trigger on plain DNS resolution. The old
  code did `nslookup` on the device and reported a finding if the
  domain resolved to any address. This is meaningless on the public
  internet — the vast majority of Pegasus C2 domains are sinkholed,
  expired, or parked on CDN endpoints, so a resolving A record is
  not evidence of anything. The new code requires an ACTIVE TCP
  connection (`/proc/net/tcp` in state 01/06/08) from the device to
  the resolved IP.

* Hash indicators are restricted to a small set of system binaries that
  are always present and hashable on a stock device. The previous code
  only checked `app_process{,32,64}`, but combined with the substring
  problem, the same false-positive class applied.

* Each STIX2 source is its own `FindingReport` (family). Findings
  inside a family are corroborated with the multi-indicator rules
  from `core.findings`:
      - hash match alone -> CRITICAL
      - 1 HIGH + 1 MEDIUM (independent classes) -> HIGH
      - 1 HIGH alone -> MEDIUM (not enough on its own)
      - 1 LOW alone  -> INFO

* STIX2 patterns that are obviously generic (wildcards, single-character
  values, template strings) are filtered out at parse time.
"""

import json
import os
import re
import socket
import time
from typing import List, Optional, Set
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
from core.confidence import KNOWN_ANDROID_PROCESSES
from core.findings import (
    Finding,
    FindingReport,
    CLASS_PROCESS,
    CLASS_PACKAGE,
    CLASS_FILE_HASH,
    CLASS_NETWORK,
    CLASS_OTHER,
    render_reports,
)

DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")
MVT_DIR = os.path.join(DATA_DIR, "mvt_indicators")

# Same canonical list as v1.1.0. Each entry is one malware family.
STIX2_REPOS = [
    {"name": "Pegasus (NSO Group)",        "url": "https://raw.githubusercontent.com/AmnestyTech/investigations/master/2021-07-18_nso/pegasus.stix2",            "local": "pegasus.stix2"},
    {"name": "Predator (Intellexa)",       "url": "https://raw.githubusercontent.com/mvt-project/mvt-indicators/main/intellexa_predator/predator.stix2",        "local": "predator.stix2"},
    {"name": "RCS Lab",                    "url": "https://raw.githubusercontent.com/mvt-project/mvt-indicators/main/2022-06-23_rcs_lab/rcs.stix2",                "local": "rcs.stix2"},
    {"name": "KingSpawn (Quadream)",       "url": "https://raw.githubusercontent.com/mvt-project/mvt-indicators/main/2023-04-11_quadream/kingspawn.stix2",          "local": "kingspawn.stix2"},
    {"name": "Operation Triangulation",    "url": "https://raw.githubusercontent.com/mvt-project/mvt-indicators/main/2023-06_01_operation_triangulation/operation_triangulation.stix2", "local": "triangulation.stix2"},
    {"name": "WyrmSpy / DragonEgg",        "url": "https://raw.githubusercontent.com/mvt-project/mvt-indicators/main/2023-07-25_wyrmspy_dragonegg/wyrmspy_dragonegg.stix2", "local": "wyrmspy.stix2"},
    {"name": "Candiru (DevilsTongue)",     "url": "https://raw.githubusercontent.com/mvt-project/mvt-indicators/main/candiru/candiru.stix2",                       "local": "candiru.stix2"},
    {"name": "ResidentBat",                "url": "https://raw.githubusercontent.com/mvt-project/mvt-indicators/main/ResidentBat/residentbat.stix2",               "local": "residentbat.stix2"},
    {"name": "Cellebrite",                 "url": "https://raw.githubusercontent.com/mvt-project/mvt-indicators/main/cellebrite/cellebrite.stix2",                 "local": "cellebrite.stix2"},
    {"name": "DarkSword",                  "url": "https://raw.githubusercontent.com/mvt-project/mvt-indicators/main/2026-03-30_darksword/darksword.stix2",         "local": "darksword.stix2"},
    {"name": "Coruna (CryptoWaters)",      "url": "https://raw.githubusercontent.com/mvt-project/mvt-indicators/main/2026-03-03_coruna_cryptowaters/coruna.stix2", "local": "coruna.stix2"},
    {"name": "Stalkerware (ECHAP)",        "url": "https://raw.githubusercontent.com/AssoEchap/stalkerware-indicators/master/generated/stalkerware.stix2",         "local": "stalkerware.stix2"},
    {"name": "Android Campaign (Amnesty)", "url": "https://raw.githubusercontent.com/AmnestyTech/investigations/master/2023-03-29_android_campaign/malware.stix2", "local": "android_campaign.stix2"},
    {"name": "Wintego Helios",             "url": "https://raw.githubusercontent.com/AmnestyTech/investigations/master/2024-05-02_wintego_helios/wintego_helios.stix2", "local": "wintego.stix2"},
    {"name": "NoviSpy (Serbia)",           "url": "https://raw.githubusercontent.com/AmnestyTech/investigations/master/2024-12-16_serbia_novispy/novispy.stix2",   "local": "novispy.stix2"},
]


# ---------------------------------------------------------------------------
# STIX2 pattern parsers (regex-based, same shape as v1.1.0)
# ---------------------------------------------------------------------------

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

# Indicator classes (from core.findings) for each STIX2 type.
_TYPE_TO_CLASS = {
    "process_name": CLASS_PROCESS,
    "app_id_exact": CLASS_PACKAGE,
    "sha256": CLASS_FILE_HASH,
    "sha1": CLASS_FILE_HASH,
    "md5": CLASS_FILE_HASH,
    "domain_exact": CLASS_NETWORK,
    "ip_exact": CLASS_NETWORK,
    "file_path": CLASS_OTHER,
    "file_name": CLASS_OTHER,
    "url": CLASS_NETWORK,
    "android_property": CLASS_OTHER,
}

# Values that are clearly noise: wildcards, template strings, the literal
# word "name", paths with <...> placeholders, etc.
_GENERIC_VALUE_RE = re.compile(
    r"(\*|<.*>|\$\{|\?\?|^name$|^path$|^value$|^process$|^file$|^app$)",
    re.IGNORECASE,
)


def _value_looks_generic(value: str, ioc_type: str) -> bool:
    if not value or len(value) < 2:
        return True
    if _GENERIC_VALUE_RE.search(value):
        return True
    # file:path wildcards like '*.apk'
    if "*" in value and len(value) < 8:
        return True
    return False


# ---------------------------------------------------------------------------
# Network state from the device
# ---------------------------------------------------------------------------

def _ip_to_proc_hex(ip: str) -> str:
    try:
        return socket.inet_aton(ip)[::-1].hex()
    except OSError:
        return ""


def _device_established_to(proc_tcp: str, target_ip_hex: str) -> bool:
    if not target_ip_hex:
        return False
    target = target_ip_hex.upper()
    for line in proc_tcp.splitlines()[1:]:
        parts = line.split()
        if len(parts) < 4:
            continue
        remote, state = parts[2], parts[3]
        if not remote.upper().startswith(target):
            continue
        if state in ("01", "06", "08"):  # ESTABLISHED, TIME_WAIT, CLOSE_WAIT
            return True
    return False


def _resolve_domain(domain: str) -> Optional[str]:
    """Resolve a domain to an IPv4 address using the host's resolver.

    Returns None on failure. We deliberately do NOT consider NXDOMAIN vs
    no-answer as different signal here — the only thing that matters is
    whether the device has an active socket to the resulting IP.
    """
    try:
        infos = socket.getaddrinfo(domain, None, type=socket.SOCK_STREAM)
    except (socket.gaierror, OSError):
        return None
    for fam, *_rest, sockaddr in infos:
        if fam == socket.AF_INET:
            return sockaddr[0]
    return None


# ---------------------------------------------------------------------------
# Download / parse
# ---------------------------------------------------------------------------

def _ensure_dir():
    os.makedirs(MVT_DIR, exist_ok=True)


def _fetch_url(url: str, timeout: int = 60) -> Optional[bytes]:
    try:
        req = Request(url, headers={"User-Agent": "CellInspector/1.2"})
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
        return local_path if os.path.exists(local_path) else None
    _ensure_dir()
    with open(local_path, "wb") as f:
        f.write(data)
    return local_path


def _parse_stix2(filepath: str) -> Optional[dict]:
    try:
        with open(filepath, "rb") as f:
            bundle = json.loads(f.read())
    except (json.JSONDecodeError, OSError) as e:
        console.print(f"  [red]Error parsing {filepath}: {e}[/]")
        return None

    result = {"malware_name": "Unknown", "indicators": [], "total_parsed": 0}
    for obj in bundle.get("objects", []):
        if obj.get("type") == "malware":
            result["malware_name"] = obj.get("name", "Unknown")
            continue
        if obj.get("type") != "indicator":
            continue
        pattern = obj.get("pattern", "")
        for ioc_type, regex in PROCESS_PATTERNS:
            m = regex.search(pattern)
            if not m:
                continue
            value = m.group(1)
            if _value_looks_generic(value, ioc_type):
                break  # skip this pattern entirely
            result["indicators"].append({
                "type": ioc_type,
                "value": value,
                "pattern": pattern,
            })
            result["total_parsed"] += 1
            break

    by_type = {}
    for ind in result["indicators"]:
        by_type[ind["type"]] = by_type.get(ind["type"], 0) + 1
    result["by_type"] = by_type
    return result


# ---------------------------------------------------------------------------
# Device data fetchers
# ---------------------------------------------------------------------------

def _fetch_process_names() -> Set[str]:
    raw = shell_command("ps -A 2>/dev/null || ps 2>/dev/null") or ""
    names: Set[str] = set()
    for line in raw.splitlines():
        parts = line.split()
        if len(parts) < 9:
            continue
        if parts[0] in ("USER", "PID"):
            continue
        n = parts[-1]
        if n and not n.isdigit():
            names.add(n)
    return names


def _fetch_installed_packages() -> Set[str]:
    raw = shell_command("pm list packages 2>/dev/null") or ""
    out: Set[str] = set()
    for line in raw.splitlines():
        line = line.strip()
        if line.startswith("package:"):
            out.add(line[len("package:"):].lower())
    return out


def _fetch_system_hashes() -> dict:
    targets = [
        "/system/bin/app_process",
        "/system/bin/app_process32",
        "/system/bin/app_process64",
    ]
    out = {}
    for path in targets:
        raw = shell_command(f"sha256sum {path} 2>/dev/null")
        if raw and raw.strip().split():
            out[path] = raw.strip().split()[0].lower()
    return out


def _fetch_proc_tcp() -> str:
    v4 = shell_command("cat /proc/net/tcp 2>/dev/null") or ""
    v6 = shell_command("cat /proc/net/tcp6 2>/dev/null") or ""
    return v4 + "\n" + v6


# ---------------------------------------------------------------------------
# Matching
# ---------------------------------------------------------------------------

def _is_known_process(value: str) -> bool:
    return value.lower() in KNOWN_ANDROID_PROCESSES


def _match_indicators(
    family: str,
    indicators: List[dict],
    proc_names: Set[str],
    packages: Set[str],
    system_hashes: dict,
    proc_tcp: str,
) -> FindingReport:
    """Apply the device state against the indicators of a single family."""
    report = FindingReport(family=family)

    for ind in indicators:
        ioc_type = ind["type"]
        value = ind["value"]

        if ioc_type == "process_name":
            if _is_known_process(value):
                continue
            if value in proc_names:
                report.add(Finding(
                    label="HIGH",
                    score=75,
                    family=family,
                    indicator_class=CLASS_PROCESS,
                    title=f"Process '{value}' running on device",
                    detail=f"Exact match in `ps -A` NAME column. Family: {family}.",
                    raw_value=value,
                    source=f"stix2:{family}",
                ))

        elif ioc_type == "app_id_exact":
            if value.lower() in packages:
                report.add(Finding(
                    label="HIGH",
                    score=80,
                    family=family,
                    indicator_class=CLASS_PACKAGE,
                    title=f"Package '{value}' installed on device",
                    detail=f"`pm list packages` contains '{value}'. Family: {family}.",
                    raw_value=value,
                    source=f"stix2:{family}",
                ))

        elif ioc_type in ("sha256", "sha1", "md5"):
            for path, h in system_hashes.items():
                if h == value.lower():
                    report.add(Finding(
                        label="CRITICAL",
                        score=95,
                        family=family,
                        indicator_class=CLASS_FILE_HASH,
                        title=f"System binary {path} hash matches",
                        detail=f"SHA256 of {path} is on the {family} indicator list. "
                               f"This is essentially definitive evidence of infection.",
                        raw_value=f"{path}:{value[:16]}...",
                        source=f"stix2:{family}",
                    ))
                    break

        elif ioc_type == "domain_exact":
            ip = _resolve_domain(value)
            if not ip:
                continue
            hex_ip = _ip_to_proc_hex(ip)
            if _device_established_to(proc_tcp, hex_ip):
                report.add(Finding(
                    label="HIGH",
                    score=80,
                    family=family,
                    indicator_class=CLASS_NETWORK,
                    title=f"Active TCP connection to {family} C2",
                    detail=f"Domain {value} -> {ip}. Active socket found in "
                           f"/proc/net/tcp (ESTABLISHED / TIME_WAIT / CLOSE_WAIT).",
                    raw_value=f"{value} -> {ip}",
                    source=f"stix2:{family}",
                ))

        elif ioc_type == "ip_exact":
            hex_ip = _ip_to_proc_hex(value)
            if _device_established_to(proc_tcp, hex_ip):
                report.add(Finding(
                    label="HIGH",
                    score=80,
                    family=family,
                    indicator_class=CLASS_NETWORK,
                    title=f"Active TCP connection to {family} C2 IP",
                    detail=f"{value} found in /proc/net/tcp (ESTABLISHED / TIME_WAIT).",
                    raw_value=value,
                    source=f"stix2:{family}",
                ))

        # file_path / file_name / url / android_property are tracked but
        # not matched against the device state (we have no cheap way to
        # enumerate every file/url on the device; MVT-tools does that with
        # an ADB pull, which is out of scope for the auditor mode).

    return report


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def run_mvt_check():
    console.print("\n[bold red]\u2699\ufe0f MVT-Powered Spyware Detection[/]")
    console.print("[dim]STIX2 indicators from MVT project (Amnesty) + strict matching[/]\n")

    _ensure_dir()

    needs_download = any(
        not os.path.exists(os.path.join(MVT_DIR, s["local"])) for s in STIX2_REPOS
    )
    if needs_download:
        console.print("[bold]Downloading STIX2 indicator files...[/]")
        with Progress(
            SpinnerColumn(spinner_name="dots"),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(bar_width=None),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            console=console,
        ) as dl_progress:
            task = dl_progress.add_task("[cyan]Downloading...", total=len(STIX2_REPOS))
            for src in STIX2_REPOS:
                dl_progress.update(task, description=f"[cyan]{src['name']}...[/]")
                _download_stix2(src)
                dl_progress.update(task, advance=1)
        console.print()

    parsed_sources = []
    with Progress(
        SpinnerColumn(spinner_name="dots"),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(bar_width=None),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        console=console,
    ) as pp:
        task = pp.add_task("[cyan]Parsing STIX2 indicators...", total=len(STIX2_REPOS))
        for src in STIX2_REPOS:
            local_path = os.path.join(MVT_DIR, src["local"])
            if os.path.exists(local_path):
                p = _parse_stix2(local_path)
                if p and p["total_parsed"] > 0:
                    parsed_sources.append(p)
                    details = ", ".join(f"{k}:{v}" for k, v in sorted(p["by_type"].items()))
                    console.print(f"  [green]\u2713[/] {p['malware_name']}: {p['total_parsed']} IOCs ({details})")
                else:
                    console.print(f"  [yellow]\u2717[/] {src['name']}: no usable indicators")
            pp.update(task, advance=1)

    if not parsed_sources:
        console.print("[red]\u274c No STIX2 indicators loaded.[/]")
        return

    total_iocs = sum(s["total_parsed"] for s in parsed_sources)
    console.print(f"\n[bold]Loaded {len(parsed_sources)} families, {total_iocs} IOCs[/]\n")

    with console.status("[bold cyan]Fetching device state (ps, packages, /proc/net/tcp)...[/]"):
        proc_names = _fetch_process_names()
        packages = _fetch_installed_packages()
        system_hashes = _fetch_system_hashes()
        proc_tcp = _fetch_proc_tcp()

    reports: List[FindingReport] = []
    for src in parsed_sources:
        family = src["malware_name"]
        rep = _match_indicators(
            family=family,
            indicators=src["indicators"],
            proc_names=proc_names,
            packages=packages,
            system_hashes=system_hashes,
            proc_tcp=proc_tcp,
        )
        if rep.findings:
            reports.append(rep)

    if not reports:
        console.print("\n[bold green]\u2705 No MVT indicators matched this device.[/]")
        console.print("[dim]Absence of indicators does not guarantee the device is clean.[/]")
        return

    render_reports(reports, console)
    console.print("\n[dim]\u2699\ufe0f Indicators from MVT project (Amnesty International) - MIT licensed[/]")
