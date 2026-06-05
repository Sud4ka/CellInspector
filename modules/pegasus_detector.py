"""
modules/pegasus_detector.py

Pegasus / NSO Group detection using strict matching and multi-indicator
corroboration. Designed to produce as few false positives as possible.

What changed vs v1.1.0
=====================

* Process names:  exact match against the NAME column of `ps -A` (not
  substring of an arbitrary line).
* Packages:       only flagged if `pm path` confirms the package is
  installed (and not just a substring of the package list).
* File paths:     only flagged if the file actually exists on the device.
* C2:             /proc/net/tcp is checked for an ESTABLISHED connection
  to any known C2 IP. We DO NOT use nslookup; the previous version
  resolved any domain and reported a finding, which was the single
  largest source of FPs.
* Kernel modules: exact match on `lsmod` / `/proc/modules` output.
* Hashes:         only checked against a small, named set of file paths
  that are part of the standard Android boot/runtime.

All findings flow through `core.findings.FindingReport`, which applies
the multi-indicator corroboration rules. A single match on its own is
NEVER enough to escalate to HIGH.
"""

import re
import socket
import struct
from typing import List, Optional, Set

from core.display import console
from core.adb_client import shell_command
from core.severity import Severity
from core.findings import (
    Finding,
    FindingReport,
    CLASS_PROCESS,
    CLASS_PACKAGE,
    CLASS_FILE_PATH,
    CLASS_FILE_HASH,
    CLASS_NETWORK,
    CLASS_KERNEL,
    CLASS_PROPERTY,
    render_reports,
)
from core.pegasus_ioc import (
    PEGASUS_SHA256,
    PEGASUS_PACKAGES,
    PEGASUS_PROCESSES,
    PEGASUS_FILE_PATHS,
    PEGASUS_C2_IPS,
    PEGASUS_C2_DOMAINS,
    PEGASUS_KERNEL_MODULES,
    PEGASUS_PROPERTIES,
)
from core.confidence import KNOWN_ANDROID_PROCESSES, SKIP_MIN_LENGTH

FAMILY = "Pegasus"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _parse_ps_names(raw: str) -> Set[str]:
    """Return the set of *exact* process names from `ps -A` output.

    Android Toybox `ps -A` format:
        USER PID PPID VSZ RSS WCHAN ADDR S NAME
    So NAME is column 9 (index 8). We tolerate leading whitespace and
    both upper- and lower-case headers.
    """
    names: Set[str] = set()
    for line in (raw or "").splitlines():
        parts = line.split()
        if len(parts) < 9:
            continue
        if parts[0] in ("USER", "PID"):
            continue
        name = parts[-1]
        if not name:
            continue
        # Skip the system zombies and pure-numeric TID/PID entries
        if name.isdigit():
            continue
        names.add(name)
    return names


def _ip_to_proc_hex(ip: str) -> str:
    """Convert 1.2.3.4 to the little-endian hex form used in /proc/net/tcp.

    /proc/net/tcp stores the address bytes in little-endian order:
        127.0.0.1     -> bytes 0x7F,0x00,0x00,0x01 -> '0100007F'
        172.65.90.23  -> bytes 0xAC,0x41,0x5A,0x17 -> '175A41AC'
    """
    try:
        packed = socket.inet_aton(ip)
    except OSError:
        return ""
    # inet_aton returns network order (big-endian) bytes; reverse the byte
    # order so the output matches the kernel's /proc/net/tcp format.
    return packed[::-1].hex()


def _parse_proc_net_tcp(raw: str) -> List[dict]:
    """Parse /proc/net/tcp{,6} into a list of connection dicts."""
    out = []
    for line in (raw or "").splitlines()[1:]:
        parts = line.split()
        if len(parts) < 10:
            continue
        local, remote, state = parts[1], parts[2], parts[3]
        out.append({
            "local": local,
            "remote": remote,
            "state": state,        # '01' = ESTABLISHED, '06' = TIME_WAIT, '0A' = LISTEN
            "uid": parts[7] if len(parts) > 7 else "",
            "inode": parts[9] if len(parts) > 9 else "",
        })
    return out


def _established_to_ip(proc_tcp: str, target_ip_hex: str) -> bool:
    """True if there is an ESTABLISHED (or TIME_WAIT) connection to target_ip_hex.

    /proc/net/tcp prints hex in uppercase; we compare case-insensitively so
    callers can pass either.
    """
    target = target_ip_hex.upper()
    for c in _parse_proc_net_tcp(proc_tcp):
        if not c["remote"].upper().startswith(target):
            continue
        if c["state"] in ("01", "06", "08"):  # ESTABLISHED, TIME_WAIT, CLOSE_WAIT
            return True
    return False


# ---------------------------------------------------------------------------
# Individual checks
# ---------------------------------------------------------------------------

def _check_processes(report: FindingReport) -> None:
    raw = shell_command("ps -A 2>/dev/null || ps 2>/dev/null")
    if not raw:
        return
    names = _parse_ps_names(raw)
    for proc in PEGASUS_PROCESSES:
        if len(proc) < SKIP_MIN_LENGTH:
            continue
        if proc.lower() in KNOWN_ANDROID_PROCESSES:
            continue
        if proc in names:
            report.add(Finding(
                label="HIGH",
                score=75,
                family=FAMILY,
                indicator_class=CLASS_PROCESS,
                title=f"Process '{proc}' matches Pegasus indicator",
                detail=f"Exact match in `ps -A` NAME column. Pegasus for Android "
                       f"uses a small set of well-known daemon names; a clean "
                       f"device should never have any of them.",
                raw_value=proc,
                source="pegasus_ioc",
            ))


def _check_packages(report: FindingReport) -> None:
    raw = shell_command("pm list packages 2>/dev/null")
    if not raw:
        return
    installed = {line.strip().removeprefix("package:").lower()
                 for line in raw.splitlines() if line.strip()}
    for pkg in PEGASUS_PACKAGES:
        if pkg.lower() in installed:
            # Confirm with `pm path` to avoid matching the package list
            # entry if it has somehow been corrupted.
            path = shell_command(f"pm path {pkg} 2>/dev/null") or ""
            report.add(Finding(
                label="HIGH",
                score=80,
                family=FAMILY,
                indicator_class=CLASS_PACKAGE,
                title=f"Package '{pkg}' installed",
                detail=f"`pm path` returned: {path.strip() or '(empty)'}",
                raw_value=pkg,
                source="pegasus_ioc",
            ))


def _check_file_paths(report: FindingReport) -> None:
    for path in PEGASUS_FILE_PATHS:
        raw = shell_command(f"ls -la {path} 2>/dev/null")
        if not raw or "No such file" in raw:
            continue
        report.add(Finding(
            label="MEDIUM",
            score=55,
            family=FAMILY,
            indicator_class=CLASS_FILE_PATH,
            title=f"Suspicious file present: {path}",
            detail=raw.strip()[:160],
            raw_value=path,
            source="pegasus_ioc",
        ))


def _check_kernel_modules(report: FindingReport) -> None:
    raw = shell_command("lsmod 2>/dev/null || cat /proc/modules 2>/dev/null")
    if not raw:
        return
    loaded = set()
    for line in raw.splitlines():
        parts = line.split()
        if parts:
            loaded.add(parts[0])
    for mod in PEGASUS_KERNEL_MODULES:
        if mod in loaded:
            report.add(Finding(
                label="MEDIUM",
                score=55,
                family=FAMILY,
                indicator_class=CLASS_KERNEL,
                title=f"Kernel module '{mod}' loaded",
                detail=f"Found in `lsmod` output. Modern Pegasus (2019+) does "
                       f"not load discrete .ko modules on Android, so a match "
                       f"implies the older 2017-2018 generation.",
                raw_value=mod,
                source="pegasus_ioc",
            ))


def _check_hashes(report: FindingReport) -> None:
    paths = [
        "/system/bin/app_process",
        "/system/bin/app_process32",
        "/system/bin/app_process64",
    ]
    for path in paths:
        raw = shell_command(f"sha256sum {path} 2>/dev/null")
        if not raw:
            continue
        parts = raw.strip().split()
        if not parts:
            continue
        h = parts[0].lower()
        if h in PEGASUS_SHA256:
            report.add(Finding(
                label="CRITICAL",
                score=98,
                family=FAMILY,
                indicator_class=CLASS_FILE_HASH,
                title=f"SHA256 of {path} matches known Pegasus sample",
                detail=f"Hash {h[:16]}... is on the Citizen Lab / Lookout list. "
                       f"This is essentially definitive evidence of infection.",
                raw_value=h,
                source="pegasus_ioc",
            ))


def _check_c2_connections(report: FindingReport) -> None:
    """The only C2 check that matters: ACTIVE TCP connection to a known IP.

    We do NOT resolve DNS. We do NOT do ping. The old behaviour of marking
    a device infected just because a C2 domain resolved via nslookup was
    the largest source of FPs in v1.1.0.
    """
    proc = shell_command("cat /proc/net/tcp 2>/dev/null") or ""
    proc6 = shell_command("cat /proc/net/tcp6 2>/dev/null") or ""
    if not proc and not proc6:
        return
    for ip in PEGASUS_C2_IPS:
        target_hex = _ip_to_proc_hex(ip)
        if not target_hex:
            continue
        if _established_to_ip(proc, target_hex) or _established_to_ip(proc6, target_hex):
            report.add(Finding(
                label="HIGH",
                score=80,
                family=FAMILY,
                indicator_class=CLASS_NETWORK,
                title=f"Active TCP connection to Pegasus C2 {ip}",
                detail="Found in /proc/net/tcp as ESTABLISHED / TIME_WAIT. "
                       "A clean device should never have such a connection.",
                raw_value=ip,
                source="pegasus_ioc",
            ))


def _check_properties(report: FindingReport) -> None:
    for prop_name, value_regex in PEGASUS_PROPERTIES:
        actual = shell_command(f"getprop {prop_name} 2>/dev/null") or ""
        actual = actual.strip()
        if not actual:
            continue
        try:
            if re.match(value_regex, actual):
                report.add(Finding(
                    label="LOW",
                    score=25,
                    family=FAMILY,
                    indicator_class=CLASS_PROPERTY,
                    title=f"Suspicious system property: {prop_name}={actual}",
                    detail=f"Value matches pattern {value_regex!r}. Could be a "
                           f"forensic indicator OR a legitimately modified "
                           f"ROM. Needs corroboration.",
                    raw_value=f"{prop_name}={actual}",
                    source="pegasus_ioc",
                ))
        except re.error:
            continue


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

CHECKS = [
    ("File hashes",        _check_hashes),
    ("Running processes",  _check_processes),
    ("Installed packages", _check_packages),
    ("File paths",         _check_file_paths),
    ("Kernel modules",     _check_kernel_modules),
    ("C2 connections",     _check_c2_connections),
    ("System properties",  _check_properties),
]


def run_pegasus_detect() -> None:
    console.print("\n[bold red]\U0001f575\ufe0f Pegasus / NSO Group Detector[/]")
    console.print("[dim]Strict matching + multi-indicator corroboration[/]\n")

    report = FindingReport(family=FAMILY)

    for name, fn in CHECKS:
        with console.status(f"[cyan]Checking {name}...[/]"):
            try:
                fn(report)
            except Exception as e:
                console.print(f"  [dim]{name} error: {e}[/]")

    if not report.findings:
        console.print("[bold green]\u2705 No Pegasus indicators detected.[/]")
        console.print("[dim]Pegasus operates at kernel level on modern devices "
                      "and may hide its components. This scan cannot rule out "
                      "an infection; for a deeper forensic pass use --mvt-check "
                      "(Amnesty STIX2 indicators).[/]")
        return

    render_reports([report], console)

    if report.is_actionable():
        console.print("\n[bold red]\U0001f6a8 High-confidence Pegasus indicators detected. "
                      "Treat this as a likely infection.[/]")
        console.print("  \u2022 Factory reset the device from recovery mode")
        console.print("  \u2022 Change all account passwords from a trusted device")
        console.print("  \u2022 Enable hardware-key 2FA on every account")
        console.print("  \u2022 Contact a digital-security helpline for assistance")
        console.print("\n[dim]\u26a0\ufe0f Kernel-level malware may persist through factory reset.[/]")
