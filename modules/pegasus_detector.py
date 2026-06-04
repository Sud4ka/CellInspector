import time
from typing import List, Tuple

from core.display import console
from core.adb_client import shell_command
from core.severity import Severity
from core.pegasus_ioc import (
    PEGASUS_SHA256,
    PEGASUS_PACKAGES,
    PEGASUS_PROCESSES,
    PEGASUS_FILE_PATHS,
    PEGASUS_C2_IPS,
    PEGASUS_C2_DOMAINS,
    PEGASUS_KERNEL_MODULES,
)


def _check_processes() -> List[Tuple]:
    findings = []
    try:
        raw = shell_command("ps -A 2>/dev/null || ps 2>/dev/null")
        if not raw:
            return []
        raw_lower = raw.lower()
        for proc in PEGASUS_PROCESSES:
            if proc in raw_lower:
                for line in raw.split("\n"):
                    if proc in line.lower():
                        findings.append((
                            Severity.CRITICAL,
                            f"Pegasus process detected: {proc}",
                            f"Running process matches known Pegasus indicator: {line.strip()}",
                            "Pegasus",
                        ))
    except Exception as e:
        console.print(f"[dim]Process check error: {e}[/]")
    return findings


def _check_packages() -> List[Tuple]:
    findings = []
    try:
        raw = shell_command("pm list packages 2>/dev/null")
        if not raw:
            return []
        raw_lower = raw.lower()
        for pkg in PEGASUS_PACKAGES:
            if pkg in raw_lower:
                findings.append((
                    Severity.CRITICAL,
                    f"Pegasus package detected: {pkg}",
                    f"Installed package matches known Pegasus indicator: {pkg}",
                    "Pegasus",
                ))
    except Exception as e:
        console.print(f"[dim]Package check error: {e}[/]")
    return findings


def _check_file_paths() -> List[Tuple]:
    findings = []
    for path in PEGASUS_FILE_PATHS:
        try:
            raw = shell_command(f"ls -la {path} 2>/dev/null")
            if raw and "No such file" not in raw:
                findings.append((
                    Severity.CRITICAL,
                    f"Suspicious file found: {path}",
                    f"Known Pegasus path exists on device: {raw.strip()[:200]}",
                    "Pegasus",
                ))
        except Exception:
            continue
    return findings


def _check_c2_connectivity() -> List[Tuple]:
    findings = []
    for domain in PEGASUS_C2_DOMAINS[:5]:
        try:
            raw = shell_command(f"nslookup {domain} 2>/dev/null || ping -c 1 -W 2 {domain} 2>/dev/null")
            if raw and ("Address" in raw or "bytes from" in raw):
                findings.append((
                    Severity.CRITICAL,
                    f"Pegasus C2 reachable: {domain}",
                    f"Device can resolve/contact known Pegasus C2 server: {domain}",
                    "Pegasus",
                ))
        except Exception:
            continue
    for ip in PEGASUS_C2_IPS[:5]:
        try:
            raw = shell_command(f"ping -c 1 -W 2 {ip} 2>/dev/null")
            if raw and "bytes from" in raw:
                findings.append((
                    Severity.CRITICAL,
                    f"Pegasus C2 reachable: {ip}",
                    f"Device can contact known Pegasus C2 IP: {ip}",
                    "Pegasus",
                ))
        except Exception:
            continue
    return findings


def _check_kernel_modules() -> List[Tuple]:
    findings = []
    try:
        raw = shell_command("lsmod 2>/dev/null || cat /proc/modules 2>/dev/null")
        if not raw:
            return []
        raw_lower = raw.lower()
        for mod in PEGASUS_KERNEL_MODULES:
            if mod in raw_lower:
                findings.append((
                    Severity.CRITICAL,
                    f"Pegasus kernel module: {mod}",
                    f"Loaded kernel module matches known Pegasus component: {mod}",
                    "Pegasus",
                ))
    except Exception as e:
        console.print(f"[dim]Kernel module check error: {e}[/]")
    return findings


def _check_hash_matching() -> List[Tuple]:
    findings = []
    paths_to_hash = [
        "/system/bin/app_process",
        "/system/bin/app_process32",
        "/system/bin/app_process64",
        "/system/lib/libandroid_runtime.so",
        "/system/lib64/libandroid_runtime.so",
    ]
    for path in paths_to_hash:
        try:
            raw = shell_command(f"sha256sum {path} 2>/dev/null || md5sum {path} 2>/dev/null")
            if not raw:
                continue
            parts = raw.strip().split()
            if not parts:
                continue
            file_hash = parts[0].lower()
            if file_hash in PEGASUS_SHA256:
                findings.append((
                    Severity.CRITICAL,
                    f"File hash match: {path}",
                    f"SHA256 {file_hash} matches known Pegasus sample",
                    "Pegasus",
                ))
        except Exception:
            continue
    return findings


def run_pegasus_detect() -> None:
    console.print("\n[bold red]\U0001f575\ufe0f Pegasus Spyware Detector[/]")
    console.print("[dim]Checking device for indicators of compromise...[/]\n")

    checks = [
        ("Running processes", _check_processes),
        ("Installed packages", _check_packages),
        ("Known file paths", _check_file_paths),
        ("Kernel modules", _check_kernel_modules),
        ("File hash matching", _check_hash_matching),
        ("C2 connectivity", _check_c2_connectivity),
    ]

    all_findings: List[Tuple] = []

    for name, func in checks:
        with console.status(f"[cyan]Checking {name}...[/]"):
            findings = func()
            all_findings.extend(findings)

    if not all_findings:
        console.print("\n[bold green]\u2705 No Pegasus indicators detected.[/]")
        console.print("[dim]Note: Pegasus operates at kernel level and may hide its components.[/]")
        console.print("[dim]This scan cannot guarantee the absence of Pegasus infection.[/]")
        return

    console.print(f"\n[bold red]\U0001f6a8 {len(all_findings)} Pegasus indicator(s) found![/]")
    for finding in all_findings:
        sev, title, desc, category = finding
        console.print(f"  [red]\u2713[/] [bold]{title}[/]")
        console.print(f"       {desc}")

    console.print("\n[bold yellow]\U0001f4a1 Recommended actions:[/]")
    console.print("  \u2022 Factory reset the device immediately")
    console.print("  \u2022 Change all account passwords from a trusted device")
    console.print("  \u2022 Enable two-factor authentication on all accounts")
    console.print("  \u2022 Contact a digital security helpline for assistance")
    console.print("  \u2022 Consider replacing the device if possible")
    console.print("\n[dim]\u26a0\ufe0f Pegasus infections are difficult to remove. Factory reset may not be sufficient.[/]")
