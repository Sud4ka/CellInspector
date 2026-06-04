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
from core.confidence import (
    KNOWN_ANDROID_PROCESSES,
    compute_confidence,
    format_confidence_badge,
    confidence_from_result,
    get_recommendation,
    SKIP_MIN_LENGTH,
)


def _check_processes() -> List[dict]:
    findings = []
    try:
        raw = shell_command("ps -A 2>/dev/null || ps 2>/dev/null")
        if not raw:
            return []
        raw_lower = raw.lower()
        for proc in PEGASUS_PROCESSES:
            if len(proc) < SKIP_MIN_LENGTH:
                continue
            if proc.lower() in KNOWN_ANDROID_PROCESSES:
                continue
            if proc in raw_lower:
                for line in raw.split("\n"):
                    if proc in line.lower():
                        confidence, label = compute_confidence("process_name", proc)
                        if label == "SKIP":
                            continue
                        findings.append({
                            "confidence": confidence,
                            "label": label,
                            "title": f"Process '{proc}' matches Pegasus indicator",
                            "detail": f"Running process: {line.strip()}",
                            "category": "Pegasus",
                        })
    except Exception as e:
        console.print(f"[dim]Process check error: {e}[/]")
    return findings


def _check_packages() -> List[dict]:
    findings = []
    try:
        raw = shell_command("pm list packages 2>/dev/null")
        if not raw:
            return []
        raw_lower = raw.lower()
        for pkg in PEGASUS_PACKAGES:
            exact = f"package:{pkg.lower()}"
            if any(exact == p.strip() for p in raw_lower.split("\n")):
                findings.append({
                    "confidence": 85,
                    "label": "HIGH",
                    "title": f"Package '{pkg}' matches Pegasus indicator",
                    "detail": f"Exact package match: {pkg}",
                    "category": "Pegasus",
                })
    except Exception as e:
        console.print(f"[dim]Package check error: {e}[/]")
    return findings


def _check_file_paths() -> List[dict]:
    findings = []
    for path in PEGASUS_FILE_PATHS:
        try:
            raw = shell_command(f"ls -la {path} 2>/dev/null")
            if raw and "No such file" not in raw:
                findings.append({
                    "confidence": 60,
                    "label": "MEDIUM",
                    "title": f"File path matches Pegasus: {path}",
                    "detail": f"Found on device: {raw.strip()[:200]}",
                    "category": "Pegasus",
                })
        except Exception:
            continue
    return findings


def _check_c2_connectivity() -> List[dict]:
    findings = []
    for domain in PEGASUS_C2_DOMAINS[:5]:
        try:
            raw = shell_command(f"nslookup {domain} 2>/dev/null || ping -c 1 -W 2 {domain} 2>/dev/null")
            if raw and ("Address" in raw or "bytes from" in raw):
                findings.append({
                    "confidence": 80,
                    "label": "HIGH",
                    "title": f"C2 domain reachable: {domain}",
                    "detail": f"Device can resolve/contact known Pegasus C2",
                    "category": "Pegasus",
                })
        except Exception:
            continue
    for ip in PEGASUS_C2_IPS[:5]:
        try:
            raw = shell_command(f"ping -c 1 -W 2 {ip} 2>/dev/null")
            if raw and "bytes from" in raw:
                findings.append({
                    "confidence": 80,
                    "label": "HIGH",
                    "title": f"C2 IP reachable: {ip}",
                    "detail": f"Device can contact known Pegasus C2 IP",
                    "category": "Pegasus",
                })
        except Exception:
            continue
    return findings


def _check_kernel_modules() -> List[dict]:
    findings = []
    try:
        raw = shell_command("lsmod 2>/dev/null || cat /proc/modules 2>/dev/null")
        if not raw:
            return []
        raw_lower = raw.lower()
        for mod in PEGASUS_KERNEL_MODULES:
            if mod in raw_lower:
                findings.append({
                    "confidence": 60,
                    "label": "MEDIUM",
                    "title": f"Kernel module matches Pegasus: {mod}",
                    "detail": f"Loaded module: {mod}",
                    "category": "Pegasus",
                })
    except Exception as e:
        console.print(f"[dim]Kernel module check error: {e}[/]")
    return findings


def _check_hash_matching() -> List[dict]:
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
                findings.append({
                    "confidence": 95,
                    "label": "CRITICAL",
                    "title": f"SHA256 match on {path}",
                    "detail": f"Hash {file_hash[:16]}... matches known Pegasus sample",
                    "category": "Pegasus",
                })
        except Exception:
            continue
    return findings


def run_pegasus_detect() -> None:
    console.print("\n[bold red]\U0001f575\ufe0f Pegasus Spyware Detector[/]")
    console.print("[dim]Analyzing device for indicators of Pegasus / NSO Group[/]\n")

    checks = [
        ("Running processes", _check_processes),
        ("Installed packages", _check_packages),
        ("Known file paths", _check_file_paths),
        ("Kernel modules", _check_kernel_modules),
        ("File hash matching", _check_hash_matching),
        ("C2 connectivity", _check_c2_connectivity),
    ]

    all_findings: List[dict] = []

    for name, func in checks:
        with console.status(f"[cyan]Checking {name}...[/]"):
            findings = func()
            all_findings.extend(findings)

    if not all_findings:
        console.print("\n[bold green]\u2705 No Pegasus indicators detected.[/]")
        console.print("[dim]Note: Pegasus operates at kernel level and may hide its components.[/]")
        console.print("[dim]This scan cannot guarantee the absence of Pegasus infection.[/]")
        return

    overall_label, overall_score = confidence_from_result(
        [(f["confidence"], f["label"]) for f in all_findings]
    )

    console.print(f"\n{'='*55}")
    console.print(f"  [bold]Overall Confidence:[/] {format_confidence_badge(overall_score, overall_label)}")
    console.print(f"{'='*55}\n")

    high_conf = [f for f in all_findings if f["label"] in ("CRITICAL", "HIGH")]
    med_conf = [f for f in all_findings if f["label"] == "MEDIUM"]
    low_conf = [f for f in all_findings if f["label"] == "LOW"]

    console.print(f"  [bold]{len(all_findings)} finding(s):[/] {len(high_conf)} high, {len(med_conf)} medium, {len(low_conf)} low\n")

    for f in sorted(all_findings, key=lambda x: -x["confidence"]):
        badge = format_confidence_badge(f["confidence"], f["label"])
        icon = "\U0001f6a8" if f["label"] in ("CRITICAL", "HIGH") else "\u26a0\ufe0f"
        console.print(f"  {badge} {icon} [bold]{f['title']}[/]")
        console.print(f"          {f['detail']}")

    console.print(f"\n[bold]Recommendation:[/] {get_recommendation(overall_label)}")

    if overall_label in ("CRITICAL", "HIGH"):
        console.print("\n[bold red]\U0001f6a8 High-confidence Pegasus indicators detected. Treat this as a likely infection.[/]")
        console.print("  \u2022 Factory reset the device from recovery mode")
        console.print("  \u2022 Change all account passwords from a trusted device")
        console.print("  \u2022 Enable two-factor authentication on all accounts")
        console.print("  \u2022 Contact a digital security helpline for assistance")
        console.print("\n[dim]\u26a0\ufe0f Kernel-level malware may persist through factory reset.[/]")
    elif overall_label == "MEDIUM":
        console.print("\n[bold orange1]\u26a0\ufe0f Medium confidence. Some indicators found but not conclusive.[/]")
        console.print("  \u2022 Investigate further before concluding infection")
        console.print("  \u2022 Check for unusual data usage, battery drain, or unexpected SMS activity")
        console.print("  \u2022 Consider running a full factory reset if other symptoms appear")
    elif overall_label == "LOW":
        console.print("\n[bold yellow]\u26a0\ufe0f Low confidence only. These may be false positives.[/]")
        console.print("  \u2022 Monitor the device for additional symptoms")
        console.print("  \u2022 Look for corroborating evidence before taking action")
    else:
        console.print(f"\n[bold cyan]\u2139\ufe0f {overall_label} confidence. Informational only.[/]")
