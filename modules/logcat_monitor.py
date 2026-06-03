import re
from typing import List, Tuple, Optional
from core.adb_client import dump_logcat, shell_command
from core.severity import Severity
from core.ioc_db import SUSPICIOUS_LOGCAT_PATTERNS


def analyze_logcat(max_lines: int = 5000) -> List[Tuple[Severity, str, str, str, Optional[List[str]], Optional[str]]]:
    findings = []
    log_output = dump_logcat(max_lines)
    if not log_output:
        findings.append((
            Severity.WARNING,
            "Cannot Access Logcat",
            "Unable to retrieve device logs. Device may be locked.",
            "Logcat",
            None,
            "Unlock the device and try again.",
        ))
        return findings

    lines = log_output.split("\n")
    findings.append((
        Severity.INFO,
        "Logcat Analysis",
        f"Analyzed {len(lines)} log lines",
        "Logcat",
        [f"Total lines: {len(lines)}"],
        None,
    ))

    matched_lines = []
    for i, line in enumerate(lines):
        for pattern in SUSPICIOUS_LOGCAT_PATTERNS:
            if re.search(pattern, line, re.IGNORECASE):
                matched_lines.append((i + 1, line.strip()[:150], pattern))
                break

    if matched_lines:
        details = []
        for lineno, content, pattern in matched_lines[:10]:
            details.append(f"Line {lineno}: {content}")
        if len(matched_lines) > 10:
            details.append(f"... and {len(matched_lines) - 10} more matches")

        findings.append((
            Severity.HIGH,
            "Suspicious Logcat Activity",
            f"Found {len(matched_lines)} log entries matching suspicious patterns",
            "Logcat",
            details,
            "Investigate the applications generating these log entries.",
        ))

    error_count = 0
    crash_count = 0
    anr_count = 0
    for line in lines:
        if "FATAL EXCEPTION" in line or "CRASH" in line.upper():
            crash_count += 1
        elif "ANR" in line and "in" in line:
            anr_count += 1
        elif "E/" in line or "ERROR" in line.upper():
            error_count += 1

    if crash_count > 0:
        findings.append((
            Severity.MEDIUM if crash_count > 5 else Severity.LOW,
            "Application Crashes Detected",
            f"Found {crash_count} crash events in logs",
            "Logcat",
            [f"Crashes: {crash_count}", f"ANRs: {anr_count}", f"Errors: {error_count}"],
            "Check if crashes correlate with any suspicious behavior.",
        ))

    if anr_count > 0:
        sev = Severity.HIGH if anr_count > 3 else Severity.LOW
        findings.append((
            sev,
            "Application Not Responding (ANR) Events",
            f"Found {anr_count} ANR events in logs",
            "Logcat",
            [f"ANRs: {anr_count}"],
            "ANRs may indicate resource-intensive malicious activity.",
        ))

    network_errors = []
    for line in lines:
        if re.search(r"NetworkSecurityConfig|SSL|TLS|certificate.*error|hostname.*verify", line, re.IGNORECASE):
            network_errors.append(line.strip()[:150])
            if len(network_errors) >= 5:
                break

    if network_errors:
        findings.append((
            Severity.MEDIUM,
            "Network Security Errors",
            f"Found network/SSL/TLS errors that may indicate MITM or certificate issues",
            "Logcat",
            network_errors[:5],
            "SSL/TLS errors could indicate a man-in-the-middle attack or malicious app.",
        ))

    return findings
