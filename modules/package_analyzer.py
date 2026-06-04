from typing import List, Tuple, Optional
from core.adb_client import list_packages, shell_command
from core.severity import Severity
from core.ioc_db import (
    SUSPICIOUS_PACKAGES,
    SUSPICIOUS_PACKAGE_PATTERNS,
    SUSPICIOUS_PERMISSIONS_HIGH,
    SUSPICIOUS_PERMISSIONS_MEDIUM,
    KNOWN_MALWARE_PACKAGES,
    STALKERWARE_PACKAGES,
)

PERMISSION_RISK_COMBOS = [
    {
        "name": "Spyware Combo (Audio + Location + Contacts)",
        "perms": {"RECORD_AUDIO", "ACCESS_FINE_LOCATION", "READ_CONTACTS", "INTERNET"},
        "severity": Severity.CRITICAL,
    },
    {
        "name": "Keylogger/ SMS Spy",
        "perms": {"READ_SMS", "RECEIVE_SMS", "INTERNET", "READ_CONTACTS"},
        "severity": Severity.CRITICAL,
    },
    {
        "name": "Full Surveillance",
        "perms": {"CAMERA", "RECORD_AUDIO", "ACCESS_FINE_LOCATION", "READ_SMS", "READ_CALL_LOG", "INTERNET"},
        "severity": Severity.CRITICAL,
    },
    {
        "name": "Call Recording",
        "perms": {"RECORD_AUDIO", "READ_CALL_LOG", "INTERNET", "READ_PHONE_STATE"},
        "severity": Severity.HIGH,
    },
    {
        "name": "Stalking (Location + Contacts + SMS)",
        "perms": {"ACCESS_FINE_LOCATION", "READ_CONTACTS", "READ_SMS", "INTERNET"},
        "severity": Severity.HIGH,
    },
    {
        "name": "Photo/Video Exfiltration",
        "perms": {"CAMERA", "READ_EXTERNAL_STORAGE", "INTERNET"},
        "severity": Severity.HIGH,
    },
    {
        "name": "Accessibility Abuse",
        "perms": {"BIND_ACCESSIBILITY_SERVICE", "INTERNET"},
        "severity": Severity.HIGH,
    },
    {
        "name": "Overlay Attack (Screen overlay + Internet)",
        "perms": {"SYSTEM_ALERT_WINDOW", "INTERNET"},
        "severity": Severity.MEDIUM,
    },
]


def _get_permissions_for_package(pkg: str) -> list:
    raw = shell_command(f"dumpsys package {pkg} 2>/dev/null | grep -A 500 'requested permissions' || true", timeout=15)
    if not raw:
        return []
    perms = []
    in_section = False
    for line in raw.split("\n"):
        if "requested permissions" in line.lower():
            in_section = True
            continue
        if in_section:
            stripped = line.strip()
            if not stripped or "install permissions" in stripped.lower():
                break
            if "android.permission." in stripped:
                parts = stripped.split()
                if parts:
                    perm_name = parts[0].strip(":")
                    perms.append(perm_name)
    return perms


def _check_permission_combos(pkg: str, perms: list) -> List[Tuple]:
    findings = []
    perm_set = set()
    short_names = set()
    for p in perms:
        perm_set.add(p)
        short = p.replace("android.permission.", "")
        short_names.add(short)

    for combo in PERMISSION_RISK_COMBOS:
        if combo["perms"].issubset(short_names):
            findings.append((
                combo["severity"],
                f"Dangerous permission combo: {combo['name']}",
                f"Package '{pkg}' has a dangerous combination of permissions: {', '.join(sorted(combo['perms']))}",
                "Permissions",
                [f"Package: {pkg}", f"Risk: {combo['name']}", f"Permissions: {', '.join(sorted(combo['perms']))}"],
                "Investigate this app. It has permission patterns consistent with spyware.",
            ))
            break

    return findings


def _check_apk_integrity(pkg: str) -> List[Tuple]:
    findings = []
    path_raw = shell_command(f"pm path {pkg} 2>/dev/null")
    if not path_raw or "package:" not in path_raw:
        return findings
    apk_path = path_raw.replace("package:", "").strip()
    hash_raw = shell_command(f"sha256sum {apk_path} 2>/dev/null || md5sum {apk_path} 2>/dev/null")
    if not hash_raw:
        return findings
    parts = hash_raw.strip().split()
    if not parts:
        return findings
    file_hash = parts[0].lower()

    from core.pegasus_ioc import PEGASUS_SHA256
    from core.ioc_db import KNOWN_MALWARE_PACKAGES

    if file_hash in PEGASUS_SHA256:
        findings.append((
            Severity.CRITICAL,
            "APK Hash Matches Pegasus Malware",
            f"Package '{pkg}' SHA256 matches known Pegasus sample",
            "APK Integrity",
            [f"Package: {pkg}", f"APK path: {apk_path}", f"SHA256: {file_hash}"],
            "Immediately factory reset the device. Pegasus is a state-level spyware.",
        ))

    return findings


def analyze_packages() -> List[Tuple]:
    findings = []
    packages = list_packages()
    if not packages:
        findings.append((
            Severity.WARNING,
            "Cannot Access Package List",
            "Unable to retrieve installed packages from the device.",
            "Packages",
            None,
            "Ensure the device is unlocked and ADB has permission.",
        ))
        return findings

    findings.append((
        Severity.INFO,
        "Installed Packages",
        f"Device has {len(packages)} installed packages",
        "Packages",
        [f"Total packages: {len(packages)}"],
        None,
    ))

    stalkerware_found = []
    for pkg in packages:
        if pkg in KNOWN_MALWARE_PACKAGES:
            findings.append((
                Severity.CRITICAL,
                "Known Malware Package Detected",
                f"Package '{pkg}' is recognized as malware",
                "Packages",
                [f"Package: {pkg}"],
                "Immediately uninstall this package and run a security scan.",
            ))
            continue

        for suspicious in SUSPICIOUS_PACKAGES:
            if suspicious in pkg:
                findings.append((
                    Severity.MEDIUM,
                    "Potentially Suspicious Package",
                    f"Package '{pkg}' matches a known suspicious package pattern",
                    "Packages",
                    [f"Package: {pkg}", f"Matched pattern: {suspicious}"],
                    "Verify the legitimacy of this application. Consider uninstalling if not recognized.",
                ))
                break

        for pattern in SUSPICIOUS_PACKAGE_PATTERNS:
            if pattern.lower() in pkg.lower():
                findings.append((
                    Severity.LOW,
                    "Package Name Raises Suspicion",
                    f"Package '{pkg}' contains suspicious pattern in its name",
                    "Packages",
                    [f"Package: {pkg}", f"Matched pattern: '{pattern}'"],
                    "Investigate this application to ensure it is legitimate.",
                ))
                break

        for stalker in STALKERWARE_PACKAGES:
            if pkg == stalker or pkg.startswith(stalker + ".") or pkg.endswith("." + stalker):
                stalkerware_found.append(pkg)
                findings.append((
                    Severity.CRITICAL,
                    "Stalkerware Detected",
                    f"Package '{pkg}' matches known stalkerware/spyware",
                    "Stalkerware",
                    [f"Package: {pkg}", f"Matches: {stalker}"],
                    "Commercial spyware used for unauthorized monitoring. Immediately uninstall.",
                ))
                break

    if stalkerware_found:
        findings.append((
            Severity.CRITICAL,
            f"Stalkerware Summary",
            f"Found {len(stalkerware_found)} stalkerware app(s) installed",
            "Stalkerware",
            stalkerware_found,
            "These apps can record calls, SMS, location, and more without the user's knowledge.",
        ))

    untrusted_sources = shell_command("pm list packages -u 2>/dev/null | grep -iE 'unknown|unauthorized|third.party' || true", timeout=10)
    if untrusted_sources and "unknown" in untrusted_sources.lower():
        findings.append((
            Severity.MEDIUM,
            "Packages from Unknown Sources",
            "Device has packages installed from unknown/untrusted sources",
            "Packages",
            ["Sideloaded apps may bypass Google Play Protect"],
            "Only install apps from trusted sources like Google Play Store.",
        ))

    perm_check_pkgs = packages[:30] if len(packages) > 30 else packages
    for pkg in perm_check_pkgs:
        perms = _get_permissions_for_package(pkg)
        if perms:
            combo_findings = _check_permission_combos(pkg, perms)
            findings.extend(combo_findings)

    return findings
