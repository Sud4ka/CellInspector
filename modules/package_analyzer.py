from typing import List, Tuple, Optional
from core.adb_client import list_packages, shell_command
from core.severity import Severity
from core.ioc_db import (
    SUSPICIOUS_PACKAGES,
    SUSPICIOUS_PACKAGE_PATTERNS,
    SUSPICIOUS_PERMISSIONS_HIGH,
    SUSPICIOUS_PERMISSIONS_MEDIUM,
    KNOWN_MALWARE_PACKAGES,
)


def analyze_packages() -> List[Tuple[Severity, str, str, str, Optional[List[str]], Optional[str]]]:
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

    return findings
