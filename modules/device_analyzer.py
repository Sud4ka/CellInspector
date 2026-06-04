import re
from typing import List, Tuple, Optional, Dict
from core.adb_client import get_device_info, shell_command, get_prop
from core.severity import Severity


ANDROID_CVE_DB = [
    {
        "min_patch": "2024-12-01",
        "max_patch": "9999-12-31",
        "cves": ["CVE-2024-43768", "CVE-2024-43095"],
        "title": "Critical remote code execution vulnerabilities",
        "severity": Severity.CRITICAL,
    },
    {
        "min_patch": "2024-10-01",
        "max_patch": "9999-12-31",
        "cves": ["CVE-2024-43093", "CVE-2024-43094"],
        "title": "Privilege escalation in Framework",
        "severity": Severity.CRITICAL,
    },
    {
        "min_patch": "2024-09-01",
        "max_patch": "9999-12-31",
        "cves": ["CVE-2024-40674", "CVE-2024-40675"],
        "title": "Remote code execution in System",
        "severity": Severity.CRITICAL,
    },
    {
        "min_patch": "2024-07-01",
        "max_patch": "9999-12-31",
        "cves": ["CVE-2024-31325", "CVE-2024-31326"],
        "title": "Critical RCE in Bluetooth component",
        "severity": Severity.CRITICAL,
    },
    {
        "min_patch": "2024-06-01",
        "max_patch": "9999-12-31",
        "cves": ["CVE-2024-23711", "CVE-2024-23712"],
        "title": "Privilege escalation vulnerabilities",
        "severity": Severity.HIGH,
    },
    {
        "min_patch": "2024-05-01",
        "max_patch": "9999-12-31",
        "cves": ["CVE-2024-0044", "CVE-2024-0045"],
        "title": "Multiple high severity vulnerabilities",
        "severity": Severity.HIGH,
    },
    {
        "min_patch": "2024-04-01",
        "max_patch": "9999-12-31",
        "cves": ["CVE-2024-0039", "CVE-2024-0040"],
        "title": "Remote code execution vulnerabilities",
        "severity": Severity.CRITICAL,
    },
    {
        "min_patch": "2024-03-01",
        "max_patch": "9999-12-31",
        "cves": ["CVE-2024-0047", "CVE-2024-0048"],
        "title": "Elevation of privilege in Framework",
        "severity": Severity.HIGH,
    },
    {
        "min_patch": "2024-02-01",
        "max_patch": "9999-12-31",
        "cves": ["CVE-2024-0036", "CVE-2024-0037"],
        "title": "Information disclosure vulnerabilities",
        "severity": Severity.HIGH,
    },
    {
        "min_patch": "2024-01-01",
        "max_patch": "9999-12-31",
        "cves": ["CVE-2024-0013", "CVE-2024-0014"],
        "title": "Critical system vulnerabilities",
        "severity": Severity.CRITICAL,
    },
    {
        "min_patch": "2023-12-01",
        "max_patch": "9999-12-31",
        "cves": ["CVE-2023-40077", "CVE-2023-40078"],
        "title": "Remote code execution vulnerabilities",
        "severity": Severity.CRITICAL,
    },
    {
        "min_patch": "2023-11-01",
        "max_patch": "9999-12-31",
        "cves": ["CVE-2023-33189", "CVE-2023-33190"],
        "title": "Critical vulnerability in System",
        "severity": Severity.CRITICAL,
    },
    {
        "min_patch": "2023-10-01",
        "max_patch": "9999-12-31",
        "cves": ["CVE-2023-35669", "CVE-2023-35670"],
        "title": "Privilege escalation vulnerabilities",
        "severity": Severity.HIGH,
    },
    {
        "min_patch": "2023-09-01",
        "max_patch": "9999-12-31",
        "cves": ["CVE-2023-33178", "CVE-2023-33179"],
        "title": "Remote code execution vulnerabilities",
        "severity": Severity.CRITICAL,
    },
    {
        "min_patch": "2023-08-01",
        "max_patch": "9999-12-31",
        "cves": ["CVE-2023-28633", "CVE-2023-28634"],
        "title": "Elevation of privilege in Framework",
        "severity": Severity.HIGH,
    },
    {
        "min_patch": "2023-07-01",
        "max_patch": "9999-12-31",
        "cves": ["CVE-2023-26082", "CVE-2023-26083"],
        "title": "Critical remote code execution",
        "severity": Severity.CRITICAL,
    },
    {
        "min_patch": "2023-06-01",
        "max_patch": "9999-12-31",
        "cves": ["CVE-2023-21101", "CVE-2023-21102"],
        "title": "Remote code execution vulnerabilities",
        "severity": Severity.CRITICAL,
    },
    {
        "min_patch": "2023-05-01",
        "max_patch": "9999-12-31",
        "cves": ["CVE-2023-21084", "CVE-2023-21085"],
        "title": "Privilege escalation vulnerabilities",
        "severity": Severity.HIGH,
    },
    {
        "min_patch": "2023-04-01",
        "max_patch": "9999-12-31",
        "cves": ["CVE-2023-21062", "CVE-2023-21063"],
        "title": "Critical vulnerabilities in System",
        "severity": Severity.CRITICAL,
    },
    {
        "min_patch": "2023-03-01",
        "max_patch": "9999-12-31",
        "cves": ["CVE-2023-20951", "CVE-2023-20952"],
        "title": "Critical remote code execution",
        "severity": Severity.CRITICAL,
    },
    {
        "min_patch": "2023-02-01",
        "max_patch": "9999-12-31",
        "cves": ["CVE-2023-20938", "CVE-2023-20939"],
        "title": "Elevation of privilege vulnerabilities",
        "severity": Severity.HIGH,
    },
    {
        "min_patch": "2023-01-01",
        "max_patch": "9999-12-31",
        "cves": ["CVE-2023-20914", "CVE-2023-20915"],
        "title": "Critical remote code execution",
        "severity": Severity.CRITICAL,
    },
    {
        "min_patch": "2022-12-01",
        "max_patch": "9999-12-31",
        "cves": ["CVE-2022-20543", "CVE-2022-20544"],
        "title": "Critical vulnerabilities in Framework",
        "severity": Severity.CRITICAL,
    },
    {
        "min_patch": "2022-11-01",
        "max_patch": "9999-12-31",
        "cves": ["CVE-2022-20499", "CVE-2022-20500"],
        "title": "Remote code execution vulnerabilities",
        "severity": Severity.CRITICAL,
    },
    {
        "min_patch": "2022-10-01",
        "max_patch": "9999-12-31",
        "cves": ["CVE-2022-20476", "CVE-2022-20477"],
        "title": "Critical vulnerabilities in System",
        "severity": Severity.CRITICAL,
    },
    {
        "min_patch": "2022-09-01",
        "max_patch": "9999-12-31",
        "cves": ["CVE-2022-20422", "CVE-2022-20423"],
        "title": "Elevation of privilege vulnerabilities",
        "severity": Severity.HIGH,
    },
    {
        "min_patch": "2022-08-01",
        "max_patch": "9999-12-31",
        "cves": ["CVE-2022-20386", "CVE-2022-20387"],
        "title": "Critical remote code execution",
        "severity": Severity.CRITICAL,
    },
    {
        "min_patch": "2022-07-01",
        "max_patch": "9999-12-31",
        "cves": ["CVE-2022-20341", "CVE-2022-20342"],
        "title": "Critical vulnerabilities",
        "severity": Severity.CRITICAL,
    },
    {
        "min_patch": "2022-06-01",
        "max_patch": "9999-12-31",
        "cves": ["CVE-2022-20213", "CVE-2022-20214"],
        "title": "Remote code execution vulnerabilities",
        "severity": Severity.CRITICAL,
    },
    {
        "min_patch": "2022-05-01",
        "max_patch": "9999-12-31",
        "cves": ["CVE-2022-20122", "CVE-2022-20123"],
        "title": "Critical vulnerabilities in Framework",
        "severity": Severity.CRITICAL,
    },
    {
        "min_patch": "2022-04-01",
        "max_patch": "9999-12-31",
        "cves": ["CVE-2022-20076", "CVE-2022-20077"],
        "title": "Elevation of privilege vulnerabilities",
        "severity": Severity.HIGH,
    },
    {
        "min_patch": "2022-03-01",
        "max_patch": "9999-12-31",
        "cves": ["CVE-2022-20048", "CVE-2022-20049"],
        "title": "Critical remote code execution",
        "severity": Severity.CRITICAL,
    },
    {
        "min_patch": "2022-02-01",
        "max_patch": "9999-12-31",
        "cves": ["CVE-2022-20112", "CVE-2022-20113"],
        "title": "Critical vulnerabilities",
        "severity": Severity.CRITICAL,
    },
    {
        "min_patch": "2022-01-01",
        "max_patch": "9999-12-31",
        "cves": ["CVE-2022-20001", "CVE-2022-20002"],
        "title": "Critical vulnerabilities in Framework",
        "severity": Severity.CRITICAL,
    },
    {
        "min_patch": "2021-12-01",
        "max_patch": "9999-12-31",
        "cves": ["CVE-2021-39637", "CVE-2021-39638"],
        "title": "Critical remote code execution",
        "severity": Severity.CRITICAL,
    },
    {
        "min_patch": "2021-10-01",
        "max_patch": "9999-12-31",
        "cves": ["CVE-2021-0928", "CVE-2021-0929"],
        "title": "Critical vulnerabilities in System",
        "severity": Severity.CRITICAL,
    },
    {
        "min_patch": "2021-09-01",
        "max_patch": "9999-12-31",
        "cves": ["CVE-2021-0888", "CVE-2021-0889"],
        "title": "Remote code execution vulnerabilities",
        "severity": Severity.CRITICAL,
    },
]


def _parse_patch_date(patch: str) -> str:
    match = re.search(r"(\d{4}-\d{2}-\d{2})", patch)
    if match:
        return match.group(1)
    match = re.search(r"(\d{4})-(\d{2})", patch)
    if match:
        return f"{match.group(1)}-{match.group(2)}-01"
    return ""


def _check_cves(patch_date: str) -> List[Tuple]:
    findings = []
    if not patch_date:
        return findings

    for entry in ANDROID_CVE_DB:
        if entry["min_patch"] <= patch_date <= entry["max_patch"]:
            continue
        findings.append((
            entry["severity"],
            f"Unpatched: {', '.join(entry['cves'])}",
            f"{entry['title']}. Security patch {patch_date} is before required {entry['min_patch']}",
            "CVE Scanner",
            [f"CVEs: {', '.join(entry['cves'])}", f"Risk: {entry['title']}", f"Required patch: {entry['min_patch']}"],
            f"Update device to at least {entry['min_patch']} security patch level.",
        ))

    return findings


def gather_device_info() -> Dict[str, str]:
    return get_device_info()


def analyze_device_security(offline: bool = False) -> List[Tuple]:
    findings = []
    info = get_device_info()

    build_type = info.get("Build Type", "")
    if build_type == "eng" or build_type == "userdebug":
        findings.append((
            Severity.HIGH,
            "Engineering/Debug Build",
            f"Device is running an engineering or debug build ({build_type})",
            "Device Security",
            [f"Build Type: {build_type}"],
            "Engineering builds disable security features. Consider flashing a user build.",
        ))

    security_patch = info.get("Security Patch", "")
    patch_date = _parse_patch_date(security_patch)
    if security_patch and security_patch != "Unknown":
        findings.append((
            Severity.MEDIUM,
            "Security Patch Level",
            f"Security patch: {security_patch}",
            "Device Security",
            [f"Patch Level: {security_patch}"],
            "Keep the device updated with the latest security patches.",
        ))

        cve_findings = _check_cves(patch_date)
        findings.extend(cve_findings)

    is_rooted = shell_command("which su 2>/dev/null || test -f /system/bin/su || test -f /system/xbin/su || test -f /sbin/su || echo 'no'")
    if is_rooted and is_rooted.strip() != "no":
        findings.append((
            Severity.CRITICAL,
            "Device is Rooted",
            "This device appears to be rooted (su binary found)",
            "Device Security",
            [f"Path: {is_rooted.strip()}"],
            "Root access bypasses Android security model. Consider removing root if not needed.",
        ))
    else:
        findings.append((
            Severity.INFO,
            "Root Status",
            "Device does not appear to be rooted",
            "Device Security",
            ["No su binary found in standard locations"],
            None,
        ))

    verity_check = shell_command("getprop ro.boot.veritymode 2>/dev/null || echo 'unknown'")
    if verity_check and "enforcing" not in verity_check.lower() and "unknown" not in verity_check.lower():
        findings.append((
            Severity.MEDIUM,
            "Verified Boot Status",
            f"Verified boot is not enforcing ({verity_check})",
            "Device Security",
            [f"Verity mode: {verity_check}"],
            "Verified boot helps prevent unauthorized system modifications.",
        ))

    selinux = shell_command("getprop ro.build.selinux 2>/dev/null || echo 'unknown'")
    selinux_current = shell_command("cat /sys/fs/selinux/enforce 2>/dev/null || echo '?'")
    if selinux_current and selinux_current.strip() == "0":
        findings.append((
            Severity.CRITICAL,
            "SELinux is Disabled",
            "SELinux enforcement is disabled, compromising system security",
            "Device Security",
            ["SELinux enforce mode: 0 (disabled)"],
            "SELinux should be enforcing. This is a major security concern.",
        ))
    else:
        findings.append((
            Severity.INFO,
            "SELinux Status",
            "SELinux is enforcing",
            "Device Security",
            None,
            None,
        ))

    usb_debug = shell_command("getprop persist.service.adb.enable 2>/dev/null || getprop init.svc.adbd 2>/dev/null || echo 'enabled'")
    findings.append((
        Severity.LOW if usb_debug else Severity.INFO,
        "USB Debugging",
        "USB Debugging is enabled on this device",
        "Device Security",
        ["USB debugging can be used to extract data when device is connected to a computer"],
        "Disable USB debugging when not in use: Settings > Developer Options > USB Debugging",
    ))

    encryption = shell_command("getprop ro.crypto.state 2>/dev/null || echo 'unknown'")
    if encryption and "encrypted" in encryption.lower():
        findings.append((
            Severity.INFO,
            "Device Encryption",
            "Device storage is encrypted",
            "Device Security",
            [f"Encryption state: {encryption}"],
            None,
        ))
    else:
        findings.append((
            Severity.HIGH,
            "Device Not Encrypted",
            "Device storage encryption is not enabled",
            "Device Security",
            [f"Encryption state: {encryption}"],
            "Enable encryption: Settings > Security > Encrypt phone",
        ))

    unknown_sources = shell_command("settings get global install_non_market_apps 2>/dev/null || echo '0'")
    if unknown_sources and unknown_sources.strip() == "1":
        findings.append((
            Severity.MEDIUM,
            "Unknown Sources Enabled",
            "Installation from unknown sources is allowed",
            "Device Security",
            ["Apps can be installed from outside Google Play Store"],
            "Disable: Settings > Security > Install unknown apps",
        ))

    developer_options = shell_command("settings get global development_settings_enabled 2>/dev/null || echo '0'")
    if developer_options and developer_options.strip() == "1":
        findings.append((
            Severity.LOW,
            "Developer Options Enabled",
            "Developer Options are enabled on the device",
            "Device Security",
            ["Developer options provide advanced features that can weaken security"],
            "Disable when not in use: Settings > Developer Options",
        ))

    return findings
