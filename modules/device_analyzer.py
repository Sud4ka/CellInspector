from typing import List, Tuple, Optional, Dict
from core.adb_client import get_device_info, shell_command, get_prop
from core.severity import Severity


def gather_device_info() -> Dict[str, str]:
    return get_device_info()


def analyze_device_security() -> List[Tuple[Severity, str, str, str, Optional[List[str]], Optional[str]]]:
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
    if security_patch and security_patch != "Unknown":
        findings.append((
            Severity.MEDIUM,
            "Security Patch Level",
            f"Security patch: {security_patch}",
            "Device Security",
            [f"Patch Level: {security_patch}"],
            "Keep the device updated with the latest security patches.",
        ))

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
