MITRE_MOBILE_MAP = {
    "Network": [
        {"technique_id": "T1437", "technique_name": "Callback", "description": "Application connects to C2 server for instructions or data exfiltration"},
        {"technique_id": "T1476", "technique_name": "Deliver Malicious App via Other Means", "description": "Network connections used to deliver or communicate with malicious components"},
        {"technique_id": "T1432", "technique_name": "Remote Access", "description": "Remote network connections enabling unauthorized access"},
    ],
    "Processes": [
        {"technique_id": "T1503", "technique_name": "Privilege Escalation", "description": "Suspicious processes may indicate privilege escalation attempts"},
        {"technique_id": "T1404", "technique_name": "Exploit via "},
    ],
}

MITRE_MOBILE_MAP = {
    "Network": [
        {"id": "T1437", "name": "Callback", "desc": "Device contacts C2 server"},
        {"id": "T1476", "name": "Deliver Malicious App via Other Means", "desc": "Malicious network communication"},
        {"id": "T1432", "name": "Remote Access", "desc": "Unauthorized remote access"},
    ],
    "Processes": [
        {"id": "T1503", "name": "Privilege Escalation", "desc": "Suspicious process activity"},
        {"id": "T1404", "name": "Exploit via Resource", "desc": "Process-based exploitation"},
    ],
    "Packages": [
        {"id": "T1403", "name": "Download New Code", "desc": "Malicious package installation"},
        {"id": "T1525", "name": "Implant", "desc": "Implanted malicious package"},
        {"id": "T1476", "name": "Deliver Malicious App via Other Means", "desc": "Sideloaded malicious package"},
    ],
    "Logcat": [
        {"id": "T1418", "name": "Software Discovery", "desc": "Logs revealing software info"},
        {"id": "T1412", "name": "Capture Data", "desc": "Data capture visible in logs"},
    ],
    "Notifications": [
        {"id": "T1518", "name": "Notification Listener", "desc": "Notification interception"},
        {"id": "T1519", "name": "Capture Notifications", "desc": "Reading notification data"},
    ],
    "Device Security": [
        {"id": "T1404", "name": "Exploit via Resource", "desc": "Device security weakness"},
        {"id": "T1526", "name": "Native Code", "desc": "System-level compromise"},
    ],
    "Permissions": [
        {"id": "T1429", "name": "Access Sensitive Data", "desc": "Permission abuse for data access"},
        {"id": "T1512", "name": "Abuse Accessibility", "desc": "Accessibility service abuse"},
    ],
    "Stalkerware": [
        {"id": "T1413", "name": "Capture Location", "desc": "GPS location tracking"},
        {"id": "T1412", "name": "Capture Data", "desc": "SMS, call, contact exfiltration"},
        {"id": "T1424", "name": "Capture Audio", "desc": "Audio recording via microphone"},
        {"id": "T1514", "name": "Capture Camera", "desc": "Camera/image capture"},
    ],
    "VPN/Proxy": [
        {"id": "T1572", "name": "Protocol Tunneling", "desc": "VPN/proxy for traffic tunneling"},
        {"id": "T1090", "name": "Proxy", "desc": "Proxy use for C2 communication"},
    ],
    "APK Integrity": [
        {"id": "T1444", "name": "Masquerade as Legitimate App", "desc": "Tampered APK masquerading"},
        {"id": "T1525", "name": "Implant", "desc": "Malicious code in APK"},
    ],
    "Pegasus": [
        {"id": "T1404", "name": "Exploit via Resource", "desc": "Kernel-level compromise"},
        {"id": "T1503", "name": "Privilege Escalation", "desc": "Root privilege escalation"},
        {"id": "T1412", "name": "Capture Data", "desc": "Comprehensive data capture"},
        {"id": "T1572", "name": "Protocol Tunneling", "desc": "Encrypted C2 tunneling"},
    ],
    "CVE Scanner": [
        {"id": "T1503", "name": "Privilege Escalation", "desc": "Unpatched CVE exploitation"},
        {"id": "T1404", "name": "Exploit via Resource", "desc": "Known vulnerability exploitation"},
    ],
}


def get_techniques(category: str) -> list:
    return MITRE_MOBILE_MAP.get(category, [])


def get_technique_ids(category: str) -> list:
    return [t["id"] for t in get_techniques(category)]


def get_all_categories() -> list:
    return list(MITRE_MOBILE_MAP.keys())
