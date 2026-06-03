import re
import socket
from typing import List, Tuple, Optional
from core.adb_client import get_tcp_connections, get_udp_connections, resolve_ip
from core.severity import Severity
from core.ioc_db import SUSPICIOUS_IPS, SUSPICIOUS_DOMAIN_PATTERNS, SUSPICIOUS_DOMAINS

PRIVATE_RANGES = [
    ("10.0.0.0", "10.255.255.255"),
    ("172.16.0.0", "172.31.255.255"),
    ("192.168.0.0", "192.168.255.255"),
    ("127.0.0.0", "127.255.255.255"),
]

KNOWN_GOOD_DOMAINS = [
    "google", "android", "whatsapp", "facebook", "instagram",
    "twitter", "x.com", "amazon", "netflix", "spotify",
    "microsoft", "apple", "icloud", "googleapis", "gvt1",
    "gvt2", "gvt3", "l.google", "googleusercontent",
    "ggpht", "googlevideo", "youtube", "gmail",
    "cloudfront", "akamai", "cloudflare",
]


def ip_to_int(ip: str) -> int:
    parts = ip.split(".")
    return (int(parts[0]) << 24) + (int(parts[1]) << 16) + (int(parts[2]) << 8) + int(parts[3])


def is_private_ip(ip: str) -> bool:
    try:
        ip_int = ip_to_int(ip)
        for start, end in PRIVATE_RANGES:
            if ip_to_int(start) <= ip_int <= ip_to_int(end):
                return True
    except (ValueError, IndexError):
        pass
    return False


def is_known_good_domain(domain: str) -> bool:
    domain = domain.lower()
    for good in KNOWN_GOOD_DOMAINS:
        if good in domain:
            return True
    return False


def analyze_network() -> List[Tuple[Severity, str, str, str, Optional[List[str]], Optional[str]]]:
    findings = []
    tcp_conns = get_tcp_connections() or []
    udp_conns = get_udp_connections() or []
    all_conns = tcp_conns + udp_conns

    connected_ips = set()
    for conn in all_conns:
        remote_ip = conn.get("remote_ip", "0.0.0.0")
        if remote_ip == "0.0.0.0":
            continue
        if not is_private_ip(remote_ip):
            connected_ips.add(remote_ip)

    resolved_domains = {}
    for ip in connected_ips:
        domain = resolve_ip(ip)
        if domain:
            resolved_domains[ip] = domain

    for conn in all_conns:
        remote_ip = conn.get("remote_ip", "0.0.0.0")
        remote_port = conn.get("remote_port", "0")
        state = conn.get("state", "")

        if remote_ip == "0.0.0.0" or remote_ip == "0000000000000000":
            continue

        domain = resolved_domains.get(remote_ip, "")

        if state == "LISTEN":
            continue

        if is_private_ip(remote_ip):
            continue

        for suspicious_prefix in SUSPICIOUS_IPS:
            if remote_ip.startswith(suspicious_prefix):
                details = [
                    f"Remote: {remote_ip}:{remote_port}",
                    f"State: {state}",
                    f"Protocol: {conn.get('protocol', 'tcp')}",
                    f"UID: {conn.get('uid', '?')}",
                ]
                if domain:
                    details.append(f"Domain: {domain}")
                findings.append((
                    Severity.HIGH,
                    "Connection to Known Malicious IP",
                    f"Device connected to a known suspicious IP range: {remote_ip}",
                    "Network",
                    details,
                    "Investigate the application using this connection. Consider blocking this IP.",
                ))
                continue

        if domain:
            for pattern in SUSPICIOUS_DOMAIN_PATTERNS:
                if re.search(pattern, domain, re.IGNORECASE):
                    details = [
                        f"Domain: {domain}",
                        f"IP: {remote_ip}:{remote_port}",
                        f"State: {state}",
                    ]
                    findings.append((
                        Severity.MEDIUM,
                        "Connection to Suspicious Domain",
                        f"Device connected to a domain matching suspicious pattern: {domain}",
                        "Network",
                        details,
                        "Verify the legitimacy of this domain.",
                    ))
                    break

        if domain and domain in SUSPICIOUS_DOMAINS:
            details = [
                f"Domain: {domain}",
                f"IP: {remote_ip}:{remote_port}",
                f"State: {state}",
            ]
            findings.append((
                Severity.MEDIUM,
                "Connection to File-Sharing/Paste Site",
                f"Device connected to a known file-sharing or paste site: {domain}",
                "Network",
                details,
                "Check if this connection is expected for any installed app.",
            ))

    if connected_ips:
        est_count = sum(1 for c in all_conns if c.get("state") == "ESTABLISHED" and not is_private_ip(c.get("remote_ip", "")))
        details = [f"Total external endpoints: {len(connected_ips)}"]
        details.append(f"Active connections: {est_count}")
        for ip in sorted(connected_ips)[:10]:
            domain = resolved_domains.get(ip, "")
            label = f"  {ip}:{domain}" if domain else f"  {ip}"
            details.append(label)
        if len(connected_ips) > 10:
            details.append(f"  ... and {len(connected_ips) - 10} more")

        sev = Severity.LOW if est_count > 15 else Severity.INFO
        title = "External Network Connections"
        description = f"Device has {len(connected_ips)} unique external endpoints ({est_count} active connections)"
        findings.append((
            sev,
            title,
            description,
            "Network",
            details,
            None,
        ))

    return findings
