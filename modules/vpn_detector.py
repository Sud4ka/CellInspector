from typing import List, Tuple, Optional
from core.adb_client import shell_command, get_prop
from core.severity import Severity


def analyze_vpn_proxy() -> List[Tuple]:
    findings = []

    vpn_interfaces = shell_command("ip -o link show 2>/dev/null | grep -iE 'tun|tap|ppp|vpn' || true")
    if vpn_interfaces and vpn_interfaces.strip():
        ifaces = [l.split(":")[1].strip() if ":" in l else l.strip() for l in vpn_interfaces.strip().split("\n") if l.strip()]
        findings.append((
            Severity.MEDIUM,
            "VPN Interface Detected",
            f"Device has {len(ifaces)} VPN/tunnel interface(s): {', '.join(ifaces)}",
            "VPN/Proxy",
            [f"Interfaces: {ifaces}"],
            "Verify the VPN is trusted. Spyware often uses VPNs to exfiltrate data.",
        ))

    vpn_packages = [
        "com.wireguard.android", "org.openvpn", "de.blinkt.openvpn",
        "net.openvpn", "app.openvpn", "com.expressvpn.vpn",
        "com.nordvpn.android", "com.windscribe.vpn", "com.protonvpn.android",
        "com.cloudflare.onedotonedotonedotone", "org.torproject.android",
        "org.torproject.torbrowser", "org.torproject", "info.guardianproject.orfox",
        "com.psiphon3", "com.psiphon3.subscription",
    ]
    raw = shell_command("pm list packages 2>/dev/null")
    installed_pkgs = raw.split("\n") if raw else []
    detected_vpns = []
    for line in installed_pkgs:
        pkg = line.replace("package:", "").strip()
        for vpn_pkg in vpn_packages:
            if pkg == vpn_pkg or pkg.startswith(vpn_pkg):
                detected_vpns.append(pkg)
                break
    if detected_vpns:
        findings.append((
            Severity.INFO,
            "VPN/Proxy Apps Installed",
            f"Found {len(detected_vpns)} VPN/proxy/tor application(s): {', '.join(detected_vpns)}",
            "VPN/Proxy",
            detected_vpns,
            "These apps can be used to anonymize traffic but also by spyware to hide C2 communication.",
        ))

    proxy_check = shell_command("settings get global http_proxy 2>/dev/null || echo 'none'")
    if proxy_check and proxy_check.strip() not in ("", "none", ":0", "null"):
        findings.append((
            Severity.HIGH,
            "Global HTTP Proxy Configured",
            f"Device has a global HTTP proxy set: {proxy_check.strip()}",
            "VPN/Proxy",
            [f"Proxy: {proxy_check.strip()}"],
            "A global proxy can intercept all device traffic. Remove if not intentionally configured.",
        ))

    orbot_check = shell_command("pm list packages 2>/dev/null | grep -i 'tor\\|orfox' || true")
    if orbot_check:
        findings.append((
            Severity.MEDIUM,
            "Tor/Orbot Detected",
            "Tor anonymization network tools are installed on this device",
            "VPN/Proxy",
            [f"Packages: {orbot_check.strip()}"],
            "Tor can be used for legitimate privacy or by spyware to anonymize C2 traffic.",
        ))

    iptunnel = shell_command("ip tunnel show 2>/dev/null || ip -o tunnel show 2>/dev/null || true")
    if iptunnel and iptunnel.strip():
        findings.append((
            Severity.MEDIUM,
            "IP Tunnel Interfaces Found",
            f"Device has IP tunnel interfaces that can encapsulate traffic",
            "VPN/Proxy",
            [f"Tunnels: {iptunnel.strip()[:200]}"],
            "Tunnels can bypass network monitoring and indicate data exfiltration.",
        ))

    if not findings:
        findings.append((
            Severity.INFO,
            "No VPN/Proxy Detected",
            "No VPN tunnels, proxies, or Tor connections found",
            "VPN/Proxy",
            None,
            None,
        ))

    return findings
