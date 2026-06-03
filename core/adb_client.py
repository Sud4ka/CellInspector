import subprocess
import os
import re
import random
import time
from typing import Optional, List, Dict, Tuple

ADB_PATH = "/usr/bin/adb"
SUDO_PASSWORD = (
    os.environ.get("CELLINSPECTOR_SUDO_PASSWORD")
    or os.environ.get("SUDO_PASSWORD")
    or "M3 siento tan triste!"
)

_wireless_connections: List[str] = []


def _run_adb_command(args: List[str], timeout: int = 30, no_pw: bool = False) -> Optional[str]:
    try:
        if no_pw:
            cmd = [ADB_PATH] + args
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        else:
            cmd = ["sudo", "-S"] + [ADB_PATH] + args
            proc = subprocess.run(
                cmd,
                input=f"{SUDO_PASSWORD}\n",
                capture_output=True,
                text=True,
                timeout=timeout,
            )
        if proc.returncode != 0:
            return None
        return proc.stdout.strip()
    except (subprocess.TimeoutExpired, subprocess.CalledProcessError):
        return None


def get_devices() -> List[Dict[str, str]]:
    output = _run_adb_command(["devices", "-l"])
    if not output:
        return []
    devices = []
    for line in output.split("\n")[1:]:
        line = line.strip()
        if not line or line == "":
            continue
        parts = line.split()
        device = {"serial": parts[0], "status": parts[1] if len(parts) > 1 else "unknown"}
        for p in parts[2:]:
            if ":" in p:
                k, v = p.split(":", 1)
                device[k] = v
        devices.append(device)
    return devices


def is_device_ready() -> bool:
    devices = get_devices()
    for d in devices:
        if d.get("status") == "device":
            return True
    return False


def shell_command(command: str, timeout: int = 30) -> Optional[str]:
    return _run_adb_command(["shell", command], timeout=timeout)


def get_prop(prop: str) -> Optional[str]:
    return shell_command(f"getprop {prop}")


def list_packages() -> Optional[List[str]]:
    output = shell_command("pm list packages")
    if not output:
        return None
    packages = []
    for line in output.split("\n"):
        line = line.strip()
        if line.startswith("package:"):
            packages.append(line[8:])
    return packages


def list_processes() -> Optional[List[Dict[str, str]]]:
    output = shell_command("ps -A 2>/dev/null || ps")
    if not output:
        return None
    lines = output.strip().split("\n")
    if not lines:
        return None
    header = lines[0].split()
    processes = []
    for line in lines[1:]:
        line = line.strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) >= 9:
            proc = {
                "user": parts[0],
                "pid": parts[1],
                "ppid": parts[2],
                "vsz": parts[3],
                "rss": parts[4],
                "name": parts[-1],
            }
            processes.append(proc)
    return processes


def get_tcp_connections() -> Optional[List[Dict[str, str]]]:
    output = shell_command("cat /proc/net/tcp 2>/dev/null")
    if not output:
        return None
    connections = []
    for line in output.strip().split("\n")[1:]:
        line = line.strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) >= 10:
            local = parts[1]
            remote = parts[2]
            state = parts[3]
            uid = parts[7]
            local_ip, local_port = parse_hex_socket(local)
            remote_ip, remote_port = parse_hex_socket(remote)
            connections.append({
                "local_ip": local_ip,
                "local_port": local_port,
                "remote_ip": remote_ip,
                "remote_port": remote_port,
                "state": decode_tcp_state(state),
                "uid": uid,
                "protocol": "tcp",
            })
    return connections


def get_udp_connections() -> Optional[List[Dict[str, str]]]:
    output = shell_command("cat /proc/net/udp 2>/dev/null")
    if not output:
        return None
    connections = []
    for line in output.strip().split("\n")[1:]:
        line = line.strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) >= 10:
            local = parts[1]
            remote = parts[2]
            state = parts[3]
            uid = parts[7]
            local_ip, local_port = parse_hex_socket(local)
            remote_ip, remote_port = parse_hex_socket(remote)
            connections.append({
                "local_ip": local_ip,
                "local_port": local_port,
                "remote_ip": remote_ip,
                "remote_port": remote_port,
                "state": decode_tcp_state(state),
                "uid": uid,
                "protocol": "udp",
            })
    return connections


def parse_hex_socket(hex_str: str) -> tuple:
    parts = hex_str.split(":")
    if len(parts) != 2:
        return ("0.0.0.0", "0")
    ip_hex = parts[0]
    port_hex = parts[1]
    try:
        port = str(int(port_hex, 16))
    except ValueError:
        port = "0"
    ip_parts = []
    for i in range(0, 8, 2):
        try:
            ip_parts.append(str(int(ip_hex[i:i+2], 16)))
        except ValueError:
            ip_parts.append("0")
    ip = ".".join(ip_parts)
    return (ip, port)


def decode_tcp_state(hex_state: str) -> str:
    states = {
        "01": "ESTABLISHED",
        "02": "SYN_SENT",
        "03": "SYN_RECV",
        "04": "FIN_WAIT1",
        "05": "FIN_WAIT2",
        "06": "TIME_WAIT",
        "07": "CLOSE",
        "08": "CLOSE_WAIT",
        "09": "LAST_ACK",
        "0A": "LISTEN",
        "0B": "CLOSING",
    }
    return states.get(hex_state.strip(), hex_state)


def get_netstat() -> Optional[str]:
    return shell_command("netstat -an 2>/dev/null || ss -tuan 2>/dev/null")


def dump_logcat(max_lines: int = 5000) -> Optional[str]:
    return shell_command(f"logcat -d -t {max_lines} 2>/dev/null", timeout=15)


def get_package_permissions(package: str) -> Optional[List[str]]:
    output = shell_command(f"dumpsys package {package} 2>/dev/null | grep -i 'permission:'", timeout=10)
    if not output:
        return None
    perms = []
    for line in output.split("\n"):
        line = line.strip()
        if "permission:" in line:
            perm = line.split("permission:")[-1].strip()
            if perm:
                perms.append(perm)
    return perms


def resolve_ip(ip: str) -> Optional[str]:
    try:
        import socket
        result = socket.gethostbyaddr(ip)
        return result[0] if result else None
    except (socket.herror, socket.gaierror, OSError):
        return None


def get_device_info() -> Dict[str, str]:
    info = {}
    props = [
        ("ro.product.manufacturer", "Manufacturer"),
        ("ro.product.model", "Model"),
        ("ro.build.version.release", "Android Version"),
        ("ro.build.version.sdk", "API Level"),
        ("ro.build.version.security_patch", "Security Patch"),
        ("ro.build.type", "Build Type"),
        ("ro.serialno", "Serial"),
        ("ro.product.cpu.abi", "CPU ABI"),
        ("ro.product.name", "Product Name"),
    ]
    for prop, label in props:
        val = get_prop(prop)
        info[label] = val or "Unknown"

    locale = get_device_locale()
    if locale:
        info["Language"] = locale

    return info


def get_device_locale() -> Optional[str]:
    for cmd in (
        "getprop persist.sys.locale 2>/dev/null",
        "getprop ro.product.locale 2>/dev/null",
        "settings get system system_locales 2>/dev/null",
    ):
        result = shell_command(cmd)
        if result and result.strip() and "not found" not in result.lower():
            raw = result.strip().split(",")[0].replace("-", "_").split("_")[0]
            if len(raw) == 2 and raw.isalpha():
                return raw
    return None


def kill_process(pid: str) -> bool:
    result = shell_command(f"kill {pid} 2>/dev/null && echo 'OK' || echo 'FAIL'")
    return result is not None and "OK" in result


def force_stop_package(package: str) -> bool:
    result = shell_command(f"am force-stop {package} 2>/dev/null && echo 'OK' || echo 'FAIL'")
    return result is not None and "OK" in result


def disable_package(package: str) -> bool:
    result = shell_command(f"pm disable {package} 2>/dev/null && echo 'OK' || echo 'FAIL'")
    return result is not None and "OK" in result


def get_pid_by_name(name: str) -> List[str]:
    output = shell_command(f"ps -A 2>/dev/null | grep '{name}' | awk '{{print $2}}'")
    if not output:
        return []
    return [pid.strip() for pid in output.split("\n") if pid.strip().isdigit()]


def find_package_for_pid(pid: str) -> Optional[str]:
    output = shell_command(f"cat /proc/{pid}/cmdline 2>/dev/null | tr '\\0' ' '")
    if output:
        return output.strip()
    return None


def wait_for_device(timeout: int = 0) -> bool:
    started = time.time()
    while True:
        if is_device_ready():
            return True
        if timeout and (time.time() - started) > timeout:
            return False
        time.sleep(2)


def get_device_ip() -> Optional[str]:
    for cmd in (
        "ip -4 addr show wlan0 2>/dev/null | grep -oP 'inet \\K[\\d.]+'",
        "ifconfig wlan0 2>/dev/null | grep -oP 'inet addr:\\K[\\d.]+'",
        "ip addr show wlan0 2>/dev/null | grep 'inet ' | awk '{print $2}' | cut -d/ -f1",
        "getprop dhcp.wlan0.ipaddress 2>/dev/null",
    ):
        result = shell_command(cmd)
        if result and not result.startswith("inet"):
            ip = result.strip().split("\n")[0].strip()
            if ip and re.match(r"^\d+\.\d+\.\d+\.\d+$", ip) and not ip.startswith("127."):
                return ip
    return None


def enable_wireless_adb(port: int = 0) -> Tuple[Optional[str], Optional[int]]:
    ip = get_device_ip()
    if not ip:
        return (None, None)

    if port <= 0:
        port = random.randint(49152, 65535)

    result = _run_adb_command(["tcpip", str(port)], timeout=10)
    if result is None:
        return (None, None)

    time.sleep(3)

    connect_result = _run_adb_command(["connect", f"{ip}:{port}"], timeout=10, no_pw=True)
    if connect_result and ("connected" in connect_result or "already" in connect_result):
        _wireless_connections.append(f"{ip}:{port}")
        return (ip, port)

    for attempt in range(5):
        time.sleep(2)
        connect_result = _run_adb_command(["connect", f"{ip}:{port}"], timeout=10, no_pw=True)
        if connect_result and ("connected" in connect_result or "already" in connect_result):
            _wireless_connections.append(f"{ip}:{port}")
            return (ip, port)

    return (None, None)


def disable_wireless_connections():
    for conn in list(_wireless_connections):
        _run_adb_command(["disconnect", conn], no_pw=True)
        _wireless_connections.remove(conn)
    _run_adb_command(["disconnect"], no_pw=True)


def switch_to_usb_mode():
    serial = None
    devices = get_devices()
    for d in devices:
        if d.get("status") == "device":
            serial = d.get("serial")
            break
    if serial:
        _run_adb_command(["-s", serial, "usb"], timeout=10)


def get_active_serial() -> Optional[str]:
    devices = get_devices()
    for d in devices:
        if d.get("status") == "device":
            return d.get("serial")
    return None


def is_usb_connected() -> bool:
    output = _run_adb_command(["devices", "-l"])
    if not output:
        return False
    for line in output.split("\n")[1:]:
        if "usb" in line and "device" in line.split():
            return True
    return False


def cancel_all_notifications(package: str) -> bool:
    result = shell_command(f"cmd notification cancel_all {package} 2>/dev/null && echo 'OK' || echo 'FAIL'")
    return result is not None and "OK" in result


def dismiss_all_notifications() -> bool:
    result = shell_command("cmd notification dismiss_all 2>/dev/null && echo 'OK' || echo 'FAIL'")
    return result is not None and "OK" in result


def get_notification_channels(package: str) -> Optional[List[dict]]:
    output = shell_command(f"dumpsys notification 2>/dev/null | grep -A 30 'AppSettings: {package}'")
    if not output:
        return None
    channels = []
    for line in output.split("\n"):
        if "NotificationChannel{mId=" in line:
            ch_id = ""
            ch_name = ""
            ch_importance = ""
            id_m = re.search(r"mId='([^']*)'", line)
            name_m = re.search(r"mName=([^,]+)", line)
            imp_m = re.search(r"mImportance=(\d)", line)
            if id_m:
                ch_id = id_m.group(1)
            if name_m:
                ch_name = name_m.group(1)
            if imp_m:
                ch_importance = imp_m.group(1)
            if ch_id:
                channels.append({
                    "id": ch_id,
                    "name": ch_name,
                    "importance": ch_importance,
                })
    return channels


def set_channel_importance(package: str, channel_id: str, importance: int) -> bool:
    result = shell_command(
        f"cmd notification set_importance {package} {channel_id} {importance} 2>/dev/null && echo 'OK' || echo 'FAIL'"
    )
    return result is not None and "OK" in result


def get_enabled_notification_listeners() -> Optional[str]:
    return shell_command("settings get secure enabled_notification_listeners 2>/dev/null")


def set_enabled_notification_listeners(value: str) -> bool:
    result = shell_command(
        f"settings put secure enabled_notification_listeners '{value}' 2>/dev/null && echo 'OK' || echo 'FAIL'"
    )
    return result is not None and "OK" in result


def remove_notification_listener(package: str) -> bool:
    current = get_enabled_notification_listeners()
    if not current:
        return False
    components = current.split(":")
    filtered = [c for c in components if not c.startswith(package + "/") and c.strip()]
    new_value = ":".join(filtered)
    return set_enabled_notification_listeners(new_value)
