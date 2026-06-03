from typing import List, Tuple, Optional
from core.adb_client import list_processes
from core.severity import Severity
from core.ioc_db import SUSPICIOUS_PROCESSES


KERNEL_PROCESSES = {
    "init", "kthreadd", "rcu_gp", "rcu_par_gp", "mm_percpu_wq",
    "rcu_tasks_kthre", "rcu_tasks_trace", "ksoftirqd", "rcu_preempt",
    "rcub", "rcuc", "migration", "cpuhp", "kworker", "kdevtmpfs",
    "netns", "oom_reaper", "writeback", "kintegrityd", "kblockd",
    "blkcg_punt_bio", "edac-poller", "devfreq_wq", "watchdogd",
    "kswapd0", "ecryptfs-kthrea", "kthrotld", "acpi_thermal_pm",
    "ata_sff", "scsi_eh", "scsi_tmf", "xfsalloc", "xfs-block",
    "xfs-data", "xfs-conv", "xfs-cil", "xfs-reclaim", "xfs-log",
    "xfsaild", "kernfs", "cryptd", "mmcqd", "loop", "spi",
    "spi32766", "irq", "ipv6_addrconf", "kstrp", "charger_manager",
    "kbase", "deferred", "sugov", "mtk", "mrdump", "usb",
    "ueventd", "vold", "netd", "zygote", "zygote64",
    "audioserver", "cameraserver", "mediaserver", "servicemanager",
    "surfaceflinger", "logd", "adbd", "lmkd", "storaged",
    "installd", "gatekeeperd", "keystore", "drm",
    "media.codec", "media.swcodec", "media.hwcodec",
    "healthd", "thermal", "thermal_core",
    "android.hardware", "vendor.", "wificond",
    "wpa_supplicant", "dhcpclient", "iwifitest",
    "statsd", "traced", "traced_perf", "iperf",
    "update_engine", "EEReport", "dumpstate",
    "iptables", "iptables-restore", "ip6tables", "ip6tables-restore", "clatd",
}


def find_suspicious_processes(processes: list) -> List[dict]:
    suspicious = []
    seen = set()
    for proc in processes:
        name = proc["name"]
        if name in seen:
            continue
        seen.add(name)
        for pattern in SUSPICIOUS_PROCESSES:
            if pattern.lower() in name.lower():
                suspicious.append(proc)
                break
    return suspicious


def find_root_processes(processes: list) -> List[dict]:
    return [
        p for p in processes
        if p["user"] == "root"
        and p["name"] not in KERNEL_PROCESSES
        and "[" not in p["name"]
        and not any(p["name"].startswith(prefix) for prefix in ["android.hardware.", "vendor."])
    ]


def analyze_processes() -> List[Tuple[Severity, str, str, str, Optional[List[str]], Optional[str]]]:
    findings = []
    processes = list_processes()
    if not processes:
        findings.append((
            Severity.WARNING,
            "Cannot Access Process List",
            "Unable to list running processes. Device may be locked or unresponsive.",
            "Processes",
            None,
            "Unlock the device and try again.",
        ))
        return findings

    total_procs = len(processes)
    user_procs = [p for p in processes if p["user"] not in ("root", "system", "kernel")]

    suspicious = find_suspicious_processes(processes)
    for proc in suspicious:
        details = [
            f"Process: {proc['name']}",
            f"PID: {proc['pid']}",
            f"User: {proc['user']}",
        ]
        findings.append((
            Severity.HIGH,
            "Suspicious Process Detected",
            f"Running process '{proc['name']}' matches known suspicious process pattern",
            "Processes",
            details,
            "Check if this process is expected. It may indicate debugging or tampering tools.",
        ))

    root_procs = find_root_processes(processes)
    for proc in root_procs:
        details = [f"Process: {proc['name']}", f"PID: {proc['pid']}"]
        findings.append((
            Severity.MEDIUM,
            "Root Process Running",
            f"Non-standard process running as root: {proc['name']}",
            "Processes",
            details,
            "Verify this process is supposed to run with root privileges.",
        ))

    findings.append((
        Severity.INFO,
        "Running Processes Summary",
        f"Total: {total_procs} processes, {len(user_procs)} user-space processes",
        "Processes",
        [f"System: {total_procs - len(user_procs)}", f"User: {len(user_procs)}"],
        None,
    ))

    return findings
