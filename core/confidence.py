KNOWN_ANDROID_PROCESSES = {
    "gatekeeperd", "gatekeeper", "keystore", "keymaster",
    "servicemanager", "surfaceflinger", "mediaserver",
    "audioserver", "cameraserver", "drmserver",
    "logd", "adbd", "lmkd", "storaged",
    "installd", "zygote", "zygote64", "ueventd",
    "vold", "netd", "wificond", "wpa_supplicant",
    "dhcpclient", "statsd", "traced", "traced_perf",
    "healthd", "thermal", "thermal_core",
    "init", "system_server", "bt_a2dp_offload",
    "media.codec", "media.swcodec", "media.hwcodec",
    "drm", "mediadrm", "media.extractor",
    "audioserver", "audio_hw", "audio_hw_primary",
    "tombstoned", "debuggerd", "debuggerd64",
    "perfprofd", "iperf", "iperf3",
    "update_engine", "dumpstate", "dumpstatez",
    "EEReport", "crashreporter",
    "wtf", "anr", "anrd", "storaged",
    "iptables", "iptables-restore", "ip6tables", "ip6tables-restore",
    "clatd", "ndc", "tc", "ip",
    "binder", "binder_io", "hwservicemanager",
    "android.hardware", "vendor.", "system.",
    "cnss-daemon", "wcnss-service", "p2p_supplicant",
    "netmgr", "diag_mdlog", "diag_socket",
    "ims_rtp_daemon", "imsdaemon", "ims_qrbg",
    "slim_daemon", "loc_launcher", "gpsd",
    "mtk", "mrdump", "ccci", "cplog",
    "tee", "secd", "sec_keyboard",
    "samsung", "knox", "tima",
}

SKIP_MIN_LENGTH = 4

HIGH_CONFIDENCE_TYPES = {"sha256", "sha1", "md5", "app_id_exact", "domain_exact", "ip_exact"}
MEDIUM_CONFIDENCE_TYPES = {"app_id_sub", "file_path", "cert_hash"}
LOW_CONFIDENCE_TYPES = {"process_name", "file_name", "url", "android_property"}


def classify_ioc_type(pattern: str) -> str:
    if "hashes.sha256" in pattern or "hashes.sha1" in pattern or "hashes.md5" in pattern:
        return "sha256"
    if "app:id" in pattern:
        return "app_id_exact"
    if "domain-name:value" in pattern or "ipv4-addr:value" in pattern:
        return "domain_exact"
    if "file:path" in pattern:
        return "file_path"
    if "file:name" in pattern:
        return "file_name"
    if "process:name" in pattern:
        return "process_name"
    if "url:value" in pattern:
        return "url"
    if "android-property:name" in pattern:
        return "android_property"
    return "unknown"


def compute_confidence(ioc_type: str, value: str) -> tuple:
    if ioc_type in ("sha256", "sha1", "md5"):
        return (95, "HIGH")

    if ioc_type == "app_id_exact":
        return (85, "HIGH")

    if ioc_type == "domain_exact":
        return (80, "HIGH")

    if ioc_type == "file_path":
        return (60, "MEDIUM")

    if ioc_type == "process_name":
        if len(value) < SKIP_MIN_LENGTH:
            return (0, "SKIP")
        if value.lower() in KNOWN_ANDROID_PROCESSES:
            return (5, "INFO")
        if len(value) < 6:
            return (10, "LOW")
        if len(value) < 8:
            return (20, "LOW")
        return (35, "LOW")

    if ioc_type == "file_name":
        if len(value) < 4:
            return (0, "SKIP")
        if len(value) < 6:
            return (15, "LOW")
        return (30, "LOW")

    if ioc_type == "url":
        return (50, "MEDIUM")

    if ioc_type == "android_property":
        return (10, "LOW")

    return (10, "LOW")


def should_skip(ioc_type: str, value: str) -> bool:
    score, label = compute_confidence(ioc_type, value)
    return label == "SKIP"


def format_confidence_badge(confidence: int, label: str) -> str:
    colors = {
        "CRITICAL": "red",
        "HIGH": "orange_red1",
        "MEDIUM": "orange1",
        "LOW": "yellow",
        "INFO": "cyan",
    }
    color = colors.get(label, "grey")
    return f"[bold {color}]{label} ({confidence}/100)[/]"


def confidence_from_result(findings: list) -> tuple:
    if not findings:
        return ("CLEAN", 100)
    max_score = max(f[0] for f in findings) if findings else 0
    if max_score >= 90:
        return ("CRITICAL", max_score)
    if max_score >= 70:
        return ("HIGH", max_score)
    if max_score >= 40:
        return ("MEDIUM", max_score)
    if max_score >= 10:
        return ("LOW", max_score)
    return ("INFO", max_score)


def get_recommendation(confidence_label: str) -> str:
    recs = {
        "CRITICAL": "Immediately disconnect from all networks. Factory reset the device from recovery mode. Change all account passwords from a trusted device.",
        "HIGH": "Strongly consider factory resetting the device. Change passwords for all accounts accessed from this device.",
        "MEDIUM": "Investigate further. Check for unusual data usage, battery drain, or unexpected behavior. Consider a factory reset if other symptoms appear.",
        "LOW": "Low confidence indicator. This may be a false positive. Monitor the device for additional symptoms before taking action.",
        "INFO": "Informational only. No action required. This is a known legitimate Android component.",
    }
    return recs.get(confidence_label, "No specific recommendation.")
