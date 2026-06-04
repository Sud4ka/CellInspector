SUSPICIOUS_PACKAGE_PATTERNS = [
    "spy", "monitor", "track", "stalk", "stealth", "hidden",
    "keylog", "sniffer", "rat", "trojan", "backdoor",
    "hack", "crack", "phish", "malware", "worm",
    "banker", "call.record", "screen.record",
    "remote.access", "vnc",
    "iq.", "adups", "mobileinsight",
]

SUSPICIOUS_PACKAGES = [
    "com.securesms",
    "com.remotex",
    "com.teamviewer.quicksupport",
    "com.anydesk.adcontrol",
    "com.lemon.lvoverseas",
]

STALKERWARE_PACKAGES = [
    "com.mspy",
    "com.mspy2",
    "com.flexispy",
    "com.flexispy.android",
    "com.cocospy",
    "com.spyzie",
    "com.spyic",
    "com.umobix",
    "com.hoverwatch",
    "com.thetruthspy",
    "com.cocospy.celltracker",
    "com.hoverwatch.monitor",
    "com.zerospy",
    "com.highstermobile",
    "com.lovedogs.phone",
    "com.phonemanager.cleaner",
    "com.callrecorder",
    "com.spyhuman",
    "com.monitors.phone",
    "com.shadow.spy",
    "com.android.monitor",
    "com.advanced.spy",
    "com.trackmyphone",
    "com.phoneclz",
    "com.spapp",
    "com.mobistealth",
    "com.mobispy",
    "com.phone.spy",
    "com.spy.app",
    "com.smstracker",
    "com.gpstracker",
    "com.family.tracker",
    "com.phone.tracker",
    "com.bbmspy",
    "com.whatsapp.tracker",
    "com.snapchat.tracker",
    "com.securetracking",
    "com.privatesms.tracker",
]

STALKERWARE_PROCESSES = [
    "mspy", "flexispy", "cocospy", "spyic", "umobix",
    "hoverwatch", "thetruthspy", "spyzie", "zerospy",
    "spapp", "mobistealth", "spyhuman", "shadowspy",
    "callrecorder", "spytool", "monitorservice",
    "tracker", "spyservice", "monitoring",
]

STALKERWARE_C2_DOMAINS = [
    "mspy.com", "flexispy.com", "cocospy.com", "spyic.com",
    "umobix.com", "hoverwatch.com", "thetruthspy.com",
    "spyzie.com", "zerospy.com", "spapp.com",
    "mobistealth.com", "spyhuman.com",
]

SUSPICIOUS_PROCESSES = [
    "frida", "busybox", "nc.", "netcat", "ncat",
    "tcpdump", "tshark", "wireshark", "mitmproxy",
    "socat", "strace", "gdbserver", "ptrace",
    "minitouch", "minicap", "am.adb",
]

SUSPICIOUS_PERMISSIONS_HIGH = [
    "android.permission.READ_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.SEND_SMS",
    "android.permission.READ_CALL_LOG",
    "android.permission.RECORD_AUDIO",
    "android.permission.CAMERA",
    "android.permission.READ_CONTACTS",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.ACCESS_BACKGROUND_LOCATION",
    "android.permission.BIND_ACCESSIBILITY_SERVICE",
    "android.permission.SYSTEM_ALERT_WINDOW",
    "android.permission.REQUEST_INSTALL_PACKAGES",
    "android.permission.PACKAGE_USAGE_STATS",
    "android.permission.QUERY_ALL_PACKAGES",
]

SUSPICIOUS_PERMISSIONS_MEDIUM = [
    "android.permission.GET_ACCOUNTS",
    "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.ACCESS_WIFI_STATE",
    "android.permission.CHANGE_WIFI_STATE",
    "android.permission.ACCESS_NETWORK_STATE",
    "android.permission.INTERNET",
    "android.permission.READ_PHONE_STATE",
    "android.permission.ADD_VOICEMAIL",
    "android.permission.USE_SIP",
    "android.permission.BLUETOOTH",
    "android.permission.VIBRATE",
]

SUSPICIOUS_DOMAIN_PATTERNS = [
    r"\.xyz$", r"\.top$", r"\.gq$", r"\.ml$", r"\.cf$",
    r"\.tk$", r"\.ga$", r"\.download$", r"\.bid$",
    r"trade", r"\.pw$", r"\.club$", r"\.work$",
    r"webredirect", r"redirectme", r"servehttp",
    r"serveftp", r"ddns", r"dynamic-dns", r"no-ip",
    r"duckdns", r"ngrok", r"localhost\.run",
]

SUSPICIOUS_IPS = [
    "185.220.101.", "185.220.102.", "185.220.103.",
    "23.129.64.", "45.33.32.", "104.238.160.",
    "192.168.1.1",
]

SUSPICIOUS_DOMAINS = [
    "pastebin.com", "pastes.io", "ghostbin.com",
    "transfer.sh", "we.tl", "ufile.io",
]

SUSPICIOUS_DNS_PATTERNS = [
    "c2", "command", "control", "panel", "admin",
    "backconnect", "reverse", "shell", "payload",
    "bot", "rat.", "malware", "exploit", "dropper",
]

SUSPICIOUS_LOGCAT_PATTERNS = [
    r"ptrace", r"debugger", r"frida", r"xposed",
    r"su ", r"/system/xbin/", r"/sbin/su",
    r"magisk", r"superuser", r"root.",
    r"selinux.*permissive",
]

KNOWN_MALWARE_PACKAGES = [
    "com.emoji.wallpaper",
    "com.hw.panel",
    "com.system.service",
    "com.google.update",
    "com.android.update",
    "com.miui.security",
]
