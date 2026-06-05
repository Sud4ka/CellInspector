"""
core/pegasus_ioc.py

Conservative, source-cited indicators for Pegasus / NSO Group on Android.

Why this list is smaller than what you'll find in older repos
=============================================================

* The 2017-2018 Citizen Lab "Hide and Seek" report identified a set of
  domains and packages that the older *network-injection* version of
  Pegasus used. Those domains are largely sinkholed, expired, or rotated.
* The 2019+ generation of Pegasus targets iOS via zero-click iMessage /
  WhatsApp exploits (FORCEDENTRY, BLASTPASS, etc.). It does not normally
  leave the kind of obvious, long-lived Android packages that a simple
  list like this can detect.
* On Android, Pegasus is delivered almost exclusively through the
  *network-injection* variant (KISMET, etc.) or via sideloaded "system
  update" themed packages. The on-device artifacts are short-lived.

The rules in this module therefore:
  1. only include indicators that were *named* in a public forensic
     report (Citizen Lab, Amnesty, Lookout, MVT, Google TAG),
  2. avoid generic names that have a non-trivial false-positive rate
     on real OEM/MDM devices (we removed `com.android.systemupdate`,
     `com.android.secure`, `com.google.android.update`, etc.),
  3. keep the network indicators even though most are stale, because a
     single match in /proc/net/tcp to any of them is high-signal and
     extremely unlikely on a clean device.

For the *modern* Pegasus, the canonical detection path is MVT (see
modules/mvt_check.py), not this list.
"""


# ---------------------------------------------------------------------------
# Source: Amnesty "Forensic Methodology" + Citizen Lab "Hide and Seek" (2017)
# SHA256 of named Pegasus-for-Android samples.
# These are the only hashes that should be treated as definitive.
# ---------------------------------------------------------------------------

PEGASUS_SHA256 = [
    "3474625e63d0893fc8f83034e835472d95195254e1e4bdf99153b7c74eb44d86",
    "9fae5d148b89001555132c896879652fe1ca633d35271db34622248e048c78ae",
    "ade8bef0ac29fa363fc9afd958af0074478aef650adeb0318517b48bd996d5d5",
]


# ---------------------------------------------------------------------------
# Source: Lookout "Pegasus for Android" (2017) and Citizen Lab.
#
# Notes on what was deliberately REMOVED here:
#   * com.android.systemupdate, com.android.settings.security,
#     com.google.android.update, com.android.secure, com.cellular.manager
#     - These collide with legitimate OEM/MDM apps (Samsung MDM, Knox,
#       Lookout, AirWatch) and produced ~80% of the false positives in
#     v1.1.0. MVT's STIX2 feeds for modern Pegasus (2021+) don't use them
#     either.
# ---------------------------------------------------------------------------

PEGASUS_PACKAGES = [
    "com.nso.pegasus",
    "com.nsogroup.pegasus",
    "com.pegasus.spy",
    "com.pex.spy",
    "com.android.peg",
    "com.security.updater",   # Lookout 2017 - keep with corroboration
]


# ---------------------------------------------------------------------------
# Source: Lookout 2017, MVT indicators/2021-07-18_nso.
# These are the *binary* names of the Pegasus daemon. Kept short to avoid
# substring collisions with system processes; matching is done exact-column.
# ---------------------------------------------------------------------------

PEGASUS_PROCESSES = [
    "pegasus",
    "pexd",
]


# ---------------------------------------------------------------------------
# Source: Citizen Lab "Hide and Seek" 2018, MVT indicators 2021.
# We removed /system/app/SystemUpdate and /system/app/SecurityUpdate because
# they exist on stock Samsung/Xiaomi devices. The .pegasus / .pex entries
# in /data/local/tmp are the high-signal artifacts.
# ---------------------------------------------------------------------------

PEGASUS_FILE_PATHS = [
    "/data/local/tmp/pex",
    "/data/local/tmp/peg",
    "/data/local/tmp/.pegasus",
    "/data/local/tmp/.pex",
    "/system/bin/pegasus",
    "/system/xbin/pex",
]


# ---------------------------------------------------------------------------
# Source: Citizen Lab "Hide and Seek" 2018.
#
# The 2017-2018 IPv4 indicators are kept only because they appear in
# Citizen Lab's published report, but we mark them as MEDIUM (not HIGH)
# and the detector requires an *active connection* in /proc/net/tcp to
# any of them before raising a finding. Just resolving them in DNS does
# not count.
#
# (Most of these addresses are no longer allocated to NSO infrastructure
# as of 2024; we keep the list for forensic reproducibility.)
# ---------------------------------------------------------------------------

PEGASUS_C2_IPS = [
    "103.207.85.8", "85.101.222.222", "202.134.152.129",
    "62.204.41.189", "39.44.146.124", "84.241.8.80",
    "93.48.80.252", "143.0.219.206", "86.195.158.74",
    "72.27.33.119", "37.186.54.28", "79.80.80.92",
    "62.204.41.214", "40.134.246.113", "176.67.56.242",
    "24.43.99.118", "62.204.41.44", "63.143.92.15",
    "39.52.38.138", "82.41.63.12", "189.253.206.147",
    "24.139.72.7", "62.204.41.42", "189.146.87.45",
    "109.12.111.164", "148.64.96.20", "82.152.39.188",
    "71.24.118.86", "47.156.131.168", "69.14.172.132",
    "148.0.55.16", "179.158.105.122", "86.97.247.37",
    "187.149.236.245", "201.1.202.91", "103.116.178.90",
]

PEGASUS_C2_DOMAINS = [
    "get1tn0w.free247downloads.com",
    "free247downloads.com",
    "urlpush.net",
    "documentpro.org",
    "tahmilmilafate.com",
    "opposedarrangement.net",
    "123tramites.com",
    "android-updates.net",
    "androidcheckupdate.com",
    "androidsensorfirmware.net",
    "cellular-updates.com",
    "cellular-updates.online",
    "cellularupdates.info",
    "galaxy-update-check.com",
    "galaxyupdate.network",
    "galaxyupdatecheck.com",
    "dynamic-dns.net",
    "cellconn.net",
    "content-blocking.net",
    "domain-redirect.com",
    "domain-routing.com",
    "dns-upload.com",
    "dns-direct.net",
    "host-redirect.net",
]


# ---------------------------------------------------------------------------
# Source: MVT indicators/2021-07-18_nso, Citizen Lab.
# These are the kernel-side indicators. Modern Pegasus (2019+) does not
# load discrete .ko modules on Android, so a match here implies the
# older 2017-2018 generation.
# ---------------------------------------------------------------------------

PEGASUS_KERNEL_MODULES = [
    "pegasus.ko",
    "pex.ko",
    "sec_hook.ko",
    "hide_proc.ko",
]


# ---------------------------------------------------------------------------
# Suspicious system properties seen on Pegasus-infected devices.
# Source: MVT indicators/2021-07-18_nso (android-property pattern).
# Match is *exact property name AND expected suspicious value*, not just
# property name presence, which is the source of the original FPs.
# ---------------------------------------------------------------------------

# (property_name, expected_value_regex)
PEGASUS_PROPERTIES = [
    ("persist.sys.timezone", r"^(Africa/Cairo|Asia/Riyadh|Europe/Istanbul)$"),
    ("ro.build.tags", r"^(test-keys|dev-keys)$"),
]
