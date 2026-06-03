import re
from typing import List, Tuple, Optional
from core.adb_client import shell_command
from core.severity import Severity

SUSPICIOUS_LISTENER_KEYWORDS = [
    "downlood", "sav.whmedia", "wamr", "parallel", "appcloner",
    "notif.listen", "notificationlistener", "notifylistener",
    "cloner", "parallelspace",
]

SYSTEM_LISTENER_PREFIXES = [
    "android.service.notification",
    "com.android.systemui",
    "com.google.android.ext.services",
    "com.android.server",
]

KNOWN_LISTENER_APPS = {
    "jbl.stc.com": ("JBL Headphones", "legitimate"),
    "com.samsung.wearable.watch7plugin": ("Samsung Watch Plugin", "legitimate"),
    "com.motorola.motodisplay": ("Moto Display", "legitimate"),
    "com.motorola.launcher3": ("Moto Launcher", "legitimate"),
    "com.microsoft.appmanager": ("Microsoft Link to Windows", "legitimate"),
    "com.google.android.projection.gearhead": ("Android Auto", "legitimate"),
    "com.downlood.sav.whmedia": ("Suspicious Media Downloader", "suspicious"),
    "com.lbe.parallel.intl": ("Parallel Space (App Cloner)", "suspicious"),
    "com.drilens.wamr": ("Unknown WAMR Tool", "suspicious"),
}

PERSISTENT_FLAGS = ["0x710", "0x702", "0x712"]
ONGOING_FGS_FLAGS = ["0x40", "0x42", "0x44"]


def _get_dumpsys_notification() -> Optional[str]:
    raw = shell_command("dumpsys notification 2>/dev/null")
    if not raw:
        return None
    return raw


def _parse_notification_listeners(dumpsys: str) -> List[dict]:
    listeners = []

    allowed_match = re.search(r"Allowed notification listeners:\s*\n\s*(.+)", dumpsys)
    allowed_raw = allowed_match.group(1) if allowed_match else ""

    user_set_match = re.search(r"Has user set:\s*\n\s*userId=(\d+)\s+value=\{(.+?)\}", dumpsys)
    user_set_raw = user_set_match.group(2) if user_set_match else ""

    enabled_section = re.search(
        r"All notification listeners \((\d+)\) enabled for current profiles:\s*\n(.+?)(?=\n\s*\n|$)",
        dumpsys, re.DOTALL
    )
    enabled_raw = enabled_section.group(2) if enabled_section else ""

    all_entries = set()
    for raw in [allowed_raw, user_set_raw, enabled_raw]:
        for entry in re.findall(r'([\w.]+(?:/[\w.]+)?)', raw):
            parts = entry.split("/")
            if parts and parts[0] and "." in parts[0]:
                all_entries.add(parts[0])

    def _is_system_listener(pkg: str) -> bool:
        return any(pkg.startswith(prefix) for prefix in SYSTEM_LISTENER_PREFIXES)

    seen = set()
    for pkg in all_entries:
        if pkg in seen:
            continue
        seen.add(pkg)
        if _is_system_listener(pkg):
            continue
        info = KNOWN_LISTENER_APPS.get(pkg, None)
        is_enabled = pkg in enabled_raw
        listeners.append({
            "package": pkg,
            "label": info[0] if info else pkg,
            "classification": info[1] if info else "unknown",
            "enabled": is_enabled,
        })

    return listeners


def _parse_non_dismissible_notifications(dumpsys: str) -> List[dict]:
    blocks = re.split(r"\n\s+(?=NotificationRecord)", dumpsys)
    found = []
    seen = set()
    for block in blocks:
        pkg_m = re.search(r"pkg=(\S+)", block)
        flags_m = re.search(r"flags=(\S+)", block)
        if not pkg_m or not flags_m:
            continue
        pkg = pkg_m.group(1)
        flags = flags_m.group(1)
        key = f"{pkg}_{flags}"
        if key in seen:
            continue
        seen.add(key)
        is_non_dismissible = re.search(r"deleteIntent=null", block) is not None
        if is_non_dismissible or flags in PERSISTENT_FLAGS:
            found.append({
                "package": pkg,
                "flags": flags,
                "non_dismissible": is_non_dismissible,
            })
    return found


def _count_notifications_by_app(dumpsys: str) -> List[dict]:
    records = re.findall(r"NotificationRecord\([^:]+:\s*pkg=(\S+)", dumpsys)
    counts = {}
    for pkg in records:
        counts[pkg] = counts.get(pkg, 0) + 1
    sorted_counts = sorted(counts.items(), key=lambda x: -x[1])
    return [{"package": pkg, "count": count} for pkg, count in sorted_counts]


def analyze_notification_listeners() -> List[Tuple]:
    findings = []

    dumpsys = _get_dumpsys_notification()
    if not dumpsys:
        findings.append((
            Severity.WARNING,
            "Notification Analysis Failed",
            "Could not retrieve notification data from device",
            "Notifications",
            ["dumpsys notification returned no output"],
            "Ensure USB debugging is enabled and device is connected.",
        ))
        return findings

    listeners = _parse_notification_listeners(dumpsys)
    if not listeners:
        return findings

    enabled_count = sum(1 for l in listeners if l["enabled"])
    total_count = len(listeners)

    suspicious_listeners = [l for l in listeners if l["classification"] == "suspicious"]
    unknown_listeners = [l for l in listeners if l["classification"] == "unknown"]

    if suspicious_listeners:
        details = []
        for l in suspicious_listeners:
            detail = f"{l['package']} ({l['label']})"
            if l["enabled"]:
                detail += " [ACTIVE]"
            details.append(detail)
        findings.append((
            Severity.HIGH,
            "Suspicious Notification Listeners Detected",
            f"{len(suspicious_listeners)} app(s) with notification listener access appear suspicious",
            "Notifications",
            details,
            "These apps can read all your notifications and potentially re-post them. "
            "Disable notification listener access: Settings > Apps > Special Access > Notification Access. "
            "Consider uninstalling these apps.",
        ))

    if unknown_listeners:
        details = []
        for l in unknown_listeners:
            detail = f"{l['package']}"
            if l["enabled"]:
                detail += " [ACTIVE]"
            details.append(detail)
        findings.append((
            Severity.MEDIUM,
            "Unknown Notification Listeners",
            f"{len(unknown_listeners)} app(s) with notification listener access are unrecognized",
            "Notifications",
            details,
            "Review these apps in Settings > Apps > Special Access > Notification Access. "
            "Only trusted apps should have this permission.",
        ))

    if enabled_count > 3:
        details = [f"{l['package']} ({l['label']})" for l in listeners if l["enabled"]]
        findings.append((
            Severity.LOW,
            f"Multiple Notification Listeners Active ({enabled_count})",
            f"{enabled_count} notification listener(s) are active on the device",
            "Notifications",
            details,
            "Each notification listener can read all incoming notifications. "
            "Disable any that are not needed.",
        ))

    return findings


def analyze_non_dismissible_notifs() -> List[Tuple]:
    findings = []

    dumpsys = _get_dumpsys_notification()
    if not dumpsys:
        return findings

    persistent = _parse_non_dismissible_notifications(dumpsys)

    non_dismissible = [n for n in persistent if n["non_dismissible"]]
    if non_dismissible:
        app_counts = {}
        for n in non_dismissible:
            app_counts[n["package"]] = app_counts.get(n["package"], 0) + 1
        details = [f"{pkg}: {count} notification(s)" for pkg, count in
                   sorted(app_counts.items(), key=lambda x: -x[1])]
        findings.append((
            Severity.MEDIUM,
            f"Non-Dismissible Notifications ({len(non_dismissible)})",
            f"{len(non_dismissible)} notification(s) cannot be dismissed by the user (deleteIntent=null)",
            "Notifications",
            details,
            "These are typically group summary notifications used by apps to maintain notification order. "
            "To block them, long-press the notification > turn off the specific notification channel, "
            "or use: adb shell cmd notification",
        ))

    persistent_flags = [n for n in persistent if n["flags"] in PERSISTENT_FLAGS and not n["non_dismissible"]]
    if persistent_flags:
        app_counts = {}
        for n in persistent_flags:
            app_counts[n["package"]] = app_counts.get(n["package"], 0) + 1
        details = [f"{pkg} (flags={n['flags']})" for pkg, count in
                   sorted(app_counts.items(), key=lambda x: -x[1]) for n in persistent_flags if n["package"] == pkg]
        findings.append((
            Severity.LOW,
            f"Persistent Notifications ({len(persistent_flags)})",
            f"{len(persistent_flags)} notification(s) with persistent flags detected",
            "Notifications",
            details[:10],
            "These notifications have ongoing/foreground service flags. "
            "They will reappear if the app's foreground service restarts.",
        ))

    return findings


def analyze_notification_overload() -> List[Tuple]:
    findings = []

    dumpsys = _get_dumpsys_notification()
    if not dumpsys:
        return findings

    counts = _count_notifications_by_app(dumpsys)
    if not counts:
        return findings

    total_notifs = sum(c["count"] for c in counts)
    findings.append((
        Severity.INFO,
        f"Total Active Notifications: {total_notifs}",
        f"{total_notifs} notification(s) currently active across {len(counts)} app(s)",
        "Notifications",
        [f"{c['package']}: {c['count']}" for c in counts[:10]],
        None,
    ))

    top_apps = [c for c in counts if c["count"] >= 20]
    for app in top_apps:
        findings.append((
            Severity.MEDIUM if app["count"] >= 50 else Severity.LOW,
            f"High Notification Volume: {app['package']} ({app['count']})",
            f"{app['package']} has {app['count']} active notification(s)",
            "Notifications",
            [f"Package: {app['package']}", f"Count: {app['count']}"],
            "Consider reviewing notification settings for this app. "
            "Disable unnecessary channels: long-press notification > turn off channel, "
            f"or use: adb shell cmd notification",
        ))

    return findings


def analyze_notifications() -> List[Tuple]:
    findings = []
    findings.extend(analyze_notification_listeners())
    findings.extend(analyze_non_dismissible_notifs())
    findings.extend(analyze_notification_overload())
    return findings


# ---------------------------------------------------------------------------
# Interactive Notification Remediation
# ---------------------------------------------------------------------------

from core.display import console, print_finding, print_summary_table
from rich.table import Table
from rich import box
from core.adb_client import (
    cancel_all_notifications,
    dismiss_all_notifications,
    get_notification_channels,
    set_channel_importance,
    remove_notification_listener,
    force_stop_package,
    disable_package,
    get_enabled_notification_listeners,
)


def _get_listener_components() -> List[dict]:
    enabled_raw = get_enabled_notification_listeners()
    enabled_pkgs = set()
    result = []

    if enabled_raw:
        for comp in enabled_raw.split(":"):
            comp = comp.strip()
            if not comp:
                continue
            parts = comp.split("/", 1)
            pkg = parts[0]
            svc = parts[1] if len(parts) > 1 else ""
            enabled_pkgs.add(pkg)
            info = KNOWN_LISTENER_APPS.get(pkg, None)
            result.append({
                "package": pkg,
                "service": svc,
                "label": info[0] if info else pkg,
                "classification": info[1] if info else "unknown",
                "enabled": True,
            })

    dumpsys = _get_dumpsys_notification()
    if dumpsys:
        all_listeners = _parse_notification_listeners(dumpsys)
        for l in all_listeners:
            if l["package"] not in enabled_pkgs:
                enabled_pkgs.add(l["package"])
                result.append({
                    "package": l["package"],
                    "service": "",
                    "label": l["label"],
                    "classification": l["classification"],
                    "enabled": False,
                })

    return result


def _show_listener_management(listeners: List[dict]):
    if not listeners:
        console.print("[yellow]No notification listeners configured.[/]")
        return

    console.print("\n[bold cyan]\U0001f514 Notification Listeners[/]")
    table = Table(box=box.ROUNDED, title="Enabled Notification Listeners", title_style="bold")
    table.add_column("#", style="dim")
    table.add_column("Package", style="cyan")
    table.add_column("Label", style="white")
    table.add_column("Status", no_wrap=True)

    for i, l in enumerate(listeners, 1):
        cls_status = "[red]SUSPICIOUS[/]" if l["classification"] == "suspicious" else \
                     "[yellow]UNKNOWN[/]" if l["classification"] == "unknown" else \
                     "[green]LEGITIMATE[/]"
        if not l.get("enabled", False):
            cls_status += " [dim](not active)[/]"
        table.add_row(str(i), l["package"], l["label"], cls_status)

    console.print(table)

    suspicious = [l for l in listeners if l["classification"] == "suspicious"]
    unknown = [l for l in listeners if l["classification"] == "unknown"]

    if not suspicious and not unknown:
        console.print("[green]\u2705 No suspicious or unknown listeners found.[/]")
        return

    console.print("\n[bold red]Options for suspicious/unknown listeners:[/]")
    opts = []
    if suspicious:
        for l in suspicious:
            opts.append(("suspicious", l))
    if unknown:
        for l in unknown:
            opts.append(("unknown", l))

    for idx, (_, l) in enumerate(opts, 1):
        tag = "[red]SUSPICIOUS[/]" if l["classification"] == "suspicious" else "[yellow]UNKNOWN[/]"
        console.print(f"  [bold]{idx}.[/] {tag} {l['package']} ({l['label']})")

    console.print("\n[dim]Enter numbers to select (comma-separated), 'a' for all, 'q' to skip:[/]")
    choice = input("  > ").strip().lower()

    if choice == "q":
        return

    indices = []
    if choice == "a":
        indices = list(range(len(opts)))
    else:
        for part in choice.split(","):
            part = part.strip()
            if part.isdigit():
                idx = int(part) - 1
                if 0 <= idx < len(opts):
                    indices.append(idx)

    if not indices:
        console.print("[yellow]No valid selection.[/]")
        return

    selected = [opts[i] for i in indices]
    for cls, l in selected:
        console.print(f"\n[cyan]Processing: {l['package']}[/]")
        console.print("  [1] Remove notification listener access")
        console.print("  [2] Force-stop package")
        console.print("  [3] Disable package entirely")
        console.print("  [4] Remove listener + force-stop")
        console.print("  [5] Skip")
        action = input("  Action (1-5): ").strip()

        if action == "1":
            if remove_notification_listener(l["package"]):
                console.print(f"  [green]\u2713 Listener access removed for {l['package']}[/]")
            else:
                console.print(f"  [red]\u2717 Failed to remove listener access[/]")
        elif action == "2":
            if force_stop_package(l["package"]):
                console.print(f"  [green]\u2713 Package force-stopped: {l['package']}[/]")
            else:
                console.print(f"  [red]\u2717 Failed to force-stop[/]")
        elif action == "3":
            if disable_package(l["package"]):
                console.print(f"  [green]\u2713 Package disabled: {l['package']}[/]")
            else:
                console.print(f"  [red]\u2717 Failed to disable package[/]")
        elif action == "4":
            if remove_notification_listener(l["package"]):
                console.print(f"  [green]\u2713 Listener access removed[/]")
            if force_stop_package(l["package"]):
                console.print(f"  [green]\u2713 Package force-stopped[/]")
        else:
            console.print(f"  [dim]Skipped[/]")


def _get_active_notif_counts() -> List[dict]:
    dumpsys = _get_dumpsys_notification()
    if not dumpsys:
        return []
    return _count_notifications_by_app(dumpsys)


def _show_notification_cleanup():
    counts = _get_active_notif_counts()
    if not counts:
        console.print("[yellow]Could not retrieve notification data.[/]")
        return

    console.print("\n[bold cyan]\U0001f4ac Active Notifications by App[/]")
    table = Table(box=box.ROUNDED, title="Active Notifications", title_style="bold")
    table.add_column("#", style="dim")
    table.add_column("Package", style="cyan")
    table.add_column("Count", justify="right")
    table.add_column("Status", no_wrap=True)

    for i, c in enumerate(counts, 1):
        cnt = c["count"]
        status = f"[red]HIGH ({cnt})[/]" if cnt >= 50 else \
                 f"[yellow]{cnt}[/]" if cnt >= 20 else \
                 f"[dim]{cnt}[/]"
        table.add_row(str(i), c["package"], str(cnt), status)

    console.print(table)

    console.print("\n[bold yellow]Options:[/]")
    console.print("  [d] Dismiss ALL notifications on device")
    console.print("  [n] Cancel notifications for specific app(s)")
    console.print("  [c] Block notification channels for specific app(s)")
    console.print("  [q] Go back")
    action = input("  > ").strip().lower()

    if action == "d":
        console.print("[cyan]Dismissing all notifications...[/]")
        success = dismiss_all_notifications()
        force_cancel = input("  Also force-cancel by package? (y/n): ").strip().lower()
        if force_cancel == "y":
            for c in counts:
                cancel_all_notifications(c["package"])
                console.print(f"  [dim]Cancelled: {c['package']}[/]")
        if success:
            console.print("[green]\u2713 All notifications dismissed.[/]")
        else:
            console.print("[red]\u2717 Failed to dismiss all notifications.[/]")

    elif action == "n":
        console.print("\n[dim]Enter app numbers to cancel (comma-separated), 'a' for all:[/]")
        choice = input("  > ").strip().lower()
        if choice == "a":
            for c in counts:
                if cancel_all_notifications(c["package"]):
                    console.print(f"  [green]\u2713 Cancelled: {c['package']}[/]")
        else:
            for part in choice.split(","):
                part = part.strip()
                if part.isdigit():
                    idx = int(part) - 1
                    if 0 <= idx < len(counts):
                        pkg = counts[idx]["package"]
                        if cancel_all_notifications(pkg):
                            console.print(f"  [green]\u2713 Cancelled: {pkg}[/]")

    elif action == "c":
        console.print("\n[dim]Enter app number to manage its channels:[/]")
        choice = input("  > ").strip()
        if choice.isdigit():
            idx = int(choice) - 1
            if 0 <= idx < len(counts):
                pkg = counts[idx]["package"]
                _show_channel_management(pkg)

    else:
        console.print("[dim]No action taken.[/]")


def _show_channel_management(package: str):
    channels = get_notification_channels(package)
    if not channels:
        console.print(f"[yellow]No channels found for {package} or cannot access.[/]")
        return

    console.print(f"\n[bold cyan]Notification Channels: {package}[/]")
    table = Table(box=box.ROUNDED, title_style="bold")
    table.add_column("#", style="dim")
    table.add_column("Channel ID", style="cyan")
    table.add_column("Name")
    table.add_column("Importance")
    table.add_column("Action")

    for i, ch in enumerate(channels, 1):
        imp = int(ch["importance"]) if ch["importance"].isdigit() else -1
        imp_str = f"{imp}" if imp >= 0 else "?"
        action_str = "[red]BLOCKED[/]" if imp == 0 else "[yellow]PERSISTENT[/]" if imp >= 4 else "[dim]OK[/]"
        table.add_row(str(i), ch["id"], ch["name"], imp_str, action_str)

    console.print(table)

    console.print("\n[dim]Enter channel numbers to block (set importance=0), 'a' for all, 'q' to skip:[/]")
    choice = input("  > ").strip().lower()
    if choice == "q":
        return
    indices = []
    if choice == "a":
        indices = list(range(len(channels)))
    else:
        for part in choice.split(","):
            part = part.strip()
            if part.isdigit():
                idx = int(part) - 1
                if 0 <= idx < len(channels):
                    indices.append(idx)
    if not indices:
        console.print("[yellow]No channels selected.[/]")
        return

    for idx in indices:
        ch = channels[idx]
        console.print(f"  [cyan]Blocking channel: {ch['id']} ({ch['name']})...[/]")
        if set_channel_importance(package, ch["id"], 0):
            console.print(f"  [green]\u2713 Channel blocked[/]")
        else:
            console.print(f"  [red]\u2717 Failed to block channel[/]")

    console.print(f"\n[green]\u2713 {len(indices)} channel(s) blocked for {package}[/]")


def _show_persistent_notif_cleanup():
    dumpsys = _get_dumpsys_notification()
    if not dumpsys:
        return
    persistent = _parse_non_dismissible_notifications(dumpsys)
    if not persistent:
        console.print("[green]\u2705 No persistent or non-dismissible notifications found.[/]")
        return

    non_dismissible = [n for n in persistent if n["non_dismissible"]]
    if not non_dismissible:
        return

    app_list = list({n["package"] for n in non_dismissible})
    console.print(f"\n[bold yellow]\U0001f6ab {len(app_list)} app(s) with non-dismissible notifications[/]")
    for i, pkg in enumerate(app_list, 1):
        count = sum(1 for n in non_dismissible if n["package"] == pkg)
        console.print(f"  {i}. {pkg} ({count} notification(s))")

    console.print("\n[bold yellow]Actions:[/]")
    console.print("  [1] Block notification channels for an app")
    console.print("  [2] Force-stop an app")
    console.print("  [3] Skip")
    choice = input("  > ").strip()

    if choice == "1":
        console.print("\n[dim]Enter app number:[/]")
        app_choice = input("  > ").strip()
        if app_choice.isdigit():
            idx = int(app_choice) - 1
            if 0 <= idx < len(app_list):
                _show_channel_management(app_list[idx])
    elif choice == "2":
        console.print("\n[dim]Enter app number to force-stop:[/]")
        app_choice = input("  > ").strip()
        if app_choice.isdigit():
            idx = int(app_choice) - 1
            if 0 <= idx < len(app_list):
                pkg = app_list[idx]
                if force_stop_package(pkg):
                    console.print(f"  [green]\u2713 Force-stopped: {pkg}[/]")
                else:
                    console.print(f"  [red]\u2717 Failed to force-stop[/]")


def run_notification_mode():
    console.print("\n[bold cyan]\U0001f514 Notification Management Mode[/]")
    console.print("[dim]Manage notification listeners, clear notifications, and block channels.\n[/]")

    while True:
        console.print("\n[bold]Select action:[/]")
        console.print("  [1] \U0001f50d Scan notification listeners")
        console.print("  [2] \U0001f4ac Clear / manage active notifications")
        console.print("  [3] \U0001f6ab Block persistent/non-dismissible notifications")
        console.print("  [4] \U0001f4cb Show full notification analysis report")
        console.print("  [q] Quit")
        action = input("\n  > ").strip().lower()

        if action == "q":
            break
        elif action == "1":
            dumpsys = _get_dumpsys_notification()
            if dumpsys:
                listeners = _get_listener_components()
                if listeners:
                    _show_listener_management(listeners)
                else:
                    f_listeners = _parse_notification_listeners(dumpsys)
                    listeners = _get_listener_components()
                    _show_listener_management(listeners)
        elif action == "2":
            _show_notification_cleanup()
        elif action == "3":
            _show_persistent_notif_cleanup()
        elif action == "4":
            from core.display import print_summary_table
            findings = analyze_notifications()
            for f in findings:
                if len(f) >= 4:
                    print_finding(f[0], f[1], f[2],
                                  details=f[4] if len(f) > 4 else None,
                                  recommendation=f[5] if len(f) > 5 else None)
            print_summary_table([(f[0], f[1], f[3]) for f in findings if len(f) >= 4])
        else:
            console.print("[yellow]Invalid option.[/]")
