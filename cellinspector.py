#!/usr/bin/env python3
import sys
import time
import os
import signal
import atexit
import argparse
from typing import List, Tuple, Optional

VERSION = "1.1.0"

from core.display import (
    console,
    print_banner,
    print_finding,
    print_device_info_table,
    print_summary_table,
    create_progress,
    generate_markdown_report,
    generate_json_report,
)
from core.severity import Severity
from core.adb_client import (
    is_device_ready,
    get_devices,
    get_device_ip,
    enable_wireless_adb,
    disable_wireless_connections,
    switch_to_usb_mode,
    is_usb_connected,
    wait_for_device,
    kill_process,
    force_stop_package,
    cancel_all_notifications,
    dismiss_all_notifications,
    remove_notification_listener,
    set_channel_importance,
    get_notification_channels,
    get_device_locale,
)
from core.guides import render_manual_guides
from modules.network_analyzer import analyze_network
from modules.process_scanner import analyze_processes, find_suspicious_processes, find_root_processes, list_processes
from modules.package_analyzer import analyze_packages
from modules.logcat_monitor import analyze_logcat
from modules.device_analyzer import gather_device_info, analyze_device_security
from modules.zero_day_checker import run_zero_day_check
from modules.pegasus_detector import run_pegasus_detect
from modules.vpn_detector import analyze_vpn_proxy
from modules.notification_analyzer import (
    analyze_notifications,
    run_notification_mode,
    _get_dumpsys_notification,
    _parse_notification_listeners,
    _parse_non_dismissible_notifications,
    _count_notifications_by_app,
    KNOWN_LISTENER_APPS,
)
from modules.remediation import (
    find_processes_by_name,
    kill_process_interactive,
    monitor_resurrection,
    create_watcher_script,
)
from core.ioc_updater import run_update_iocs
from modules.mvt_check import run_mvt_check

_wireless_ip: Optional[str] = None
_wireless_port: Optional[int] = None
_device_locale: str = "en"


def cleanup_exit():
    global _wireless_ip, _wireless_port
    if _wireless_ip or _wireless_port:
        console.print("\n[bold yellow]\U0001f50c Closing wireless ADB connections...[/]")
        disable_wireless_connections()
        console.print("[green]\u2713 All wireless ADB connections closed.[/]")
        if is_usb_connected():
            switch_to_usb_mode()
            console.print("[green]\u2713 ADB switched back to USB mode.[/]")
        console.print("[yellow]\u26a0\ufe0f Device is no longer accessible via wireless ADB.[/]")
        _wireless_ip = None
        _wireless_port = None


def signal_handler(sig, frame):
    cleanup_exit()
    console.print("\n[bold red]CellInspector terminated.[/]")
    sys.exit(0)


def wait_for_device_or_exit():
    if is_device_ready():
        return

    console.print("\n[bold yellow]\U0001f4f1 Esperando dispositivo...[/]")
    console.print("[dim]Conecta tu tel\u00e9fono por USB con depuraci\u00f3n activada.[/]")

    spinner = 0
    while not is_device_ready():
        spin_chars = ["\u25d0", "\u25d3", "\u25d1", "\u25d2"]
        console.print(f"\r  [cyan]{spin_chars[spinner % 4]}[/] Esperando dispositivo...", end="")
        spinner += 1
        time.sleep(1)

    console.print("\r  [green]\u2713 Dispositivo detectado![/]                     ")
    time.sleep(0.5)


def setup_wireless():
    global _wireless_ip, _wireless_port

    if not is_usb_connected():
        console.print("[yellow]Dispositivo no conectado por USB. No se puede configurar modo inal\u00e1mbrico.[/]")
        return False

    console.print("\n[bold cyan]\U0001f4f6 Modo inal\u00e1mbrico[/]")
    console.print("[dim]Se habilitar\u00e1 ADB por WiFi en un puerto aleatorio.[/]")
    console.print("[dim]Podr\u00e1s desconectar el cable USB y seguir trabajando.[/]")

    ip = get_device_ip()
    if not ip:
        console.print("[red]\u274c No se pudo obtener la IP del dispositivo. Verifica que est\u00e9 conectado a WiFi.[/]")
        return False

    console.print(f"[cyan]\u2022 IP del dispositivo:[/] [bold]{ip}[/]")

    with console.status("[cyan]Configurando ADB inal\u00e1mbrico...[/]"):
        result_ip, result_port = enable_wireless_adb()

    if not result_ip or not result_port:
        console.print("[red]\u274c No se pudo habilitar ADB inal\u00e1mbrico.[/]")
        console.print("[yellow]Aseg\u00farate de que el dispositivo tenga Android 11+ y que la 'Depuraci\u00f3n inal\u00e1mbrica' est\u00e9 activada en Opciones de Desarrollador.[/]")
        return False

    _wireless_ip = result_ip
    _wireless_port = result_port

    console.print(f"\n[green]\u2713 ADB inal\u00e1mbrico activado![/]")
    console.print(f"  [cyan]\u2022 Direcci\u00f3n:[/] [bold]{_wireless_ip}:{_wireless_port}[/]")
    console.print(f"  [yellow]\U0001f5b1 Ya puedes desconectar el cable USB.[/]")
    console.print(f"  [dim]Presiona Enter cuando est\u00e9s listo...[/]", end="")
    input()

    return True


def run_module(
    name: str,
    func,
    progress,
    task_id,
    verbose: bool = False,
) -> List[Tuple]:
    try:
        findings = func()
        progress.update(
            task_id,
            advance=1,
            description=f"[green]\u2713[/] {name}",
        )
        if verbose and findings:
            for finding in findings:
                if finding and len(finding) >= 4 and finding[0] >= Severity.LOW:
                    print_finding(finding[0], finding[1], finding[2], details=finding[4] if len(finding) > 4 else None)
        return findings
    except Exception as e:
        progress.update(
            task_id,
            advance=1,
            description=f"[red]\u2717[/] {name} (error)",
        )
        if verbose:
            console.print(f"[red]Error in {name}: {e}[/]")
        return []


def run_scan(verbose: bool = False, offline: bool = False) -> Tuple[List[Tuple], dict]:
    device_info = gather_device_info()
    console.print("\n[bold cyan]\U0001f4f1 Device Connected[/]")
    print_device_info_table(device_info)

    console.print("[bold]Starting analysis...[/]\n")

    all_findings = []
    summary = []

    with create_progress() as progress:
        task = progress.add_task("[cyan]Scanning device...[/]", total=7)

        modules = [
            ("Network Analysis", analyze_network),
            ("Process Scanner", analyze_processes),
            ("Package Analysis", analyze_packages),
            ("Logcat Analysis", lambda: analyze_logcat()),
            ("Notification Analysis", analyze_notifications),
            ("Device Security", lambda: analyze_device_security(offline=offline)),
            ("VPN/Proxy Detection", analyze_vpn_proxy),
        ]

        for name, func in modules:
            findings = run_module(name, func, progress, task, verbose)
            all_findings.extend(findings)

    console.print("\n[bold]Analysis complete![/]\n")

    for finding in all_findings:
        if finding and len(finding) >= 4:
            sev, title, desc, category = finding[0], finding[1], finding[2], finding[3]
            details = finding[4] if len(finding) > 4 else None
            recommendation = finding[5] if len(finding) > 5 else None

            print_finding(sev, title, desc, details=details, recommendation=recommendation)
            summary.append((sev, title, category))

    return all_findings, device_info


def run_full_scan(verbose: bool = False, wireless: bool = False):
    global _device_locale
    print_banner()
    wait_for_device_or_exit()

    if wireless:
        if not setup_wireless():
            console.print("[yellow]Continuando en modo USB...[/]")

    detected = get_device_locale()
    if detected:
        _device_locale = detected
        lang_name = {"es": "Espa\u00f1ol", "en": "English", "pt": "Portugu\u00eas", "fr": "Fran\u00e7ais"}.get(detected, detected)
        console.print(f"[dim]Idioma del dispositivo: {lang_name} ({detected})[/]")

    all_findings, device_info = run_scan(verbose=verbose)

    print_summary_table([(f[0], f[1], f[3]) for f in all_findings if f and len(f) >= 4])

    total = len(all_findings)
    if total == 0:
        console.print("[bold green]\u2705 Device appears clean! No issues detected.[/]")
    else:
        critical = sum(1 for f in all_findings if len(f) >= 4 and f[0] == Severity.CRITICAL)
        high = sum(1 for f in all_findings if len(f) >= 4 and f[0] == Severity.HIGH)
        medium = sum(1 for f in all_findings if len(f) >= 4 and f[0] == Severity.MEDIUM)
        low = sum(1 for f in all_findings if len(f) >= 4 and f[0] == Severity.LOW)

        console.print(f"\n[bold]Final Report:[/]")
        if critical:
            console.print(f"  [red]\U0001f6a8 Critical: {critical}[/]")
        if high:
            console.print(f"  [orange_red1]\u274c High: {high}[/]")
        if medium:
            console.print(f"  [orange1]\u26a0\ufe0f Medium: {medium}[/]")
        if low:
            console.print(f"  [yellow]\u26a0\ufe0f Low: {low}[/]")
        console.print(f"  [cyan]\u2139\ufe0f Total: {total}[/]")

    manual_findings = [f for f in all_findings if len(f) >= 4 and f[0] >= Severity.LOW]
    render_manual_guides(manual_findings)

    console.print("\n[dim]Report generated by CellInspector[/]")


def run_kill_mode():
    print_banner()
    wait_for_device_or_exit()

    device_info = gather_device_info()
    console.print("\n[bold cyan]\U0001f4f1 Device Connected[/]")
    print_device_info_table(device_info)

    processes = list_processes()
    if not processes:
        console.print("[red]Cannot access process list.[/]")
        return

    console.print("\n[bold]Scanning for suspicious processes...[/]")

    suspicious = find_suspicious_processes(processes)
    root_procs = find_root_processes(processes)
    candidates = []

    if suspicious:
        console.print(f"\n[bold red]\U0001f6a8 {len(suspicious)} suspicious process(es) detected:[/]")
        for p in suspicious:
            console.print(f"  \u2022 [bold]{p['name']}[/] (PID: [cyan]{p['pid']}[/], User: {p['user']})")
            candidates.append(p)

    root_procs_filtered = [p for p in root_procs if p not in suspicious]
    if root_procs_filtered:
        console.print(f"\n[bold orange1]\U0001f6e1\ufe0f  {len(root_procs_filtered)} non-standard root process(es):[/]")
        for p in root_procs_filtered:
            console.print(f"  \u2022 [white]{p['name']}[/] (PID: [cyan]{p['pid']}[/])")
            candidates.append(p)

    if not candidates:
        console.print("[yellow]No processes available for termination.[/]")
        return

    kill_process_interactive(candidates)


def run_report_mode(wireless: bool = False):
    print_banner()
    wait_for_device_or_exit()

    if wireless:
        if not setup_wireless():
            pass

    all_findings, device_info = run_scan(verbose=False)

    report_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "reports")
    os.makedirs(report_dir, exist_ok=True)

    timestamp = time.strftime("%Y%m%d_%H%M%S")
    report_path = os.path.join(report_dir, f"cellinspector_report_{timestamp}.md")

    output = generate_markdown_report(device_info, all_findings, report_path)
    console.print(f"\n[bold green]\u2705 Report saved to:[/] [cyan]{output}[/]")
    console.print(f"\n[bold]Summary:[/]")
    console.print(f"  [dim]\u2022 Total findings: {len(all_findings)}[/]")

    if all_findings:
        max_sev = max(f[0] for f in all_findings)
        console.print(f"  [dim]\u2022 Threat level: {max_sev.label}[/]")

    return report_path


def run_fix_all(verbose: bool = False, wireless: bool = False):
    global _device_locale
    print_banner()
    wait_for_device_or_exit()

    if wireless:
        if not setup_wireless():
            console.print("[yellow]Continuando en modo USB...[/]")

    detected = get_device_locale()
    if detected:
        _device_locale = detected
        lang_name = {"es": "Espa\u00f1ol", "en": "English", "pt": "Portugu\u00eas", "fr": "Fran\u00e7ais"}.get(detected, detected)
        console.print(f"[dim]Idioma del dispositivo: {lang_name} ({detected})[/]")

    console.print("\n[bold cyan]=== Paso 1: Escaneo inicial ===[/]")
    before_findings, device_info = run_scan(verbose=verbose)

    console.print("\n[bold cyan]=== Paso 2: Aplicando correcciones automáticas ===[/]\n")

    fixes_applied = []
    fixes_failed = []

    dumpsys = _get_dumpsys_notification()
    if dumpsys:
        listeners = _parse_notification_listeners(dumpsys)
        suspicious_listeners = [l for l in listeners if l.get("classification") == "suspicious"]
        for l in suspicious_listeners:
            console.print(f"[cyan]Removiendo acceso de listener:[/] {l['package']} ({l.get('label', '?')})...")
            if remove_notification_listener(l["package"]):
                console.print(f"  [green]\u2713 Listener access removed[/]")
                fixes_applied.append(f"Removed notification listener: {l['package']}")
            else:
                console.print(f"  [red]\u2717 No se pudo remover[/]")
                fixes_failed.append(f"Remove listener: {l['package']}")

        counts = _count_notifications_by_app(dumpsys)
        top_apps = [c for c in counts if c["count"] >= 10]
        for app in top_apps:
            console.print(f"[cyan]Cancelando notificaciones de:[/] {app['package']} ({app['count']})...")
            if cancel_all_notifications(app["package"]):
                console.print(f"  [green]\u2713 Notifications cancelled[/]")
                fixes_applied.append(f"Cancelled notifications: {app['package']}")
            else:
                console.print(f"  [red]\u2717 No se pudieron cancelar[/]")

        console.print(f"[cyan]Descartando todas las notificaciones...[/]")
        if dismiss_all_notifications():
            console.print(f"  [green]\u2713 All notifications dismissed[/]")
            fixes_applied.append("Dismissed all notifications")
        else:
            console.print(f"  [red]\u2717 No se pudieron descartar[/]")

        persistent = _parse_non_dismissible_notifications(dumpsys)
        blocked_channels = set()
        for p in persistent:
            pkg = p["package"]
            if pkg in blocked_channels:
                continue
            blocked_channels.add(pkg)
            channels = get_notification_channels(pkg)
            if channels:
                blocked_any = False
                for ch in channels[:5]:
                    console.print(f"[cyan]Bloqueando canal:[/] {pkg}/{ch['id']}...")
                    if set_channel_importance(pkg, ch["id"], 0):
                        blocked_any = True
                if blocked_any:
                    fixes_applied.append(f"Blocked notification channels: {pkg}")
            else:
                console.print(f"[cyan]Force-stopping:[/] {pkg}...")
                if force_stop_package(pkg):
                    fixes_applied.append(f"Force-stopped: {pkg}")

    processes = list_processes()
    killed_pids = set()
    if processes:
        suspicious = find_suspicious_processes(processes)
        root_procs = find_root_processes(processes)
        seen = set()
        candidates = []
        for p in suspicious + root_procs:
            pid = p.get("pid", "")
            if pid not in seen:
                seen.add(pid)
                candidates.append(p)
        for p in candidates:
            pid = p.get("pid", "")
            name = p.get("name", "?")
            if pid in killed_pids:
                continue
            killed_pids.add(pid)
            console.print(f"[cyan]Matando proceso:[/] {name} (PID: {pid})...")
            if kill_process(pid):
                console.print(f"  [green]\u2713 Process killed[/]")
                fixes_applied.append(f"Killed process: {name} (PID: {pid})")
            else:
                pkg_guess = name.split("/")[0]
                if "." in pkg_guess and len(pkg_guess) > 5:
                    console.print(f"  [cyan]Force-stopping package:[/] {pkg_guess}...")
                    if force_stop_package(pkg_guess):
                        console.print(f"  [green]\u2713 Package force-stopped[/]")
                        fixes_applied.append(f"Force-stopped: {pkg_guess}")
                    else:
                        console.print(f"  [red]\u2717 Failed[/]")
                        fixes_failed.append(f"Kill process: {name} (PID: {pid})")
                else:
                    console.print(f"  [red]\u2717 Failed to kill[/]")
                    fixes_failed.append(f"Kill process: {name} (PID: {pid})")

    console.print("\n[bold cyan]=== Resumen de correcciones ===[/]")
    if fixes_applied:
        console.print(f"\n[bold green]\u2705 {len(fixes_applied)} correccion(es) aplicadas:[/]")
        for f in fixes_applied:
            console.print(f"  \u2022 {f}")
    if fixes_failed:
        console.print(f"\n[bold red]\u2717 {len(fixes_failed)} correccion(es) fallaron:[/]")
        for f in fixes_failed:
            console.print(f"  \u2022 [dim]{f}[/]")
    if not fixes_applied and not fixes_failed:
        console.print("[yellow]No se encontraron correcciones automaticas que aplicar.[/]")

    console.print("\n[bold cyan]=== Paso 3: Re-escaneo para verificar cambios ===[/]")
    time.sleep(2)

    after_findings, _ = run_scan(verbose=verbose)

    console.print("\n[bold cyan]=== Comparativa antes/despues ===[/]")

    def _count_by_severity(findings):
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0, "TOTAL": 0}
        for f in findings:
            if len(f) >= 4:
                counts[f[0].label] = counts.get(f[0].label, 0) + 1
                counts["TOTAL"] += 1
        return counts

    before_counts = _count_by_severity(before_findings)
    after_counts = _count_by_severity(after_findings)

    from rich.table import Table
    from rich import box
    delta_table = Table(title="FixAll Delta Report", box=box.ROUNDED, title_style="bold cyan")
    delta_table.add_column("Severity", style="white", no_wrap=True)
    delta_table.add_column("Before", justify="right")
    delta_table.add_column("After", justify="right")
    delta_table.add_column("Delta", justify="right")

    total_before = before_counts["TOTAL"]
    total_after = after_counts["TOTAL"]

    for sev_label in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        b = before_counts.get(sev_label, 0)
        a = after_counts.get(sev_label, 0)
        diff = a - b
        if diff < 0:
            delta_str = f"[green]-{abs(diff)}[/]"
        elif diff > 0:
            delta_str = f"[red]+{diff}[/]"
        else:
            delta_str = "[dim]0[/]"
        delta_table.add_row(sev_label, str(b), str(a), delta_str)

    total_diff = total_after - total_before
    if total_diff < 0:
        total_delta = f"[green]-{abs(total_diff)}[/]"
    elif total_diff > 0:
        total_delta = f"[red]+{total_diff}[/]"
    else:
        total_delta = "[dim]0[/]"
    delta_table.add_row("[bold]TOTAL[/]", str(total_before), str(total_after), total_delta)

    console.print()
    console.print(delta_table)
    console.print()

    if total_after < total_before:
        resolved = total_before - total_after
        console.print(f"[bold green]\u2705 {resolved} hallazgo(s) resuelto(s) automaticamente.[/]")
        if after_findings:
            console.print(f"[yellow]\u26a0\ufe0f {total_after} hallazgo(s) restante(s) requieren atencion manual.[/]")
        else:
            console.print("[bold green]\u2705 Todos los hallazgos han sido resueltos.[/]")
    elif total_after == total_before:
        if fixes_applied:
            console.print("[yellow]Los hallazgos son los mismos, pero se aplicaron correcciones de fondo")
            console.print("[yellow](las notificaciones pueden reaparecer al abrir las apps).[/]")
        else:
            console.print("[yellow]No se realizaron cambios detectables. Los hallazgos pueden requerir intervencion manual.[/]")
    else:
        console.print("[red]Algunos hallazgos nuevos aparecieron (posiblemente rotacion de procesos/notificaciones).[/]")

    if not fixes_applied and fixes_failed:
        console.print(f"\n[bold red]\u2717 Todas las correcciones fallaron. Verifica la conexion ADB.[/]")
    elif fixes_applied:
        console.print(f"\n[bold green]\u2713 {len(fixes_applied)} correccion(es) aplicadas exitosamente.[/]")

    remaining_findings = [f for f in after_findings if len(f) >= 4 and f[0] >= Severity.LOW]
    render_manual_guides(remaining_findings)

    console.print(f"\n[dim]FixAll completed. Run without --fixall for a standard scan.[/]")


def run_monitor(verbose: bool = False, interval: int = 10, wireless: bool = False):
    print_banner()
    wait_for_device_or_exit()

    if wireless:
        if not setup_wireless():
            pass

    console.print(f"\n[bold cyan]\U0001f52c Monitoring mode active[/]")
    console.print(f"[dim]Refreshing every {interval} seconds. Press Ctrl+C to stop.[/]\n")

    try:
        while True:
            console.print(f"[bold cyan]--- [{time.strftime('%H:%M:%S')}] Scan ---[/]")

            device_info = gather_device_info()
            print_device_info_table(device_info)

            modules = [
                ("Network", analyze_network),
                ("Processes", analyze_processes),
                ("Packages", analyze_packages),
                ("Logcat", lambda: analyze_logcat(1000)),
                ("Notifications", analyze_notifications),
                ("Security", analyze_device_security),
            ]

            all_findings = []
            for name, func in modules:
                with console.status(f"[cyan]Analyzing {name}...[/]"):
                    findings = func()
                all_findings.extend(findings)

                for finding in findings:
                    if finding and len(finding) >= 4:
                        sev, title, desc, category = finding[0], finding[1], finding[2], finding[3]
                        details = finding[4] if len(finding) > 4 else None
                        rec = finding[5] if len(finding) > 5 else None
                        if sev >= Severity.LOW:
                            print_finding(sev, title, desc, details=details, recommendation=rec)

            summary = [(f[0], f[1], f[3]) for f in all_findings if f and len(f) >= 4]
            print_summary_table(summary)

            console.print(f"[dim]Next scan in {interval} seconds...[/]\n")
            time.sleep(interval)
    except KeyboardInterrupt:
        console.print("\n[bold red]Monitoring stopped.[/]")


def run_live_logcat():
    print_banner()
    wait_for_device_or_exit()
    console.print("\n[bold cyan]\U0001f4e1 Live Logcat Monitor[/]")
    console.print("[dim]Streaming real-time logcat. Ctrl+C to stop.[/]\n")
    try:
        import subprocess
        proc = subprocess.Popen(
            ["adb", "logcat", "-v", "time"],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )
        while True:
            line = proc.stdout.readline()
            if not line:
                break
            if "FATAL EXCEPTION" in line or "CRASH" in line.upper():
                console.print(f"[bold red]{line.strip()}[/]")
            elif "ANR" in line:
                console.print(f"[bold orange1]{line.strip()}[/]")
            elif "Error" in line or "error" in line:
                console.print(f"[yellow]{line.strip()}[/]")
            elif "frida" in line.lower() or "ptrace" in line.lower():
                console.print(f"[bold red]\U0001f6a8 {line.strip()}[/]")
            else:
                console.print(f"[dim]{line.strip()}[/]")
    except KeyboardInterrupt:
        console.print("\n[bold red]Live logcat stopped.[/]")
    except FileNotFoundError:
        console.print("[red]ADB not found. Ensure adb is installed and in PATH.[/]")


def run_all(verbose: bool = False, wireless: bool = False, offline: bool = False, json_output: bool = False):
    global _device_locale
    print_banner()
    wait_for_device_or_exit()

    if wireless:
        if not setup_wireless():
            console.print("[yellow]Continuando en modo USB...[/]")

    detected = get_device_locale()
    if detected:
        _device_locale = detected
        lang_name = {"es": "Espa\u00f1ol", "en": "English", "pt": "Portugu\u00eas", "fr": "Fran\u00e7ais"}.get(detected, detected)
        console.print(f"[dim]Idioma del dispositivo: {lang_name} ({detected})[/]")

    all_findings, device_info = run_scan(verbose=verbose)

    if not offline:
        console.print("\n[bold cyan]\U0001f50d Extended Analysis (requires internet)[/]")
        from modules.zero_day_checker import run_zero_day_check
        from modules.pegasus_detector import run_pegasus_detect

        console.print("\n[bold]--- Zero-Day Scan ---[/]")
        run_zero_day_check(deep=False)

        console.print("\n[bold]--- Pegasus Detection ---[/]")
        run_pegasus_detect()

    vpn_findings = analyze_vpn_proxy()
    all_findings.extend(vpn_findings)
    if verbose:
        for f in vpn_findings:
            if len(f) >= 4 and f[0] >= Severity.LOW:
                print_finding(f[0], f[1], f[2], details=f[4] if len(f) > 4 else None)

    print_summary_table([(f[0], f[1], f[3]) for f in all_findings if f and len(f) >= 4])

    total = len(all_findings)
    if total == 0:
        console.print("[bold green]\u2705 Device appears clean! No issues detected.[/]")
    else:
        critical = sum(1 for f in all_findings if len(f) >= 4 and f[0] == Severity.CRITICAL)
        high = sum(1 for f in all_findings if len(f) >= 4 and f[0] == Severity.HIGH)
        medium = sum(1 for f in all_findings if len(f) >= 4 and f[0] == Severity.MEDIUM)
        low = sum(1 for f in all_findings if len(f) >= 4 and f[0] == Severity.LOW)
        console.print(f"\n[bold]Final Report:[/]")
        if critical:
            console.print(f"  [red]\U0001f6a8 Critical: {critical}[/]")
        if high:
            console.print(f"  [orange_red1]\u274c High: {high}[/]")
        if medium:
            console.print(f"  [orange1]\u26a0\ufe0f Medium: {medium}[/]")
        if low:
            console.print(f"  [yellow]\u26a0\ufe0f Low: {low}[/]")
        console.print(f"  [cyan]\u2139\ufe0f Total: {total}[/]")

    if json_output:
        report_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "reports")
        os.makedirs(report_dir, exist_ok=True)
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        json_path = os.path.join(report_dir, f"cellinspector_report_{timestamp}.json")
        generate_json_report(device_info, all_findings, json_path)
        console.print(f"\n[green]\u2713 JSON report saved:[/] [cyan]{json_path}[/]")

    manual_findings = [f for f in all_findings if len(f) >= 4 and f[0] >= Severity.LOW]
    render_manual_guides(manual_findings)

    console.print("\n[dim]Full analysis completed by CellInspector[/]")


def main():
    parser = argparse.ArgumentParser(
        description="CellInspector - Mobile Device Security Auditor",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog="""
Examples:
   %(prog)s                          Run full device security scan
  %(prog)s --0days                  Scan GitHub for active PoC exploits
  %(prog)s --0days --deep           Deep scan: Reddit, Pastebin, forums + GitHub
  %(prog)s --pegasus-detect         Scan device for Pegasus spyware indicators
  %(prog)s --all                    Run full scan + zero-day + pegasus + VPN/Proxy
  %(prog)s --all --json             Full scan with JSON report export
  %(prog)s --all --offline          Full scan without internet-dependent checks
  %(prog)s --live                   Real-time logcat streaming with alerts
  %(prog)s --wireless               Enable wireless ADB before scanning
  %(prog)s --verbose                Run scan with verbose output
  %(prog)s --monitor                Monitor device in real-time
  %(prog)s --kill                   List and kill suspicious processes
  %(prog)s --notifications          Interactive notification management
   %(prog)s --mvt-check               Check device with MVT STIX2 indicators
  %(prog)s --fixall                 Auto-fix all issues and re-verify
  %(prog)s --report                 Run scan and generate Markdown report
  %(prog)s --update-ioc             Download threat intelligence feeds to data/
  %(prog)s --monitor --interval 30  Monitor every 30 seconds
    """,
    )
    parser.add_argument(
        "--0days",
        action="store_true",
        dest="zero_days",
        help="Search GitHub for active PoC exploits targeting this device",
    )
    parser.add_argument(
        "--deep",
        action="store_true",
        dest="deep_scan",
        help="Deep scan: search Reddit, Pastebin, and web forums for PoC exploits (use with --0days)",
    )
    parser.add_argument(
        "-f", "--fixall",
        action="store_true",
        help="Auto-fix all detected issues and re-verify",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Show detailed findings during scan",
    )
    parser.add_argument(
        "-m", "--monitor",
        action="store_true",
        help="Real-time monitoring mode",
    )
    parser.add_argument(
        "-k", "--kill",
        action="store_true",
        help="Interactive process killer mode",
    )
    parser.add_argument(
        "-n", "--notifications",
        action="store_true",
        help="Interactive notification management mode",
    )
    parser.add_argument(
        "-r", "--report",
        action="store_true",
        help="Generate Markdown report after scan",
    )
    parser.add_argument(
        "-w", "--wireless",
        action="store_true",
        help="Enable wireless ADB (WiFi) connection before scanning",
    )
    parser.add_argument(
        "-i", "--interval",
        type=int,
        default=10,
        help="Monitoring interval in seconds (default: 10)",
    )
    parser.add_argument(
        "--pegasus-detect",
        action="store_true",
        help="Scan device for Pegasus spyware indicators of compromise",
    )
    parser.add_argument(
        "--all",
        action="store_true",
        dest="run_all",
        help="Run full analysis: security scan + zero-day + Pegasus + VPN/Proxy",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        dest="json_output",
        help="Export findings as JSON report (use with --all or standalone)",
    )
    parser.add_argument(
        "--offline",
        action="store_true",
        help="Skip all internet-dependent checks (C2, GitHub, DuckDuckGo)",
    )
    parser.add_argument(
        "--live",
        action="store_true",
        help="Stream real-time logcat with alert highlighting",
    )
    parser.add_argument(
        "--version",
        action="store_true",
        help="Show version and exit",
    )
    parser.add_argument(
        "--update-ioc",
        action="store_true",
        help="Download threat intelligence feeds (MalwareBazaar, CISA) to data/",
    )
    parser.add_argument(
        "--mvt-check",
        action="store_true",
        help="Check device with MVT STIX2 indicators (Pegasus, Predator, etc.)",
    )
    parser.add_argument(
        "--no-banner",
        action="store_true",
        help="Skip the banner display",
    )

    args = parser.parse_args()

    atexit.register(cleanup_exit)
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    if args.version:
        console.print(f"[bold cyan]CellInspector[/] [white]v{VERSION}[/]")
        console.print("[dim]Mobile Device Security Auditor[/]")
        return

    if args.update_ioc:
        run_update_iocs()
        return

    if args.mvt_check:
        if not args.no_banner:
            print_banner()
        wait_for_device_or_exit()
        run_mvt_check()
        return

    if args.live:
        run_live_logcat()
        return

    if args.run_all:
        run_all(verbose=args.verbose, wireless=args.wireless, offline=args.offline, json_output=args.json_output)
        return

    if args.zero_days:
        if not args.no_banner:
            print_banner()
        wait_for_device_or_exit()
        run_zero_day_check(deep=args.deep_scan)
    elif args.pegasus_detect:
        if not args.no_banner:
            print_banner()
        wait_for_device_or_exit()
        run_pegasus_detect()
    elif args.fixall:
        run_fix_all(verbose=args.verbose, wireless=args.wireless)
    elif args.kill:
        run_kill_mode()
    elif args.notifications:
        wait_for_device_or_exit()
        run_notification_mode()
    elif args.report:
        run_report_mode(wireless=args.wireless)
    elif args.monitor:
        run_monitor(verbose=args.verbose, interval=args.interval, wireless=args.wireless)
    else:
        run_full_scan(verbose=args.verbose, wireless=args.wireless)


if __name__ == "__main__":
    main()
