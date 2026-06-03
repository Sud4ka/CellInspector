import time
import os
import signal
from typing import List, Optional

from core.display import console
from core.adb_client import shell_command, kill_process, force_stop_package, disable_package, get_pid_by_name, SUDO_PASSWORD
from core.severity import Severity


def find_processes_by_name(name_fragment: str) -> List[dict]:
    output = shell_command(f"ps -A 2>/dev/null | grep -i '{name_fragment}'")
    if not output:
        return []
    procs = []
    for line in output.strip().split("\n"):
        parts = line.split()
        if len(parts) >= 9:
            procs.append({
                "pid": parts[1],
                "name": parts[-1],
                "user": parts[0],
            })
    return procs


def kill_process_interactive(processes: List[dict]):
    if not processes:
        console.print("[yellow]No suspicious processes found to kill.[/]")
        return

    console.print("\n[bold red]\U0001f5d1  Suspicious Processes - Select to Kill[/]")
    for i, proc in enumerate(processes, 1):
        console.print(f"  [bold]{i}.[/] PID [cyan]{proc['pid']}[/] - [white]{proc['name']}[/] ([dim]{proc['user']}[/])")

    if not processes:
        console.print("[yellow]No processes available for termination.[/]")
        return

    console.print(f"\n[dim]Enter numbers (1-{len(processes)}) separated by commas, 'a' for all, or 'q' to quit:[/]")
    choice = input("  > ").strip().lower()

    if choice == "q":
        return

    indices = []
    if choice == "a":
        indices = list(range(len(processes)))
    else:
        for part in choice.split(","):
            part = part.strip()
            if part.isdigit():
                idx = int(part) - 1
                if 0 <= idx < len(processes):
                    indices.append(idx)

    if not indices:
        console.print("[red]No valid selections.[/]")
        return

    killed = []
    for idx in indices:
        proc = processes[idx]
        console.print(f"\n[cyan]Attempting to kill {proc['name']} (PID: {proc['pid']})...[/]")

        success = kill_process(proc["pid"])
        if success:
            console.print(f"  [green]\u2713 Process {proc['name']} (PID: {proc['pid']}) killed successfully[/]")
            killed.append(proc)
        else:
            console.print(f"  [red]\u2717 Failed to kill {proc['name']} (PID: {proc['pid']})[/]")

            alt = force_stop_package_by_pid(proc["pid"])
            if alt:
                console.print(f"  [green]\u2713 Force-stop via package succeeded[/]")
                killed.append(proc)

    if killed:
        monitor_resurrection(killed)


def force_stop_package_by_pid(pid: str) -> bool:
    cmdline = shell_command(f"cat /proc/{pid}/cmdline 2>/dev/null | tr '\\0' ' '")
    if not cmdline:
        return False
    pkg = cmdline.strip().split()[0] if cmdline.strip() else ""
    if pkg and "." in pkg:
        console.print(f"  [dim]Trying force-stop package: {pkg}[/]")
        result = shell_command(f"am force-stop {pkg} 2>/dev/null && echo 'OK' || echo 'FAIL'")
        return result is not None and "OK" in result
    return False


def monitor_resurrection(killed_procs: List[dict], check_seconds: int = 15, interval: float = 2.0):
    console.print(f"\n[bold yellow]\U0001f50d Monitoring for resurrection ({check_seconds}s)...[/]")

    watchlist = {p["name"]: p for p in killed_procs}
    resurrected = []

    for second in range(0, check_seconds, int(interval)):
        time.sleep(interval)
        for name, orig in list(watchlist.items()):
            procs = find_processes_by_name(name)
            if procs:
                watchlist.pop(name, None)
                resurrected.append((name, procs))
                console.print(f"  [red]\U0001f4af Process '{name}' has RESURRECTED! (PID: {procs[0]['pid']})[/]")

        if not watchlist:
            break

    if not resurrected:
        console.print(f"  [green]\u2705 No resurrection detected. All processes stayed dead.[/]")
    else:
        console.print(f"\n[bold red]\U0001f6a8 {len(resurrected)} process(es) resurrected![/]")
        for name, procs in resurrected:
            console.print(f"  - [red]{name}[/] (new PID: {procs[0]['pid']})")

        console.print("\n[bold yellow]Options:[/]")
        console.print("  [1] Create persistent watcher to keep killing this process")
        console.print("  [2] Disable the associated package (if available)")
        console.print("  [3] Skip - do nothing")
        choice = input("  > ").strip()

        for name, procs in resurrected:
            if choice == "1":
                create_watcher_script(name, procs)
            elif choice == "2":
                cmdline = shell_command(f"cat /proc/{procs[0]['pid']}/cmdline 2>/dev/null | tr '\\0' ' '")
                if cmdline:
                    pkg = cmdline.strip().split()[0]
                    if pkg and "." in pkg:
                        result = disable_package(pkg)
                        if result:
                            console.print(f"  [green]\u2713 Package {pkg} disabled[/]")
                        else:
                            console.print(f"  [red]\u2717 Could not disable {pkg}[/]")
            else:
                console.print(f"  [dim]Skipping {name}[/]")


def create_watcher_script(process_name: str, procs: list, ip_address: str = None):
    watcher_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    watcher_path = os.path.join(watcher_dir, f"watcher_{process_name}.sh")

    script_lines = [
        "#!/bin/bash",
        f"# CellInspector Watcher - Monitors and kills: {process_name}",
        f"# Created: {time.strftime('%Y-%m-%d %H:%M:%S')}",
        "# This script runs continuously to prevent the process from running.",
        "# Add to crontab or run in background to auto-start on boot.",
        "",
        f'TARGET="{process_name}"',
        'ADB="/usr/bin/adb"',
        f'SUDO_PASS="{SUDO_PASSWORD}"',
        "",
        'echo "[CellInspector Watcher] Monitoring process: $TARGET"',
        "",
        "while true; do",
        '    PIDS=$(echo "$SUDO_PASS" | sudo -S $ADB shell "ps -A 2>/dev/null | grep -i \'' + process_name + "' | awk '{print \\$2}'\" 2>/dev/null)",
        "",
        '    if [ -n "$PIDS" ]; then',
        "        for PID in $PIDS; do",
        '            echo "[$(date \'+%H:%M:%S\')] Killing $TARGET (PID: $PID)"',
        '            echo "$SUDO_PASS" | sudo -S $ADB shell "kill $PID" 2>/dev/null',
        '            CMDLINE=$(echo "$SUDO_PASS" | sudo -S $ADB shell "cat /proc/$PID/cmdline 2>/dev/null | tr \'\\0\' \' \'" 2>/dev/null)',
        "            PKG=$(echo $CMDLINE | cut -d' ' -f1)",
        '            if echo $PKG | grep -q "\\."; then',
        '                echo "$SUDO_PASS" | sudo -S $ADB shell "am force-stop $PKG" 2>/dev/null',
        "            fi",
        "        done",
        "    fi",
        "    sleep 5",
        "done",
        "",
    ]
    content = "\n".join(script_lines)

    with open(watcher_path, "w") as f:
        f.write(content)

    os.chmod(watcher_path, 0o755)

    console.print(f"\n[green]\u2713 Watcher script created:[/] [bold]{watcher_path}[/]")
    console.print(f"\n[bold cyan]To run in background:[/]")
    console.print(f"  [white]nohup {watcher_path} &[/]")
    console.print(f"\n[bold cyan]To add to crontab (start on boot):[/]")
    console.print(f"  [white]@reboot {watcher_path} &[/]")
    console.print(f"\n[dim]The watcher checks every 5 seconds and auto-kills '{process_name}'[/]")
