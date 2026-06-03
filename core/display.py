from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.layout import Layout
from rich.live import Live
from rich.text import Text
from rich import box
import time
from typing import List, Optional
from core.severity import Severity

console = Console()


def create_thermometer(severity: Severity, label: str = "THREAT LEVEL") -> Panel:
    levels = [
        (Severity.INFO, "\u2501" * 5),
        (Severity.LOW, "\u2501" * 5),
        (Severity.MEDIUM, "\u2501" * 5),
        (Severity.HIGH, "\u2501" * 5),
        (Severity.CRITICAL, "\u2501" * 5),
    ]

    segments = []
    for sev, bar in levels:
        if sev.value < severity.value:
            color = sev.color
            char = "\u2588"
        elif sev.value == severity.value:
            color = sev.color
            char = "\u2588"
        else:
            color = "grey23"
            char = "\u2501"

        style = f"bold {color}" if sev.value <= severity.value else color
        segments.append(f"[{style}]{char * 5}[/]")

    bar_str = "".join(segments)

    indicator = f"[bold {severity.color}]{severity.emoji} {severity.label}[/]"

    content = Text.assemble(
        (f"  {label}:  ", "bold white"),
        (bar_str, ""),
        "\n",
        (f"  Current: {indicator}", ""),
    )

    border_style = severity.color if severity.value >= Severity.MEDIUM.value else "grey"

    return Panel(
        content,
        border_style=border_style,
        box=box.ROUNDED,
        padding=(0, 1),
        title="[bold]SEVERITY THERMOMETER[/]",
        title_align="center",
    )


def print_banner():
    banner = r"""
[bold cyan]   ____          _ _    ___           _           __
  / ___|___   __| | |  |_ _|_ __  ___(_)_ __   ___ _ __ ___
 | |   / _ \ / _` | |   | || '_ \/ __| | '_ \ / _ \ '__/ __|
 | |__| (_) | (_| | |___| || | | \__ \ | |_) |  __/ |  \__ \
  \____\___/ \__,_|_____|___|_| |_|___/_| .__/ \___|_|  |___/
                                         |_|[/]
[dim]    Mobile Device Security Auditor - v1.0.0[/]
"""
    console.print(banner, justify="center")


def print_finding(
    severity: Severity,
    title: str,
    description: str,
    details: Optional[List[str]] = None,
    recommendation: Optional[str] = None,
):
    color = severity.color

    panel_content = [f"[{color}]{description}[/]"]

    if details:
        panel_content.append("\n\n[bold]Details:[/]")
        for d in details:
            panel_content.append(f"\n  \u2022 {d}")

    if recommendation:
        panel_content.append(f"\n\n[bold green]Recommendation:[/] {recommendation}")

    panel = Panel(
        "\n".join(panel_content),
        title=f"[bold {color}]{severity.emoji} [{severity.label}] {title}[/]",
        border_style=color,
        box=box.ROUNDED,
        padding=(1, 2),
    )
    console.print(panel)
    console.print()


def print_device_info_table(info: dict):
    table = Table(title="Device Information", box=box.ROUNDED, title_style="bold cyan")
    table.add_column("Property", style="cyan", no_wrap=True)
    table.add_column("Value", style="white")

    for key, value in info.items():
        table.add_row(key, str(value))

    console.print(table)
    console.print()


def print_summary_table(findings: List[tuple]):
    if not findings:
        console.print("[green]\u2705 No findings detected. Device looks clean![/]")
        return

    table = Table(
        title="Findings Summary",
        box=box.ROUNDED,
        title_style="bold",
        header_style="bold white",
    )
    table.add_column("#", style="dim")
    table.add_column("Severity", no_wrap=True)
    table.add_column("Title", style="white")
    table.add_column("Category", style="cyan")

    max_severity = Severity.INFO
    for i, (sev, title, category) in enumerate(findings, 1):
        table.add_row(
            str(i),
            f"[{sev.color}]{sev.emoji} {sev.label}[/]",
            title,
            category,
        )
        if sev > max_severity:
            max_severity = sev

    console.print()
    console.print(table)
    console.print()
    console.print(create_thermometer(max_severity))
    console.print()


def create_progress() -> Progress:
    return Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        console=console,
    )


def generate_markdown_report(
    device_info: dict,
    findings: List[tuple],
    output_path: str,
):
    if not findings:
        max_sev = Severity.INFO
    else:
        max_sev = max(f[0] for f in findings)

    severity_emoji = {
        Severity.INFO: "",
        Severity.LOW: "",
        Severity.MEDIUM: "",
        Severity.HIGH: "",
        Severity.CRITICAL: "",
    }
    severity_label = {
        Severity.INFO: "Info",
        Severity.LOW: "Low",
        Severity.MEDIUM: "Medium",
        Severity.HIGH: "High",
        Severity.CRITICAL: "Critical",
    }

    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")

    critical = sum(1 for f in findings if f[0] == Severity.CRITICAL)
    high = sum(1 for f in findings if f[0] == Severity.HIGH)
    medium = sum(1 for f in findings if f[0] == Severity.MEDIUM)
    low = sum(1 for f in findings if f[0] == Severity.LOW)
    info = sum(1 for f in findings if f[0] == Severity.INFO)

    lines = []
    lines.append(f"# CellInspector Security Report")
    lines.append(f"")
    lines.append(f"**Device:** {device_info.get('Manufacturer', 'Unknown')} {device_info.get('Model', 'Unknown')}")
    lines.append(f"**Android:** {device_info.get('Android Version', 'Unknown')} (API {device_info.get('API Level', '?')})")
    lines.append(f"**Security Patch:** {device_info.get('Security Patch', 'Unknown')}")
    lines.append(f"**Serial:** {device_info.get('Serial', 'Unknown')}")
    lines.append(f"**Scan Date:** {timestamp}")
    lines.append(f"")
    lines.append(f"---")
    lines.append(f"")
    lines.append(f"## Summary")
    lines.append(f"")
    lines.append(f"| Severity | Count |")
    lines.append(f"|----------|-------|")
    lines.append(f"| Critical | {critical} |")
    lines.append(f"| High     | {high} |")
    lines.append(f"| Medium   | {medium} |")
    lines.append(f"| Low      | {low} |")
    lines.append(f"| Info     | {info} |")
    lines.append(f"| **Total** | **{len(findings)}** |")
    lines.append(f"")
    lines.append(f"**Overall Threat Level: {max_sev.label}**")
    lines.append(f"")
    lines.append(f"---")
    lines.append(f"")
    lines.append(f"## Findings")
    lines.append(f"")

    for i, finding in enumerate(findings, 1):
        if len(finding) < 4:
            continue
        sev, title, desc, category = finding[0], finding[1], finding[2], finding[3]
        details = finding[4] if len(finding) > 4 else None
        recommendation = finding[5] if len(finding) > 5 else None

        lines.append(f"### {i}. [{sev.label}] {title}")
        lines.append(f"")
        lines.append(f"| | |")
        lines.append(f"|---|---|")
        lines.append(f"| **Category** | {category} |")
        lines.append(f"| **Severity** | {sev.label} |")
        lines.append(f"")
        lines.append(f"{desc}")
        lines.append(f"")

        if details:
            lines.append(f"**Details:**")
            lines.append(f"")
            for d in details:
                lines.append(f"- {d}")
            lines.append(f"")

        if recommendation:
            lines.append(f"> **Recommendation:** {recommendation}")
            lines.append(f"")

        lines.append(f"---")
        lines.append(f"")

    lines.append(f"## Device Information")
    lines.append(f"")
    lines.append(f"| Property | Value |")
    lines.append(f"|----------|-------|")
    for key, value in device_info.items():
        lines.append(f"| {key} | {value} |")
    lines.append(f"")
    lines.append(f"---")
    lines.append(f"")
    lines.append(f"*Report generated by CellInspector on {timestamp}*")

    content = "\n".join(lines)

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(content)

    return output_path
