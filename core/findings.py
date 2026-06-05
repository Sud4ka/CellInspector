"""
core/findings.py

Multi-indicator corroboration engine for CellInspector.

Problem we solve:
    A single IOC match on its own is almost never proof of compromise. Real
    infections show *clusters* of independent indicators (process + C2
    connection + suspicious file + hash match, etc.).

This module:
    * defines a Finding dataclass with confidence + evidence
    * groups findings into clusters by family/target
    * upgrades cluster severity when 2+ independent indicators corroborate
    * exposes a small, testable surface (`add`, `evaluate`, `render`)

Rule summary (multi-indicator mode):
    * 1 CRITICAL match  -> CRITICAL regardless
    * 1 HIGH match alone -> MEDIUM (not enough on its own)
    * 2+ independent MEDIUMs -> HIGH
    * 1 HIGH + 1 MEDIUM (independent) -> HIGH
    * 1 HIGH + 1 HIGH -> CRITICAL
    * 1 MEDIUM alone  -> MEDIUM
    * 1 LOW alone     -> INFO
    * 0 findings      -> CLEAN
"""

from dataclasses import dataclass, field
from typing import List, Optional, Tuple


# ---------------------------------------------------------------------------
# Confidence levels (kept in sync with core/confidence.py label values)
# ---------------------------------------------------------------------------

LEVELS = ("CLEAN", "INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL")
RANK = {lvl: i for i, lvl in enumerate(LEVELS)}

# Independent indicator classes. Two findings in the same class don't
# corroborate each other.
CLASS_PROCESS = "process"
CLASS_PACKAGE = "package"
CLASS_FILE_PATH = "file_path"
CLASS_FILE_HASH = "file_hash"
CLASS_NETWORK = "network"
CLASS_KERNEL = "kernel"
CLASS_PROPERTY = "system_property"
CLASS_OTHER = "other"


@dataclass
class Finding:
    label: str                 # CRITICAL | HIGH | MEDIUM | LOW | INFO
    score: int                 # 0..100
    family: str                # "Pegasus", "Predator", "Generic", ...
    indicator_class: str       # one of CLASS_*
    title: str                 # short human title
    detail: str = ""           # supporting evidence
    raw_value: str = ""        # the actual IOC value
    source: str = ""           # "mvt", "pegasus", "stix2:pegasus"
    recommendation: str = ""

    def to_dict(self) -> dict:
        return {
            "label": self.label,
            "score": self.score,
            "family": self.family,
            "class": self.indicator_class,
            "title": self.title,
            "detail": self.detail,
            "value": self.raw_value,
            "source": self.source,
        }

    @property
    def rank(self) -> int:
        return RANK.get(self.label, 0)


def _compare(a: str, b: str) -> str:
    return a if RANK.get(a, 0) >= RANK.get(b, 0) else b


def _corroborate_cluster(findings: List[Finding]) -> Tuple[str, int]:
    """Return the corroborated (label, score) for a cluster.

    Two findings corroborate each other only if they are in different
    indicator classes. Same-class matches only count as one piece of evidence.
    """

    if not findings:
        return ("CLEAN", 100)

    classes = {f.indicator_class for f in findings}
    max_score = max(f.score for f in findings)
    has_critical = any(f.label == "CRITICAL" for f in findings)
    has_high = any(f.label == "HIGH" for f in findings)
    has_medium = any(f.label == "MEDIUM" for f in findings)
    has_low = any(f.label == "LOW" for f in findings)

    # File hash on its own is the gold standard
    if CLASS_FILE_HASH in classes and any(
        f.label in ("HIGH", "CRITICAL") and f.indicator_class == CLASS_FILE_HASH
        for f in findings
    ):
        return ("CRITICAL", max(95, max_score))

    if has_critical and len(classes) >= 2:
        return ("CRITICAL", max_score)

    if has_high and has_medium and len(classes) >= 2:
        return ("HIGH", max_score)

    if has_high and has_high and len(classes) >= 2:
        return ("CRITICAL", max_score)

    medium_classes = {f.indicator_class for f in findings if f.label == "MEDIUM"}
    if len(medium_classes) >= 2:
        return ("HIGH", max_score)

    if has_high and len(classes) >= 2:
        return ("HIGH", max_score)

    if has_high:
        # HIGH alone is suspicious but not conclusive
        return ("MEDIUM", max_score)

    if has_medium and len(classes) >= 2:
        return ("MEDIUM", max_score)

    if has_medium:
        return ("MEDIUM", max_score)

    if has_low:
        # Single LOW indicator on its own is treated as INFO. We only
        # surface it as LOW when at least one other class corroborates.
        if len(classes) >= 2:
            return ("LOW", max_score)
        return ("INFO", max_score)

    if findings:
        return ("INFO", max_score)

    return ("CLEAN", 100)


@dataclass
class FindingReport:
    """Aggregated result of a family of findings."""

    family: str
    findings: List[Finding] = field(default_factory=list)
    label: str = "CLEAN"
    score: int = 100

    def add(self, f: Finding) -> None:
        self.findings.append(f)
        self.label, self.score = _corroborate_cluster(self.findings)

    def merge(self, other: "FindingReport") -> None:
        for f in other.findings:
            self.add(f)

    def is_actionable(self) -> bool:
        return self.label in ("CRITICAL", "HIGH")

    def by_class(self) -> dict:
        out = {}
        for f in self.findings:
            out.setdefault(f.indicator_class, []).append(f)
        return out

    def to_dict(self) -> dict:
        return {
            "family": self.family,
            "label": self.label,
            "score": self.score,
            "classes": sorted({f.indicator_class for f in self.findings}),
            "findings": [f.to_dict() for f in self.findings],
        }


# ---------------------------------------------------------------------------
# Recommendation text per corroborated level
# ---------------------------------------------------------------------------

_RECOMMENDATIONS = {
    "CRITICAL": (
        "Disconnected confirmed indicators (hash + C2 traffic OR multi-class "
        "HIGH+CRITICAL). Treat as an active compromise: factory reset from "
        "recovery mode, rotate all credentials from a trusted device, enable "
        "hardware-key 2FA on every account."
    ),
    "HIGH": (
        "Multiple independent indicators agree. The device is very likely "
        "compromised. Disconnect from networks, back up only essential data, "
        "factory reset from recovery, and rotate credentials."
    ),
    "MEDIUM": (
        "At least one credible indicator was found. Investigate manually "
        "before concluding infection. Look for corroborating evidence "
        "(unusual data usage, battery drain, unknown processes at boot, "
        "unexpected SMS)."
    ),
    "LOW": (
        "Only weak indicators were found. These often correspond to "
        "legitimate system components or stale IOCs. No immediate action "
        "required; monitor the device for additional symptoms."
    ),
    "INFO": (
        "Informational. No action needed."
    ),
    "CLEAN": (
        "No indicators found. Absence of evidence is not evidence of absence."
    ),
}


def get_recommendation(label: str) -> str:
    return _RECOMMENDATIONS.get(label, _RECOMMENDATIONS["INFO"])


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------

_BADGE_COLOR = {
    "CRITICAL": "red",
    "HIGH": "orange_red1",
    "MEDIUM": "orange1",
    "LOW": "yellow",
    "INFO": "cyan",
    "CLEAN": "green",
}


def render_reports(reports: List[FindingReport], console, format_confidence_badge=None):
    """Pretty-print the corroborated reports. Optional custom badge fn."""
    if not reports:
        console.print("[bold green]\u2705 No indicators matched this device.[/]")
        return

    actionable = [r for r in reports if r.is_actionable()]
    informational = [r for r in reports if not r.is_actionable() and r.findings]

    if not actionable and not informational:
        console.print("[bold green]\u2705 No indicators matched this device.[/]")
        return

    for rep in actionable + informational:
        color = _BADGE_COLOR.get(rep.label, "white")
        badge = (
            f"[bold {color}]{rep.label} ({rep.score}/100)[/]"
            if not format_confidence_badge
            else format_confidence_badge(rep.score, rep.label)
        )
        console.print(f"\n  {badge}  [bold]{rep.family}[/]  ({len(rep.findings)} indicator(s))")
        for f in sorted(rep.findings, key=lambda x: -x.score):
            sub_color = _BADGE_COLOR.get(f.label, "white")
            console.print(
                f"    [bold {sub_color}]\u25b8 {f.label}[/] "
                f"[dim]({f.indicator_class})[/] {f.title}"
            )
            if f.detail:
                console.print(f"        [dim]{f.detail}[/]")
        console.print(f"    [dim]Recommendation:[/] {get_recommendation(rep.label)}")
