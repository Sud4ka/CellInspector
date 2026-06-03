from enum import Enum
from rich.color import Color
from rich.style import Style


class Severity(Enum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4
    WARNING = 5

    def __lt__(self, other):
        if isinstance(other, Severity):
            return self.value < other.value
        return NotImplemented

    def __le__(self, other):
        if isinstance(other, Severity):
            return self.value <= other.value
        return NotImplemented

    def __gt__(self, other):
        if isinstance(other, Severity):
            return self.value > other.value
        return NotImplemented

    def __ge__(self, other):
        if isinstance(other, Severity):
            return self.value >= other.value
        return NotImplemented

    @property
    def color(self) -> str:
        return {
            Severity.INFO: "cyan",
            Severity.LOW: "yellow",
            Severity.MEDIUM: "orange1",
            Severity.HIGH: "orange_red1",
            Severity.CRITICAL: "red1",
            Severity.WARNING: "yellow",
        }[self]

    @property
    def emoji(self) -> str:
        return {
            Severity.INFO: "\u2139\ufe0f",
            Severity.LOW: "\u26a0\ufe0f",
            Severity.MEDIUM: "\u26a0\ufe0f",
            Severity.HIGH: "\u274c",
            Severity.CRITICAL: "\U0001F6A8",
            Severity.WARNING: "\u26a0\ufe0f",
        }[self]

    @property
    def label(self) -> str:
        return {
            Severity.INFO: "INFO",
            Severity.LOW: "LOW",
            Severity.MEDIUM: "MEDIUM",
            Severity.HIGH: "HIGH",
            Severity.CRITICAL: "CRITICAL",
            Severity.WARNING: "WARNING",
        }[self]

    @property
    def rich_style(self) -> Style:
        return Style(color=self.color, bold=self.value >= 3)


def get_severity(score: float) -> Severity:
    if score >= 9.0:
        return Severity.CRITICAL
    elif score >= 7.0:
        return Severity.HIGH
    elif score >= 4.0:
        return Severity.MEDIUM
    elif score >= 1.0:
        return Severity.LOW
    return Severity.INFO
