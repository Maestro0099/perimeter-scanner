"""Уровни риска: подписи, порядок, перевод CVSS в уровень."""

from __future__ import annotations

SEVERITY_ORDER_LIST: list[str] = ["critical", "high", "medium", "low", "info"]
SEVERITY_RANK: dict[str, int] = {s: len(SEVERITY_ORDER_LIST) - i for i, s in enumerate(SEVERITY_ORDER_LIST)}
SEVERITY_LABELS: dict[str, str] = {
    "critical": "Критический",
    "high": "Высокий",
    "medium": "Средний",
    "low": "Низкий",
    "info": "Информационный",
}


def severity_from_cvss(cvss: float | None) -> str:
    if cvss is None:
        return "medium"
    if cvss >= 9.0:
        return "critical"
    if cvss >= 7.0:
        return "high"
    if cvss >= 4.0:
        return "medium"
    if cvss > 0.0:
        return "low"
    return "info"


def max_severity(values: list[str]) -> str:
    if not values:
        return "info"
    return max(values, key=lambda s: SEVERITY_RANK.get(s, 0))


def severity_at_least(value: str, threshold: str) -> bool:
    return SEVERITY_RANK.get(value, 0) >= SEVERITY_RANK.get(threshold, 0)
