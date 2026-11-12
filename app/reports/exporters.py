"""Экспорт отчётов в HTML, PDF, CSV и JSON."""

from __future__ import annotations

import csv
import io
import json
from typing import Any

from app.analysis.severity import SEVERITY_LABELS
from app.reports.builder import serialize
from app.templating import CATEGORY_LABELS, templates

CSV_COLUMNS = [
    ("severity", "Уровень"),
    ("asset", "Актив"),
    ("category", "Категория"),
    ("port", "Порт"),
    ("title", "Находка"),
    ("cve", "CVE"),
    ("cvss", "CVSS"),
    ("description", "Описание"),
    ("recommendation", "Рекомендация"),
    ("scan_id", "Скан"),
]


def to_json(report: dict[str, Any]) -> bytes:
    data = serialize({k: v for k, v in report.items() if k not in ("host", "target")})
    return json.dumps(data, ensure_ascii=False, indent=2, default=str).encode("utf-8")


def to_csv(report: dict[str, Any]) -> bytes:
    buf = io.StringIO()
    # BOM — чтобы Excel корректно открыл кириллицу
    buf.write("﻿")
    writer = csv.writer(buf, delimiter=";", quoting=csv.QUOTE_MINIMAL)
    writer.writerow([title for _, title in CSV_COLUMNS])
    for f in serialize(report.get("findings", [])):
        row = []
        for key, _ in CSV_COLUMNS:
            v = f.get(key)
            if key == "severity":
                v = SEVERITY_LABELS.get(v, v)
            elif key == "category":
                v = CATEGORY_LABELS.get(v, v)
            elif key == "port" and v:
                v = f"{v}/{f.get('protocol', '')}"
            row.append(_csv_safe("" if v is None else str(v)))
        writer.writerow(row)
    return buf.getvalue().encode("utf-8")


def _csv_safe(value: str) -> str:
    """Защита от CSV-инъекций формул при открытии в табличных редакторах."""
    if value and value[0] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + value
    return value


def to_html(report: dict[str, Any]) -> bytes:
    template = templates.env.get_template("reports/export.html")
    return template.render(report=report, r=report).encode("utf-8")


def _quiet_pdf_loggers() -> None:
    """WeasyPrint и fontTools очень многословны на уровнях DEBUG/INFO — оставляем только предупреждения.

    Уровень выставляется каждому логгеру семейства явно: часть из них получает
    собственный уровень при импорте, и настройка родителя на них не действует.
    """
    import logging

    for name in list(logging.root.manager.loggerDict):
        if name.split(".")[0] in ("fontTools", "weasyprint"):
            logging.getLogger(name).setLevel(logging.WARNING)
    for name in ("fontTools", "weasyprint"):
        logging.getLogger(name).setLevel(logging.WARNING)


def to_pdf(report: dict[str, Any]) -> bytes:
    try:
        from weasyprint import HTML
    except (ImportError, OSError) as exc:  # нет системных библиотек pango/cairo
        raise RuntimeError("Экспорт в PDF недоступен: не установлены библиотеки WeasyPrint") from exc
    _quiet_pdf_loggers()
    html = to_html(report).decode("utf-8")
    def _no_fetch(url: str, *args: Any, **kwargs: Any) -> dict:
        raise ValueError(f"Загрузка внешних ресурсов запрещена: {url}")

    return HTML(string=html, base_url=None, url_fetcher=_no_fetch).write_pdf()


EXPORTERS = {
    "json": (to_json, "application/json"),
    "csv": (to_csv, "text/csv; charset=utf-8"),
    "html": (to_html, "text/html; charset=utf-8"),
    "pdf": (to_pdf, "application/pdf"),
}
