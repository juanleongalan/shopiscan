"""
history.py
------------
Comparación histórica entre escaneos de la misma tienda.

Cada vez que se completa un escaneo, guardamos una "instantánea" compacta
(score de riesgo, etiqueta, títulos de los hallazgos, contadores clave) en
un archivo JSONL local, uno por tienda (identificada por su dominio). En
la siguiente ejecución sobre la misma tienda, comparamos el escaneo actual
contra la última instantánea guardada para mostrar la evolución: si el
riesgo subió o bajó, qué hallazgos son nuevos y cuáles se resolvieron.

El histórico se guarda en el directorio home del usuario
(`~/.shopiscan/history/`), NO dentro del repositorio del proyecto, para
evitar mezclar datos de escaneos (que pueden incluir información sobre
terceros) con el control de versiones del código.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from . import utils

HISTORY_DIR = Path.home() / ".shopiscan" / "history"


def _history_file(slug: str) -> Path:
    HISTORY_DIR.mkdir(parents=True, exist_ok=True)
    return HISTORY_DIR / f"{slug}.jsonl"


def _snapshot_from_result(result_dict: dict) -> dict:
    findings = result_dict.get("findings", []) or []
    risk = result_dict.get("risk", {}) or {}
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "url": result_dict.get("url"),
        "score": risk.get("score", 0),
        "label": risk.get("label", "BAJO"),
        "finding_titles": sorted({f.get("title", "") for f in findings if f.get("title")}),
        "leaked_secrets_count": len(result_dict.get("leaked_secrets", []) or []),
        "outdated_libraries_count": len(result_dict.get("outdated_libraries", []) or []),
        "shadow_apps_count": len(result_dict.get("shadow_apps", []) or []),
        "missing_headers": sorted(result_dict.get("missing_headers", []) or []),
    }


def load_previous_snapshot(slug: str) -> Optional[dict]:
    """Devuelve la última instantánea guardada para esta tienda, o None si
    es la primera vez que se escanea (o el histórico no es legible)."""
    path = _history_file(slug)
    if not path.exists():
        return None
    try:
        last_line = None
        with path.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    last_line = line
        if last_line is None:
            return None
        return json.loads(last_line)
    except (OSError, json.JSONDecodeError):
        return None


def save_snapshot(slug: str, result_dict: dict) -> None:
    """Añade la instantánea del escaneo actual al histórico de esta tienda."""
    path = _history_file(slug)
    snapshot = _snapshot_from_result(result_dict)
    try:
        with path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(snapshot, ensure_ascii=False) + "\n")
    except OSError as exc:
        utils.warning(f"No se pudo guardar el histórico de escaneos: {exc}")


@dataclass
class ComparisonResult:
    previous_date: str
    previous_score: int
    current_score: int
    score_delta: int
    previous_label: str
    current_label: str
    new_findings: list[str] = field(default_factory=list)
    resolved_findings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "previous_date": self.previous_date,
            "previous_score": self.previous_score,
            "current_score": self.current_score,
            "score_delta": self.score_delta,
            "previous_label": self.previous_label,
            "current_label": self.current_label,
            "new_findings": self.new_findings,
            "resolved_findings": self.resolved_findings,
        }


def compare(previous: dict, current_result_dict: dict) -> ComparisonResult:
    """Compara la instantánea anterior contra el resultado del escaneo actual."""
    current = _snapshot_from_result(current_result_dict)
    previous_titles = set(previous.get("finding_titles", []))
    current_titles = set(current.get("finding_titles", []))

    return ComparisonResult(
        previous_date=previous.get("timestamp", "desconocida"),
        previous_score=previous.get("score", 0),
        current_score=current.get("score", 0),
        score_delta=current.get("score", 0) - previous.get("score", 0),
        previous_label=previous.get("label", "BAJO"),
        current_label=current.get("label", "BAJO"),
        new_findings=sorted(current_titles - previous_titles),
        resolved_findings=sorted(previous_titles - current_titles),
    )


def print_comparison(comparison: ComparisonResult) -> None:
    from colorama import Fore, Style

    utils.section("Comparación con el escaneo anterior")
    print(f"Escaneo anterior: {comparison.previous_date}")

    delta = comparison.score_delta
    if delta > 0:
        trend = f"{Fore.RED}▲ +{delta} (empeoró){Style.RESET_ALL}"
    elif delta < 0:
        trend = f"{Fore.GREEN}▼ {delta} (mejoró){Style.RESET_ALL}"
    else:
        trend = f"{Fore.YELLOW}= sin cambios{Style.RESET_ALL}"
    print(
        f"Score: {comparison.previous_score}/100 ({comparison.previous_label}) "
        f"→ {comparison.current_score}/100 ({comparison.current_label})  {trend}"
    )

    if comparison.new_findings:
        print(f"\n{Fore.RED}Hallazgos nuevos desde el último escaneo:{Style.RESET_ALL}")
        for title in comparison.new_findings:
            print(f"  + {title}")

    if comparison.resolved_findings:
        print(f"\n{Fore.GREEN}Hallazgos resueltos desde el último escaneo:{Style.RESET_ALL}")
        for title in comparison.resolved_findings:
            print(f"  - {title}")

    if not comparison.new_findings and not comparison.resolved_findings:
        utils.info("Sin cambios en los hallazgos respecto al escaneo anterior.")
