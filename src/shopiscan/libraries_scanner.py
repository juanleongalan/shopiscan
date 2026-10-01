"""
libraries_scanner.py
----------------------
Detecta librerías JavaScript de terceros cargadas por el tema/apps y las
compara contra un umbral de versión conocido como vulnerable.

Fuente de las vulnerabilidades: avisos públicos y de dominio general sobre
estas librerías (jQuery, jQuery UI, Bootstrap, Lodash, Moment.js, AngularJS).
No son vulnerabilidades de Shopify en sí, sino de librerías genéricas que
muchos temas siguen incluyendo sin actualizar.

NOTA ACADÉMICA: los números de CVE y umbrales de versión aquí incluidos
deben tratarse como punto de partida, no como fuente definitiva. Antes de
citarlos en un informe formal, verifica la versión exacta y el CVE en
https://nvd.nist.gov o https://github.com/advisories.
"""

from __future__ import annotations

import re
from typing import Optional

from . import utils

Version = tuple[int, int, int]


def _parse_version(raw: str) -> Optional[Version]:
    parts = raw.split(".")
    try:
        nums = [int(re.sub(r"[^\d]", "", p) or 0) for p in parts[:3]]
        while len(nums) < 3:
            nums.append(0)
        return tuple(nums)  # type: ignore[return-value]
    except ValueError:
        return None


# name -> (regex para extraer versión del src/contenido, versión mínima segura, CVE(s), descripción)
LIBRARY_SIGNATURES: dict[str, dict] = {
    "jQuery": {
        "pattern": r"jquery[.-]?(\d+\.\d+\.\d+)(?:\.min)?\.js",
        "safe_from": (3, 5, 0),
        "cve": "CVE-2020-11022, CVE-2020-11023",
        "detail": "Versiones de jQuery anteriores a 3.5.0 son vulnerables a XSS a través de jQuery.htmlPrefilter() con HTML no confiable.",
    },
    "jQuery UI": {
        "pattern": r"jquery-ui[.-]?(\d+\.\d+\.\d+)(?:\.min)?\.js",
        "safe_from": (1, 13, 2),
        "cve": "CVE-2021-41182, CVE-2021-41183, CVE-2021-41184",
        "detail": "Versiones de jQuery UI anteriores a 1.13.2 tienen múltiples XSS en los widgets Datepicker y Dialog.",
    },
    "Bootstrap": {
        "pattern": r"bootstrap[.-]?(\d+\.\d+\.\d+)(?:\.min)?\.(?:js|css)",
        "safe_from": (4, 3, 1),
        "cve": "CVE-2019-8331, CVE-2018-14040",
        "detail": "Versiones de Bootstrap anteriores a 4.3.1 tienen XSS en los componentes tooltip/popover/toast a través de la opción 'data-template'.",
    },
    "Lodash": {
        "pattern": r"lodash[.-]?(\d+\.\d+\.\d+)(?:\.min)?\.js",
        "safe_from": (4, 17, 21),
        "cve": "CVE-2020-8203, CVE-2021-23337",
        "detail": "Versiones de Lodash anteriores a 4.17.21 son vulnerables a contaminación de prototipos (prototype pollution) e inyección de comandos.",
    },
    "Moment.js": {
        "pattern": r"moment[.-]?(\d+\.\d+\.\d+)(?:\.min)?\.js",
        "safe_from": (2, 29, 4),
        "cve": "CVE-2022-24785",
        "detail": "Versiones de Moment.js anteriores a 2.29.4 son vulnerables a ReDoS (Regular Expression Denial of Service) al parsear ciertas cadenas de fecha.",
    },
    "AngularJS": {
        "pattern": r"angular[.-]?(\d+\.\d+\.\d+)(?:\.min)?\.js",
        "safe_from": None,  # AngularJS (1.x) llegó a EOL en enero de 2022: TODA versión se considera obsoleta
        "cve": "EOL / sin soporte oficial",
        "detail": "AngularJS (1.x, distinto de Angular 2+) alcanzó el fin de vida en enero de 2022. Ya no recibe parches de seguridad, independientemente de la versión.",
    },
}


def detect_outdated_libraries(html: str) -> list[dict]:
    """Busca librerías conocidas en el HTML y compara su versión contra el umbral seguro."""
    utils.info("Buscando librerías JS desactualizadas...")
    findings = []

    for lib_name, sig in LIBRARY_SIGNATURES.items():
        match = re.search(sig["pattern"], html, re.IGNORECASE)
        if not match:
            continue

        version_str = match.group(1)
        version = _parse_version(version_str)
        safe_from = sig["safe_from"]

        is_vulnerable = safe_from is not None and version is not None and version < safe_from
        is_eol = safe_from is None  # ej. AngularJS: toda versión se marca

        if is_vulnerable or is_eol:
            findings.append(
                {
                    "library": lib_name,
                    "version_detected": version_str,
                    "cve": sig["cve"],
                    "detail": sig["detail"],
                    "severity": "Alta" if is_vulnerable else "Media",
                }
            )
            utils.warning(f"{lib_name} {version_str} desactualizado/vulnerable ({sig['cve']})")

    if not findings:
        utils.success("No se detectaron librerías JS con versiones conocidas como vulnerables.")

    return findings
