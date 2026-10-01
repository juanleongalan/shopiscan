"""
utils.py
---------
Funciones auxiliares de presentación: banner, colores y helpers de impresión.
Mantener esta capa separada de la lógica de escaneo facilita las pruebas
unitarias (no queremos testear "colores en pantalla").
"""

from __future__ import annotations

from colorama import Fore, Style, init

# Inicializa colorama (necesario en Windows para que los códigos ANSI funcionen)
init(autoreset=True)

BANNER = r"""
   _____ _ _               _____                          _   _      _
  / ____(_) |             / ____|                        | \ | |    | |
 | |     _| |__   ___ _ _| (___   ___  ___ _   _ _ __ ___|  \| | ___| |_
 | |    | | '_ \ / _ \ '__\___ \ / _ \/ __| | | | '__/ _ \ . ` |/ _ \ __|
 | |____| | |_) |  __/ |  ____) |  __/ (__| |_| | | |  __/ |\  |  __/ |_
  \_____|_|_.__/ \___|_| |_____/ \___|\___|\__,_|_|  \___|_| \_|\___|\__|

           Auditoria de seguridad para tiendas Shopify + IA local (Ollama)
"""

DISCLAIMER = (
    "AVISO LEGAL: Esta herramienta es exclusivamente para fines educativos y\n"
    "auditorías de seguridad autorizadas. El usuario es responsable de obtener\n"
    "permiso explícito antes de escanear cualquier sitio web que no le\n"
    "pertenezca. Los autores no se hacen responsables del mal uso de este\n"
    "software. Escanear sistemas sin autorización puede ser ILEGAL en tu país."
)


def print_banner() -> None:
    """Imprime el banner ASCII y el disclaimer legal al iniciar la herramienta."""
    print(Fore.CYAN + BANNER + Style.RESET_ALL)
    print(Fore.YELLOW + DISCLAIMER + Style.RESET_ALL)
    print()


def info(msg: str) -> None:
    print(f"[*] {msg}")


def success(msg: str) -> None:
    print(Fore.GREEN + f"[+] {msg}" + Style.RESET_ALL)


def warning(msg: str) -> None:
    print(Fore.YELLOW + f"[!] {msg}" + Style.RESET_ALL)


def error(msg: str) -> None:
    print(Fore.RED + f"[-] {msg}" + Style.RESET_ALL)


def section(title: str) -> None:
    print()
    print(Fore.CYAN + Style.BRIGHT + f"=== {title} ===" + Style.RESET_ALL)


# Naranja no existe en la paleta básica de colorama; se usa el código
# ANSI de 256 colores (208 = naranja). colorama sigue gestionando el
# RESET_ALL con normalidad para volver al color por defecto después.
_ORANGE = "\033[38;5;208m"


def severity_color(severity: str) -> str:
    """Devuelve el color asociado a un nivel de severidad:
    Crítica=rojo, Alta=naranja, Media=amarillo, Baja=verde, Info=azul."""
    mapping = {
        "CRÍTICA": Fore.RED,
        "CRITICA": Fore.RED,
        "ALTA": _ORANGE,
        "MEDIA": Fore.YELLOW,
        "BAJA": Fore.GREEN,
        "INFO": Fore.BLUE,
    }
    return mapping.get(severity.upper(), Fore.WHITE)


def print_findings(findings: list[dict]) -> None:
    """Imprime la lista de hallazgos rule-based (sin IA) con severidad,
    categoría OWASP, detalle y remediación sugerida (cuando aplica)."""
    if not findings:
        return
    section("ALERTAS DEL ESCANEO")
    order = {"CRÍTICA": 0, "CRITICA": 0, "ALTA": 1, "MEDIA": 2, "BAJA": 3, "INFO": 4}
    sorted_findings = sorted(findings, key=lambda f: order.get(f.get("level", "INFO").upper(), 5))
    for finding in sorted_findings:
        level = finding.get("level", "Info")
        color = severity_color(level)
        owasp = finding.get("owasp_category")
        owasp_tag = f" {Fore.CYAN}[{owasp}]{Style.RESET_ALL}" if owasp else ""
        print(f"\n{color}[{level.upper()}] {finding.get('title', '')}{Style.RESET_ALL}{owasp_tag}")
        detail = finding.get("detail")
        if detail:
            print(f"  > {detail}")
        remediation = finding.get("remediation")
        if remediation:
            print(f"  > {Fore.CYAN}Solución sugerida:{Style.RESET_ALL} {remediation}")
