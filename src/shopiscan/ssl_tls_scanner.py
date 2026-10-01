"""
ssl_tls_scanner.py
--------------------
Verifica la expiración del certificado TLS y la versión de TLS negociada
con el servidor. Es una comprobación 100% pasiva: abre una única conexión
TLS estándar de lectura (el mismo handshake que hace cualquier navegador
al visitar el sitio), sin enviar ningún payload ni intentar downgrade.

Aporta una dimensión que ShopiScan no cubría hasta ahora: todo el resto
del escáner analiza el HTML/headers ya servidos por HTTPS, pero no la
salud del propio certificado/protocolo TLS subyacente.
"""

from __future__ import annotations

import socket
import ssl
from datetime import datetime, timezone

from . import utils

CONNECT_TIMEOUT = 10
CERT_EXPIRY_WARNING_DAYS = 15

# Versiones de TLS consideradas obsoletas/inseguras por navegadores modernos.
OBSOLETE_TLS_VERSIONS = {"TLSv1", "TLSv1.1", "SSLv3", "SSLv2"}


def check_ssl(hostname: str, port: int = 443) -> list[dict]:
    """Devuelve una lista de findings (mismo formato que build_findings())
    sobre el estado del certificado TLS y la versión de protocolo
    negociada. Nunca lanza excepción: cualquier fallo de conexión se
    traduce en un finding informativo, no en un error que tumbe el escaneo.
    """
    utils.info("Verificando certificado TLS y versión de protocolo...")
    findings: list[dict] = []
    context = ssl.create_default_context()

    try:
        with socket.create_connection((hostname, port), timeout=CONNECT_TIMEOUT) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as tls_sock:
                cert = tls_sock.getpeercert()
                tls_version = tls_sock.version()

        findings.extend(_check_cert_expiry(cert))
        findings.extend(_check_tls_version(tls_version))

        if not findings:
            utils.success(f"Certificado TLS válido, protocolo {tls_version}.")

    except ssl.SSLCertVerificationError as exc:
        utils.error(f"Certificado TLS inválido: {exc}")
        findings.append(
            {
                "level": "Alta",
                "title": "Certificado TLS inválido",
                "detail": (
                    f"Falló la verificación del certificado ({exc}). Los navegadores "
                    "mostrarán una advertencia de seguridad a los visitantes, lo que "
                    "daña gravemente la confianza y puede bloquear ventas."
                ),
            }
        )
    except (socket.timeout, socket.gaierror, ConnectionRefusedError, OSError) as exc:
        utils.warning(f"No se pudo establecer conexión TLS en el puerto {port}: {exc}")
        # No es necesariamente un problema de seguridad (puede ser un firewall,
        # un timeout puntual...), así que se registra como informativo, no como alerta.

    return findings


def _check_cert_expiry(cert: dict) -> list[dict]:
    not_after_raw = cert.get("notAfter")
    if not not_after_raw:
        return []

    try:
        not_after = datetime.strptime(not_after_raw, "%b %d %H:%M:%S %Y %Z")
        not_after = not_after.replace(tzinfo=timezone.utc)
    except ValueError:
        return []

    days_left = (not_after - datetime.now(timezone.utc)).days

    if days_left < 0:
        utils.error(f"¡Certificado TLS expirado hace {abs(days_left)} día(s)!")
        return [
            {
                "level": "Crítica",
                "title": "Certificado TLS expirado",
                "detail": (
                    f"El certificado expiró hace {abs(days_left)} día(s) ({not_after_raw}). "
                    "Los navegadores bloquean el acceso al sitio con una advertencia de "
                    "seguridad a pantalla completa: esto detiene las ventas por completo "
                    "hasta que se renueve."
                ),
            }
        ]
    if days_left < CERT_EXPIRY_WARNING_DAYS:
        utils.warning(f"Certificado TLS próximo a expirar en {days_left} día(s).")
        return [
            {
                "level": "Media",
                "title": "Certificado TLS próximo a expirar",
                "detail": (
                    f"El certificado expira en {days_left} día(s) ({not_after_raw}). "
                    "Conviene confirmar que la renovación automática (la mayoría de "
                    "certificados de Shopify se renuevan solos) esté funcionando."
                ),
            }
        ]
    return []


def _check_tls_version(tls_version: str | None) -> list[dict]:
    if tls_version in OBSOLETE_TLS_VERSIONS:
        utils.warning(f"Versión de TLS obsoleta negociada: {tls_version}")
        return [
            {
                "level": "Alta",
                "title": f"Versión de TLS obsoleta ({tls_version})",
                "detail": (
                    f"El servidor negoció {tls_version}, una versión de TLS considerada "
                    "insegura y deprecada por los navegadores modernos. Los visitantes con "
                    "navegadores actualizados podrían no poder conectar, y el tráfico es "
                    "más vulnerable a ataques criptográficos conocidos contra ese protocolo."
                ),
            }
        ]
    return []
