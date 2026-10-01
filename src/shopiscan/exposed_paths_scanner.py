"""
exposed_paths_scanner.py
--------------------------
Comprueba un conjunto reducido y deliberadamente conservador de rutas
públicas sensibles que, si responden 200 con contenido que REALMENTE
tiene la forma esperada (no cualquier página HTML), indican una mala
configuración grave de la infraestructura detrás del dominio.

No es específico de Shopify: aplica a cualquier sitio, y es
particularmente relevante para tiendas con dominio propio que tienen
infraestructura adicional delante de Shopify (proxies, apps headless,
despliegues de staging, repositorios desplegados directamente al
servidor web, etc.).

Son peticiones GET simples, equivalentes a lo que haría cualquier
visitante o buscador. No hay fuerza bruta ni enumeración agresiva.

Protección contra falsos positivos, en DOS capas:

1. **"Soft 404"**: algunos sitios devuelven HTTP 200 para CUALQUIER ruta
   (SPA que sirve siempre index.html, página de error personalizada sin
   el código HTTP correcto, o incluso ciertas configuraciones de Shopify
   que sirven la página de tema para rutas desconocidas). Antes de
   confiar en un 200, se comprueba primero una ruta aleatoria que casi
   seguro no existe; si esa ruta también da 200, se asume "soft 404" y
   se omite toda la categoría.
2. **Validación de forma del contenido**: aunque la ruta específica no
   sea "soft 404" general, un 200 en /.env o /.git/config NO es
   automáticamente una fuga — tiene que PARECER un archivo .env o un
   config de Git de verdad. Una página HTML corriente (con <html>,
   <!DOCTYPE>, <script>, etc.) nunca se considera una fuga, aunque
   responda 200 y tenga contenido largo. Esto evita falsos positivos
   cuando el servidor/CDN devuelve una página normal (p. ej. el tema de
   la tienda) para una ruta que en realidad no expone nada.
"""

from __future__ import annotations

import re
import uuid

from . import utils

# Marcadores que indican "esto es una página HTML normal, no un archivo
# de configuración crudo" — si aparecen, NUNCA se considera una fuga,
# sea cual sea el path solicitado.
_HTML_MARKERS = re.compile(r"<!doctype\s+html|<html[\s>]|<head[\s>]|<body[\s>]", re.IGNORECASE)

# path -> (severidad, título corto, explicación, validador_de_forma)
# El validador recibe el texto de la respuesta y devuelve True solo si
# el contenido tiene pinta real de ser ese archivo, no una página cualquiera.


def _looks_like_dotenv(text: str) -> bool:
    if _HTML_MARKERS.search(text):
        return False
    lines = [l.strip() for l in text.splitlines() if l.strip() and not l.strip().startswith("#")]
    if not lines:
        return False
    keyvalue_lines = sum(1 for l in lines if re.match(r"^[A-Za-z_][A-Za-z0-9_]*\s*=", l))
    # Al menos la mitad de las líneas no vacías deben tener pinta de KEY=VALUE,
    # o debe contener alguna palabra clave típica de secretos.
    if lines and keyvalue_lines / len(lines) >= 0.5:
        return True
    return bool(re.search(r"\b(SECRET|PASSWORD|API_KEY|DATABASE_URL|PRIVATE_KEY|AWS_|TOKEN)\b", text, re.IGNORECASE))


def _looks_like_git_config(text: str) -> bool:
    if _HTML_MARKERS.search(text):
        return False
    return bool(re.search(r"^\s*\[(core|remote|branch)\b", text, re.IGNORECASE | re.MULTILINE))


def _looks_like_git_head(text: str) -> bool:
    if _HTML_MARKERS.search(text):
        return False
    stripped = text.strip()
    return bool(re.match(r"^ref:\s*refs/", stripped, re.IGNORECASE) or re.match(r"^[0-9a-f]{40}$", stripped))


SENSITIVE_PATHS = {
    "/.env": (
        "Crítica",
        "Archivo .env accesible públicamente",
        "Un archivo .env accesible desde la web puede contener credenciales de "
        "base de datos, claves de API o secretos de aplicación en texto plano. "
        "El contenido recuperado tiene la forma de un archivo .env real "
        "(líneas KEY=VALOR o palabras clave de secretos), no una página genérica.",
        _looks_like_dotenv,
    ),
    "/.git/config": (
        "Alta",
        "Configuración de Git (.git/config) accesible públicamente",
        "Indica que el directorio .git del repositorio se desplegó junto con el "
        "sitio y es descargable. Con herramientas públicas se puede "
        "reconstruir el repositorio completo (historial de commits, y a veces "
        "credenciales que se borraron en un commit posterior pero siguen en el historial).",
        _looks_like_git_config,
    ),
    "/.git/HEAD": (
        "Alta",
        "Referencia de Git (.git/HEAD) accesible públicamente",
        "Mismo riesgo que .git/config: el directorio .git está expuesto "
        "públicamente y el repositorio podría reconstruirse por completo.",
        _looks_like_git_head,
    ),
}

# Ruta que casi con toda seguridad no existe, usada para detectar
# comportamiento "soft 404" (sitios que devuelven 200 para todo).
_PROBE_PATH_PREFIX = "/__shopiscan_probe_"


def scan_exposed_paths(base_url: str, get_func) -> list[dict]:
    """Busca rutas sensibles expuestas. `get_func(url) -> Response | None`
    se inyecta desde core.py (reutiliza el mismo helper de reintentos que
    el resto del escáner).
    """
    utils.info("Revisando rutas sensibles de infraestructura (.env, .git)...")

    probe_url = base_url.rstrip("/") + _PROBE_PATH_PREFIX + uuid.uuid4().hex[:12]
    probe_resp = get_func(probe_url)
    if probe_resp is not None and probe_resp.status_code == 200:
        utils.info(
            "El sitio devuelve HTTP 200 para rutas inexistentes ('soft 404'); "
            "se omite la comprobación de rutas sensibles para evitar falsos positivos."
        )
        return []

    findings = []
    for path, (severity, title, detail, looks_real) in SENSITIVE_PATHS.items():
        resp = get_func(base_url.rstrip("/") + path)
        if resp is None or resp.status_code != 200:
            continue
        if not resp.text or not looks_real(resp.text):
            continue
        findings.append(
            {
                "level": severity,
                "title": title,
                "detail": detail + f" (ruta: {path})",
            }
        )
        utils.error(f"¡Ruta sensible expuesta!: {path}")

    if not findings:
        utils.success("No se detectaron rutas sensibles de infraestructura expuestas.")

    return findings
