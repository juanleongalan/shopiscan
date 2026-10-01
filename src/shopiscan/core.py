"""
core.py
--------
Motor de escaneo pasivo/activo de ShopiScan.

IMPORTANTE (alcance ético y técnico):
Shopify es una plataforma SaaS cerrada: no se puede acceder al servidor,
la base de datos ni el núcleo de la aplicación. Todo lo que hacemos aquí
se basa en información PÚBLICA que cualquier visitante del sitio también
puede ver (HTML, headers HTTP, cookies, archivos como robots.txt o
endpoints públicos de la Storefront API). No se realiza fuerza bruta,
inyección ni ningún tipo de explotación activa.
"""

from __future__ import annotations

import json
import re
import time
from urllib.parse import urlsplit, urlunsplit
from dataclasses import dataclass, field
from typing import Optional

import requests
from bs4 import BeautifulSoup

from . import utils
from . import secrets_scanner
from . import libraries_scanner
from . import shadow_apps_scanner
from . import exposed_paths_scanner
from . import ssl_tls_scanner
from . import owasp_mapping
from . import remediation_mapping
from . import scoring

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 ShopiScan/2.0"
    )
}

SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
]

HIGH_IMPACT_HEADERS = {"Content-Security-Policy", "X-Frame-Options"}

REQUEST_TIMEOUT = 10

PUBLIC_API_ENDPOINTS = ["/products.json", "/collections.json", "/cart.js"]

PUBLIC_FILES = ["/sitemap.xml", "/robots.txt"]

APP_FINGERPRINTS: dict[str, list[str]] = {
    "Klaviyo": ["klaviyo.com", "klaviyo.push"],
    "Yotpo": ["yotpo.com"],
    "Judge.me": ["judge.me", "judgeme"],
    "Loox": ["loox.io", "loox.app"],
    "Stamped.io": ["stamped.io"],
    "Okendo": ["okendo.io"],
    "Fera Reviews": ["fera.ai"],
    "Trustpilot": ["trustpilot.com"],
    "Postscript": ["postscript.io"],
    "Attentive": ["attentivemobile.com"],
    "Omnisend": ["omnisend.com"],
    "ReCharge": ["rechargeapps.com", "rechargepayments.com"],
    "Bold Apps": ["boldapps.net", "boldcommerce.com"],
    "Rebuy": ["rebuyengine.com"],
    "Smile.io": ["smile.io"],
    "Rivo Loyalty": ["rivo.io"],
    "ReferralCandy": ["referralcandy.com"],
    "PageFly": ["pagefly.io"],
    "Shogun": ["getshogun.com"],
    "AfterShip": ["aftership.com"],
    "Gorgias": ["gorgias.chat", "gorgias.com", "9gtb.com"],
    "Tidio": ["tidio.co", "tidiochat"],
    "Intercom": ["widget.intercom.io"],
    "Crisp Chat": ["client.crisp.chat"],
    "Zendesk": ["zdassets.com", "zendesk.com", "zend-apps.com"],
    "Google Analytics / Tag Manager": ["google-analytics.com", "googletagmanager.com"],
    "Meta (Facebook) Pixel": ["connect.facebook.net", "fbq("],
    "TikTok Pixel": ["analytics.tiktok.com", "ttq.load"],
    "Pinterest Tag": ["pintrk("],
    "Hotjar": ["hotjar.com"],
    "Snapchat Pixel": ["sc-static.net/scevent"],
    "Shop Pay / Shop App": ["shop.app"],
    "Zoorix (Upsell/Bundles)": ["zoorix.com"],
    "Appstle (Subscriptions)": ["appstle.com"],
    "Doofinder (Búsqueda)": ["doofinder.com"],
    "Kueski Pay (BNPL)": ["kueskipay.com"],
    "Mailchimp": ["chimpstatic.com", "mailchimp.com", "mc.us", "list-manage.com"],
    "PepperFinance (BNPL)": ["pepperfinance.es", "pepper.money"],
    "EasyLockdown (restricción de acceso)": ["easylockdown"],
}

# Dominios operados por el propio Shopify (no son "apps de terceros" en el
# sentido de instalables/desinstalables desde el Admin), para no marcarlos
# como "scripts externos sin identificar" cuando en realidad son nativos
# de la plataforma (p. ej. Shop Pay / Shop App).
SHOPIFY_NATIVE_DOMAINS = {"shop.app", "shopifycloud.com", "shopifysvc.com"}

PASSWORD_PAGE_INDICATORS = [
    'name="password"',
    'id="password"',
    "opening soon",
    "this store will be back soon",
    "enter using password",
    "esta tienda estará disponible en breve",
]


@dataclass
class ScanResult:
    url: str
    is_shopify: bool = False
    detection_method: Optional[str] = None

    theme_name: Optional[str] = None
    theme_id: Optional[str] = None
    theme_role: Optional[str] = None
    theme_store_id: Optional[str] = None
    theme_schema_name: Optional[str] = None
    theme_version: Optional[str] = None

    apps_generic: list[str] = field(default_factory=list)
    known_services: list[str] = field(default_factory=list)

    missing_headers: list[str] = field(default_factory=list)
    present_headers: list[str] = field(default_factory=list)

    exposed_files: list[str] = field(default_factory=list)
    exposed_api_endpoints: list[str] = field(default_factory=list)

    password_protected: bool = False
    generator_meta: Optional[str] = None
    insecure_cookies: list[str] = field(default_factory=list)

    response_time_ms: Optional[int] = None
    findings: list[dict] = field(default_factory=list)

    leaked_secrets: list[dict] = field(default_factory=list)
    outdated_libraries: list[dict] = field(default_factory=list)
    shadow_apps: list[dict] = field(default_factory=list)
    exposed_paths: list[dict] = field(default_factory=list)
    tls_findings: list[dict] = field(default_factory=list)
    catalog: dict = field(default_factory=dict)
    risk: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "url": self.url,
            "is_shopify": self.is_shopify,
            "detection_method": self.detection_method,
            "theme": {
                "name": self.theme_name or "Desconocido",
                "id": self.theme_id,
                "role": self.theme_role,
                "theme_store_id": self.theme_store_id,
                "schema_name": self.theme_schema_name,
                "version": self.theme_version or "Desconocido",
            },
            "apps_generic": self.apps_generic,
            "known_services": self.known_services,
            "missing_headers": self.missing_headers,
            "present_headers": self.present_headers,
            "exposed_files": self.exposed_files,
            "exposed_api_endpoints": self.exposed_api_endpoints,
            "password_protected": self.password_protected,
            "generator_meta": self.generator_meta,
            "insecure_cookies": self.insecure_cookies,
            "leaked_secrets": [
                {k: v for k, v in s.items()} for s in self.leaked_secrets
            ],
            "outdated_libraries": self.outdated_libraries,
            "shadow_apps": self.shadow_apps,
            "exposed_paths": self.exposed_paths,
            "tls_findings": self.tls_findings,
            "catalog": self.catalog,
            "risk": self.risk,
            "findings": self.findings,
        }


def _get(url: str) -> requests.Response:
    start = time.time()
    response = requests.get(url, headers=HEADERS, timeout=REQUEST_TIMEOUT)
    response.raise_for_status()
    response.elapsed_ms = int((time.time() - start) * 1000)
    return response


def detect_shopify(url: str) -> tuple[bool, Optional[requests.Response], Optional[str]]:
    utils.info(f"Analizando objetivo: {url}")
    try:
        response = _get(url)
    except requests.exceptions.RequestException as exc:
        utils.error(f"Error de conexión: {exc}")
        return False, None, None

    if "X-ShopId" in response.headers or "X-Shopify-Stage" in response.headers:
        utils.success("¡Shopify detectado! (vía headers HTTP)")
        return True, response, "headers"

    if "cdn.shopify.com" in response.text:
        utils.success("¡Shopify detectado! (vía CDN en el HTML)")
        return True, response, "cdn_reference"

    if re.search(r"Shopify\.shop\s*=", response.text):
        utils.success("¡Shopify detectado! (vía variable global Shopify.shop)")
        return True, response, "js_global"

    utils.error("No parece ser un sitio Shopify.")
    return False, response, None


def _extract_balanced_json(text: str, start_idx: int) -> Optional[str]:
    if start_idx >= len(text) or text[start_idx] != "{":
        return None
    depth = 0
    for i in range(start_idx, len(text)):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                return text[start_idx : i + 1]
    return None


def extract_theme_object(html: str) -> Optional[dict]:
    idx = html.find("Shopify.theme")
    if idx == -1:
        return None
    brace_idx = html.find("{", idx)
    if brace_idx == -1:
        return None
    json_str = _extract_balanced_json(html, brace_idx)
    if not json_str:
        return None
    try:
        return json.loads(json_str)
    except json.JSONDecodeError:
        return None


def scan_theme(response: requests.Response) -> dict:
    utils.info("Escaneando tema...")
    html = response.text
    info: dict = {
        "name": None,
        "id": None,
        "role": None,
        "theme_store_id": None,
        "schema_name": None,
        "version": None,
    }

    theme_obj = extract_theme_object(html)
    if theme_obj:
        info["name"] = theme_obj.get("name")
        info["id"] = str(theme_obj.get("id")) if theme_obj.get("id") else None
        info["role"] = theme_obj.get("role")
        info["theme_store_id"] = (
            str(theme_obj.get("theme_store_id")) if theme_obj.get("theme_store_id") else None
        )
        info["schema_name"] = theme_obj.get("schema_name")

    if not info["id"]:
        match = re.search(r"/t/(\d+)/", html)
        if match:
            info["id"] = match.group(1)

    version_match = re.search(r'"theme_version"\s*:\s*"([^"]+)"', html)
    if version_match:
        info["version"] = version_match.group(1)

    if info["name"]:
        utils.success(f"Nombre del tema: {info['name']}" + (f" (rol: {info['role']})" if info["role"] else ""))
    elif info["id"]:
        utils.warning(f"No se pudo resolver el nombre del tema; solo se obtuvo el ID: {info['id']}")
    else:
        utils.warning("No se pudo identificar el tema automáticamente.")

    if info["version"]:
        utils.success(f"Versión del tema: {info['version']}")

    return info


def scan_apps(response: requests.Response) -> list[str]:
    utils.info("Buscando apps de terceros (rutas genéricas)...")
    soup = BeautifulSoup(response.text, "html.parser")

    response_url = getattr(response, "url", "") or ""
    own_domain = re.sub(r"^https?://", "", str(response_url)).split("/")[0]

    apps_found: set[str] = set()
    for script in soup.find_all("script", src=True):
        src = script["src"]
        match = re.search(r"/apps/([^/?\"]+)", src)
        if match:
            apps_found.add(match.group(1))
            continue
        domain_match = re.search(r"https?://([\w.-]+)/", src)
        if domain_match:
            domain = domain_match.group(1)
            is_shopify_native = "shopify" in domain or any(
                domain == d or domain.endswith("." + d) for d in SHOPIFY_NATIVE_DOMAINS
            )
            if not is_shopify_native and domain != own_domain:
                apps_found.add(domain)

    apps_list = sorted(apps_found)
    if apps_list:
        utils.success(f"Scripts externos sin identificar: {len(apps_list)}")
    return apps_list


def detect_known_services(html: str) -> list[str]:
    utils.info("Buscando huellas de apps/servicios conocidos...")
    html_lower = html.lower()
    found = []
    for name, patterns in APP_FINGERPRINTS.items():
        if any(p.lower() in html_lower for p in patterns):
            found.append(name)

    if found:
        utils.success(f"Servicios de terceros identificados: {len(found)} -> {', '.join(found)}")
    else:
        utils.warning("No se identificaron servicios de terceros conocidos.")
    return found


def scan_security_headers(response: requests.Response) -> tuple[list[str], list[str]]:
    utils.info("Auditando headers de seguridad...")
    present, missing = [], []
    for header in SECURITY_HEADERS:
        if header in response.headers:
            present.append(header)
            utils.success(f"Presente: {header}")
        else:
            missing.append(header)
            utils.warning(f"Falta: {header}")
    return present, missing


def _site_root(url: str) -> str:
    """Devuelve el origen (scheme://netloc) de una URL, sin path, query ni
    fragmento.

    Bug real corregido: si el usuario apunta ShopiScan a una subruta (p. ej.
    una página de producto o de política de envíos) o una URL con query
    string, las comprobaciones de rutas conocidas en la raíz del sitio
    (/sitemap.xml, /products.json, /.env...) deben hacerse SIEMPRE contra
    la raíz del dominio, nunca concatenando el path directamente sobre la
    URL original. Antes de este fix, una URL con query string como
    'https://tienda.com/?shpxid=abc' + '/sitemap.xml' generaba una petición
    mal formada que en la práctica acababa pidiendo la home (query string
    con basura), pero el código igualmente reportaba "Encontrado" solo por
    recibir un 200 — un falso positivo silencioso.
    """
    parts = urlsplit(url)
    return urlunsplit((parts.scheme, parts.netloc, "", "", ""))


def _get_with_retries(url: str, retries: int = 1) -> Optional[requests.Response]:
    """GET con un reintento breve ante fallos de red transitorios.

    Sin esto, un timeout puntual en /products.json podía marcar como
    'resuelto' en el histórico un hallazgo que en realidad seguía activo
    (falso negativo por flakiness de red, no por un cambio real en la tienda).
    """
    last_exc: Optional[Exception] = None
    for attempt in range(retries + 1):
        try:
            return requests.get(url, headers=HEADERS, timeout=REQUEST_TIMEOUT)
        except requests.exceptions.RequestException as exc:
            last_exc = exc
            if attempt < retries:
                time.sleep(0.5)
    if last_exc:
        utils.warning(f"No se pudo verificar {url} tras {retries + 1} intento(s): {last_exc}")
    return None


def scan_public_files(base_url: str) -> list[str]:
    utils.info("Revisando archivos públicos comunes...")
    found = []
    for path in PUBLIC_FILES:
        resp = _get_with_retries(base_url.rstrip("/") + path, retries=1)
        if resp is not None and resp.status_code == 200:
            found.append(path)
            utils.success(f"Encontrado: {path}")
    return found


def scan_public_api_endpoints(base_url: str) -> list[str]:
    utils.info("Revisando endpoints públicos de la Storefront API...")
    found = []
    for endpoint in PUBLIC_API_ENDPOINTS:
        resp = _get_with_retries(base_url.rstrip("/") + endpoint, retries=1)
        if resp is not None and resp.status_code == 200 and "json" in resp.headers.get("Content-Type", ""):
            found.append(endpoint)
            utils.success(f"Endpoint público accesible: {endpoint}")
    return found


def scan_catalog(base_url: str) -> dict:
    """Analiza /products.json para contar el catálogo y detectar si se
    expone el nivel de inventario (stock) de cada variante.

    Shopify, desde 2021, oculta 'inventory_quantity' en la API pública por
    defecto, pero algunas tiendas antiguas o mal configuradas siguen
    exponiéndolo. Es información útil para la competencia, no un riesgo
    de seguridad grave, pero vale la pena reportarlo.
    """
    utils.info("Analizando catálogo público (products.json)...")
    catalog_info: dict = {
        "accessible": False,
        "product_count_sample": 0,
        "inventory_exposed": False,
    }
    try:
        resp = _get_with_retries(
            base_url.rstrip("/") + "/products.json?limit=50", retries=1
        )
        if resp is None or resp.status_code != 200:
            return catalog_info
        data = resp.json()
        products = data.get("products", [])
        catalog_info["accessible"] = True
        catalog_info["product_count_sample"] = len(products)

        for product in products:
            for variant in product.get("variants", []):
                if "inventory_quantity" in variant and variant.get("inventory_quantity") is not None:
                    catalog_info["inventory_exposed"] = True
                    break
            if catalog_info["inventory_exposed"]:
                break

        if catalog_info["inventory_exposed"]:
            utils.warning("El stock (inventory_quantity) de los productos es público.")
        else:
            utils.success(f"Catálogo accesible ({catalog_info['product_count_sample']} productos en muestra), sin stock expuesto.")
    except (requests.exceptions.RequestException, ValueError):
        pass

    return catalog_info


def check_password_protection(response: requests.Response) -> bool:
    html_lower = response.text.lower()
    is_protected = any(indicator in html_lower for indicator in PASSWORD_PAGE_INDICATORS)
    if is_protected:
        utils.warning("La tienda parece estar protegida con contraseña (modo 'Coming soon').")
    return is_protected


def check_generator_meta(html: str) -> Optional[str]:
    match = re.search(
        r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)["\']', html, re.IGNORECASE
    )
    return match.group(1) if match else None


def check_cookies(response: requests.Response) -> list[str]:
    insecure = []
    try:
        for cookie in response.cookies:
            if not cookie.secure:
                insecure.append(cookie.name)
    except Exception:
        pass
    if insecure:
        utils.warning(f"Cookies sin flag Secure: {', '.join(insecure)}")
    return insecure


def _header_explanation(header: str) -> str:
    explanations = {
        "Content-Security-Policy": "Sin CSP, la tienda es más vulnerable a ataques XSS mediante scripts inyectados (propios o de apps comprometidas).",
        "X-Frame-Options": "Sin este header, la tienda puede ser embebida en un <iframe> malicioso (riesgo de clickjacking).",
        "Strict-Transport-Security": "Sin HSTS, un usuario podría ser degradado a HTTP y expuesto a ataques man-in-the-middle.",
        "X-Content-Type-Options": "Sin este header, el navegador puede 'adivinar' tipos MIME, lo que facilita ataques de sniffing.",
        "Referrer-Policy": "Sin esta política, la URL completa (con posibles datos sensibles en query params) puede filtrarse a sitios externos vía el header Referer.",
        "Permissions-Policy": "Sin esta política, no se restringe qué APIs del navegador (cámara, geolocalización, etc.) pueden usar scripts de terceros.",
    }
    return explanations.get(header, "Header de seguridad recomendado por buenas prácticas OWASP.")


def build_findings(result: ScanResult) -> list[dict]:
    findings: list[dict] = []

    for secret in result.leaked_secrets:
        findings.append(
            {
                "level": secret["severity"],
                "title": f"Posible credencial filtrada: {secret['type']}",
                "detail": f"{secret['explanation']} (valor enmascarado: {secret['masked_value']}, fuente: {secret['source']})",
            }
        )

    for lib in result.outdated_libraries:
        findings.append(
            {
                "level": lib["severity"],
                "title": f"Librería desactualizada: {lib['library']} {lib['version_detected']}",
                "detail": f"{lib['detail']} Referencia: {lib['cve']}.",
            }
        )

    for shadow in result.shadow_apps:
        findings.append(
            {
                "level": shadow["severity"],
                "title": f"Posible residuo de app desinstalada: {shadow['app']}",
                "detail": shadow["detail"],
            }
        )

    findings.extend(result.exposed_paths)
    findings.extend(result.tls_findings)

    if result.catalog.get("inventory_exposed"):
        findings.append(
            {
                "level": "Media",
                "title": "Niveles de stock (inventory_quantity) expuestos públicamente",
                "detail": (
                    "El endpoint /products.json devuelve la cantidad exacta de stock por variante. "
                    "Cualquiera (incluida la competencia) puede monitorizar el inventario en tiempo real."
                ),
            }
        )

    for header in result.missing_headers:
        severity = "Alta" if header in HIGH_IMPACT_HEADERS else "Baja"
        findings.append(
            {
                "level": severity,
                "title": f"Falta el header de seguridad {header}",
                "detail": _header_explanation(header),
            }
        )

    if result.insecure_cookies:
        hsts_present = "Strict-Transport-Security" in result.present_headers
        # Sin HSTS, un ataque de degradación SSL (SSL-stripping) que fuerce HTTP
        # es considerablemente más plausible, así que el riesgo real de que estas
        # cookies viajen en claro es mayor. Con HSTS activo (el caso habitual en
        # Shopify), el navegador se niega a hacer downgrade a HTTP una vez visitado
        # el sitio, por lo que el riesgo práctico baja de Media a Baja.
        severity = "Baja" if hsts_present else "Media"
        findings.append(
            {
                "level": severity,
                "title": "Cookies enviadas sin el flag Secure",
                "detail": (
                    f"Las cookies {', '.join(result.insecure_cookies)} pueden viajar en texto "
                    "plano si el navegador degrada la conexión a HTTP. Deberían marcarse Secure."
                    + (
                        " El sitio sí envía Strict-Transport-Security, lo que mitiga bastante "
                        "el riesgo práctico de degradación a HTTP tras la primera visita."
                        if hsts_present
                        else " Además, el sitio NO envía Strict-Transport-Security, lo que hace "
                        "más plausible un ataque de degradación SSL (SSL-stripping)."
                    )
                ),
            }
        )

    if result.exposed_api_endpoints:
        findings.append(
            {
                "level": "Baja",
                "title": "Endpoints públicos de la Storefront API accesibles",
                "detail": (
                    f"Se pudo acceder sin autenticación a: {', '.join(result.exposed_api_endpoints)}. "
                    "Esto es el comportamiento por defecto de Shopify (no es un fallo de configuración), "
                    "pero expone catálogo, precios e inventario a cualquiera, incluida la competencia "
                    "(scraping automatizado de precios)."
                ),
            }
        )

    if result.password_protected:
        findings.append(
            {
                "level": "Info",
                "title": "Tienda protegida con contraseña",
                "detail": (
                    "La tienda está en modo 'Coming soon'. Ten en cuenta que este escaneo se hizo "
                    "sobre la página de contraseña, no sobre el sitio real; los resultados de tema "
                    "y apps pueden ser incompletos."
                ),
            }
        )

    if result.generator_meta:
        findings.append(
            {
                "level": "Baja",
                "title": "Meta tag 'generator' expone la plataforma",
                "detail": f"Valor detectado: '{result.generator_meta}'. Es información menor pero facilita el reconocimiento a un atacante.",
            }
        )

    if not result.known_services and not result.apps_generic:
        findings.append(
            {
                "level": "Info",
                "title": "No se detectaron apps de terceros",
                "detail": "Puede que la tienda use pocas apps, o que las cargue de forma diferida (lazy-loaded) tras interacción del usuario, lo cual este escaneo pasivo no captura.",
            }
        )

    return findings


def run_scan(url: str, fetch_scripts: bool = True) -> ScanResult:
    if not url.startswith("http"):
        url = "https://" + url

    result = ScanResult(url=url)

    is_shopify, response, method = detect_shopify(url)
    result.is_shopify = is_shopify
    result.detection_method = method

    if not is_shopify or response is None:
        return result

    result.response_time_ms = getattr(response, "elapsed_ms", None)

    theme_info = scan_theme(response)
    result.theme_name = theme_info["name"]
    result.theme_id = theme_info["id"]
    result.theme_role = theme_info["role"]
    result.theme_store_id = theme_info["theme_store_id"]
    result.theme_schema_name = theme_info["schema_name"]
    result.theme_version = theme_info["version"]

    result.apps_generic = scan_apps(response)
    result.known_services = detect_known_services(response.text)
    result.present_headers, result.missing_headers = scan_security_headers(response)
    site_root = _site_root(url)
    result.exposed_files = scan_public_files(site_root)
    result.exposed_api_endpoints = scan_public_api_endpoints(site_root)
    result.password_protected = check_password_protection(response)
    result.generator_meta = check_generator_meta(response.text)
    result.insecure_cookies = check_cookies(response)
    result.catalog = scan_catalog(site_root)
    result.leaked_secrets = secrets_scanner.scan_for_leaked_secrets(
        response.text, url, fetch_scripts=fetch_scripts
    )
    result.outdated_libraries = libraries_scanner.detect_outdated_libraries(response.text)
    result.shadow_apps = shadow_apps_scanner.detect_shadow_apps(response.text)
    result.exposed_paths = exposed_paths_scanner.scan_exposed_paths(
        site_root, lambda u: _get_with_retries(u, retries=1)
    )
    result.tls_findings = ssl_tls_scanner.check_ssl(urlsplit(site_root).hostname)

    result.findings = build_findings(result)
    owasp_mapping.enrich_findings_with_owasp(result.findings)
    remediation_mapping.enrich_findings_with_remediation(result.findings)
    result.risk = scoring.compute_risk_score(result.findings)

    return result
