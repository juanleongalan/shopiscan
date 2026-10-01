"""
shadow_apps_scanner.py
------------------------
Detección heurística de "shadow apps": residuos de código que dejan atrás
las apps de Shopify después de desinstalarse.

Cuando una app se instala, normalmente inyecta en el tema: un `<script>`
que apunta a su CDN (activo mientras la app está instalada), y a menudo
también contenedores HTML (`<div id="...">`), comentarios marcadores
(`<!-- BEGIN app-name -->`) o bloques de CSS que quedan "horneados" en el
código del tema. Cuando el comerciante desinstala la app desde el Admin,
Shopify no siempre limpia estos residuos automáticamente si se insertaron
manualmente o vía Asset API en versiones antiguas del tema.

Heurística usada aquí: para cada app conocida, definimos:
  - `markers`: patrones de residuo (contenedores, comentarios, clases CSS)
    que sobreviven aunque la app esté desinstalada.
  - `active_indicators`: patrones que solo aparecen si la app sigue
    activamente cargando su script (p. ej. su dominio en un <script src>).

Si se encuentra un marcador de residuo PERO ningún indicador de actividad,
lo señalamos como posible "shadow app": código muerto que aumenta la
superficie de ataque (mantenimiento, XSS en scripts obsoletos referenciados
por id, confusión para futuros desarrolladores) sin aportar ningún valor.

IMPORTANTE: esto es una heurística, no una certeza. Un falso positivo es
posible si la app carga su script de forma diferida (lazy-loaded) tras
interacción del usuario, algo que un escaneo pasivo no puede capturar.
"""

from __future__ import annotations

import re

from . import utils

# name -> {markers: [...], active_indicators: [...], detail: str}
SHADOW_APP_SIGNATURES: dict[str, dict] = {
    "Loox (reseñas con fotos)": {
        "markers": [r'id=["\']loox[-_]', r'class=["\'][^"\']*\bloox\b'],
        "active_indicators": [r"loox\.io", r"loox\.app"],
        "detail": "Contenedores o clases CSS de Loox presentes en el HTML sin ningún script activo de loox.io/loox.app cargándose.",
    },
    "Judge.me (reseñas)": {
        "markers": [r'id=["\']judgeme[-_]', r'class=["\'][^"\']*\bjdgm\b'],
        "active_indicators": [r"judge\.me", r"judgeme\.com", r"judgemecdn"],
        "detail": "Contenedores/clases 'jdgm' de Judge.me presentes sin script activo de judge.me.",
    },
    "Yotpo (reseñas/UGC)": {
        "markers": [r'id=["\']yotpo[-_]', r'class=["\'][^"\']*\byotpo\b'],
        "active_indicators": [r"yotpo\.com"],
        "detail": "Contenedores/clases de Yotpo presentes sin script activo de yotpo.com.",
    },
    "Klaviyo (email marketing)": {
        "markers": [r'id=["\']klaviyo[-_]', r"klaviyoForms", r"_klOnsite"],
        "active_indicators": [r"klaviyo\.com", r"klaviyo\.push"],
        "detail": "Formularios o variables JS de Klaviyo presentes sin script activo de klaviyo.com.",
    },
    "ReCharge (suscripciones)": {
        "markers": [r'id=["\']recharge[-_]', r'class=["\'][^"\']*\brecharge\b'],
        "active_indicators": [r"rechargeapps\.com", r"rechargepayments\.com"],
        "detail": "Contenedores de ReCharge presentes sin script activo de rechargepayments.com.",
    },
    "Gorgias (chat/soporte)": {
        "markers": [r'id=["\']gorgias[-_]', r"GorgiasChat"],
        "active_indicators": [r"gorgias\.chat", r"gorgias\.com"],
        "detail": "Referencias a GorgiasChat presentes sin script activo de gorgias.chat.",
    },
    "Smile.io (fidelización/puntos)": {
        "markers": [r'id=["\']smile[-_]', r"sweet\.js", r"smile-ui"],
        "active_indicators": [r"smile\.io"],
        "detail": "Contenedores de Smile.io presentes sin script activo de smile.io.",
    },
    "PageFly / GemPages (page builders)": {
        "markers": [r'class=["\'][^"\']*\bpf-', r'id=["\']gp-'],
        "active_indicators": [r"pagefly", r"gempages"],
        "detail": "Marcado HTML de un page builder (PageFly/GemPages) presente sin sus scripts activos: puede indicar secciones huérfanas tras desinstalar el builder.",
    },
    "Stamped.io (reseñas/UGC)": {
        "markers": [r'id=["\']stamped[-_]', r'class=["\'][^"\']*\bstamped-'],
        "active_indicators": [r"stamped\.io"],
        "detail": "Contenedores 'stamped-' presentes sin script activo de stamped.io.",
    },
    "Trustpilot (reseñas)": {
        "markers": [r'class=["\'][^"\']*trustpilot-widget', r'id=["\']trustpilot[-_]'],
        "active_indicators": [r"trustpilot\.com"],
        "detail": "Widget de Trustpilot presente en el HTML sin script activo de trustpilot.com.",
    },
    "Rebuy (upsell/cross-sell)": {
        "markers": [r'id=["\']rebuy[-_]', r'class=["\'][^"\']*\brebuy-'],
        "active_indicators": [r"rebuyengine\.com"],
        "detail": "Contenedores 'rebuy-' presentes sin script activo de rebuyengine.com.",
    },
    "Zoorix (upsell/bundles)": {
        "markers": [r'id=["\']zoorix[-_]', r'class=["\'][^"\']*\bzoorix-'],
        "active_indicators": [r"zoorix\.com"],
        "detail": "Contenedores 'zoorix-' presentes sin script activo de zoorix.com.",
    },
    "Appstle (suscripciones)": {
        "markers": [r'id=["\']appstle[-_]', r'class=["\'][^"\']*\bappstle-'],
        "active_indicators": [r"appstle\.com"],
        "detail": "Contenedores 'appstle-' presentes sin script activo de appstle.com.",
    },
    "Doofinder (buscador)": {
        "markers": [r'id=["\']doofinder[-_]', r"df-search-box"],
        "active_indicators": [r"doofinder\.com"],
        "detail": "Marcado de búsqueda de Doofinder presente sin script activo de doofinder.com.",
    },
    "Tidio (chat)": {
        "markers": [r'id=["\']tidio[-_]', r"tidio-chat"],
        "active_indicators": [r"tidio\.co", r"tidiochat"],
        "detail": "Contenedores de chat de Tidio presentes sin script activo de tidio.co.",
    },
    "Hotjar (analítica de comportamiento)": {
        "markers": [r"_hjSettings", r"hotjar-", r"hj\(\s*['\"](trigger|event|identify|stateChange)"],
        "active_indicators": [r"hotjar\.com", r"hotjar\.io"],
        "detail": "Variables/marcado de Hotjar presentes sin script activo de hotjar.com.",
    },
    "Zendesk (soporte)": {
        "markers": [r'id=["\']zendesk[-_]', r"zEmbed", r"zE\(\s*['\"]webWidget"],
        "active_indicators": [r"zdassets\.com", r"zendesk\.com", r"zend-apps\.com"],
        "detail": "Marcado del widget de Zendesk presente sin script activo de zdassets.com/zendesk.com.",
    },
    "Intercom (chat/soporte)": {
        "markers": [r'id=["\']intercom[-_]', r"intercomSettings"],
        "active_indicators": [r"widget\.intercom\.io", r"intercom\.io"],
        "detail": "Marcado/variables de Intercom presentes sin script activo de widget.intercom.io.",
    },
    "Crisp Chat": {
        "markers": [r'id=["\']crisp[-_]', r"\$crisp\b"],
        "active_indicators": [r"client\.crisp\.chat"],
        "detail": "Marcado/variables de Crisp presentes sin script activo de client.crisp.chat.",
    },
    "Privy (pop-ups/email capture)": {
        "markers": [r'id=["\']privy[-_]', r'class=["\'][^"\']*\bprivy-'],
        "active_indicators": [r"privy\.com"],
        "detail": "Contenedores 'privy-' presentes sin script activo de privy.com.",
    },
    "Wheelio (ruleta de descuentos)": {
        "markers": [r'id=["\']wheelio[-_]', r"wheelio"],
        "active_indicators": [r"wheelio\.com", r"wheelio\.co"],
        "detail": "Marcado de Wheelio presente sin script activo de wheelio.com/.co.",
    },
    "Okendo (reseñas)": {
        "markers": [r'id=["\']okendo[-_]', r'class=["\'][^"\']*\bokeReviews'],
        "active_indicators": [r"okendo\.io"],
        "detail": "Contenedores 'okeReviews'/okendo- presentes sin script activo de okendo.io.",
    },
    "Attentive (SMS marketing)": {
        "markers": [r'id=["\']attentive[-_]', r"__attentive"],
        "active_indicators": [r"attentivemobile\.com"],
        "detail": "Variables/marcado de Attentive presentes sin script activo de attentivemobile.com.",
    },
    "Postscript (SMS marketing)": {
        "markers": [r'id=["\']postscript[-_]', r"postscript_sdk"],
        "active_indicators": [r"postscript\.io"],
        "detail": "Marcado/variables de Postscript presentes sin script activo de postscript.io.",
    },
    "AfterShip (tracking de envíos)": {
        "markers": [r'id=["\']aftership[-_]', r'class=["\'][^"\']*\baftership-'],
        "active_indicators": [r"aftership\.com"],
        "detail": "Contenedores 'aftership-' presentes sin script activo de aftership.com.",
    },
    "Bold Apps (upsell/suscripciones)": {
        "markers": [r'id=["\']bold[-_]', r'class=["\'][^"\']*\bbold-'],
        "active_indicators": [r"boldapps\.net", r"boldcommerce\.com"],
        "detail": "Contenedores 'bold-' presentes sin script activo de boldapps.net/boldcommerce.com.",
    },
}


def detect_shadow_apps(html: str) -> list[dict]:
    """Busca residuos de apps desinstaladas: marcadores de contenedor
    presentes en el HTML sin el indicador de actividad correspondiente.
    """
    utils.info("Buscando residuos de apps desinstaladas (shadow apps)...")
    findings = []

    for app_name, sig in SHADOW_APP_SIGNATURES.items():
        marker_hit = any(re.search(pattern, html, re.IGNORECASE) for pattern in sig["markers"])
        if not marker_hit:
            continue

        is_active = any(re.search(pattern, html, re.IGNORECASE) for pattern in sig["active_indicators"])
        if is_active:
            continue  # la app sigue activa: no es un residuo, es uso normal

        findings.append(
            {
                "app": app_name,
                "severity": "Baja",
                "detail": sig["detail"],
            }
        )
        utils.warning(f"Posible residuo de app desinstalada: {app_name}")

    if not findings:
        utils.success("No se detectaron residuos evidentes de apps desinstaladas.")

    return findings
