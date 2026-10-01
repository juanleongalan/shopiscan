"""
Pruebas de la política de severidad revisada en core.py, basada en el
análisis de más de 30 escaneos reales (ver CHANGELOG / README):

  - Cookies sin Secure: severidad depende de si HSTS está presente.
  - Endpoints públicos de la Storefront API: Info -> Baja.
  - shop.app (Shop Pay / Shop App) ya no cuenta como "script sin
    identificar": es un dominio nativo de Shopify.
"""

from shopiscan import core


class TestCookieSeverityPolicy:
    def test_media_when_hsts_missing(self):
        result = core.ScanResult(
            url="https://tienda.com",
            insecure_cookies=["localization"],
            present_headers=[],
        )
        findings = core.build_findings(result)
        finding = next(f for f in findings if "Cookies enviadas" in f["title"])
        assert finding["level"] == "Media"

    def test_baja_when_hsts_present(self):
        result = core.ScanResult(
            url="https://tienda.com",
            insecure_cookies=["localization"],
            present_headers=["Strict-Transport-Security"],
        )
        findings = core.build_findings(result)
        finding = next(f for f in findings if "Cookies enviadas" in f["title"])
        assert finding["level"] == "Baja"


class TestStorefrontApiSeverityPolicy:
    def test_exposed_endpoints_are_baja_not_info(self):
        result = core.ScanResult(
            url="https://tienda.com",
            exposed_api_endpoints=["/products.json"],
        )
        findings = core.build_findings(result)
        finding = next(f for f in findings if "Storefront API" in f["title"])
        assert finding["level"] == "Baja"


class TestShopAppFingerprint:
    def test_shop_app_recognized_as_known_service(self):
        html = '<script src="https://shop.app/pay-widget.js"></script>'
        services = core.detect_known_services(html)
        assert "Shop Pay / Shop App" in services

    def test_shop_app_not_counted_as_generic_unidentified_script(self):
        from unittest.mock import MagicMock

        html = '<script src="https://shop.app/pay-widget.js"></script>'
        response = MagicMock()
        response.text = html
        response.url = "https://tienda-ejemplo.com/"
        apps = core.scan_apps(response)
        assert "shop.app" not in apps
