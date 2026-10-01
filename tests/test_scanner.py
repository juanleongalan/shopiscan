"""
Pruebas unitarias de ShopiScan.

Usamos mocks para NO hacer peticiones de red reales durante los tests:
esto los hace rápidos, deterministas y evita escanear sitios de terceros
como efecto secundario de correr `pytest`.
"""

from unittest.mock import MagicMock, patch

import pytest

from shopiscan import core, secrets_scanner, libraries_scanner, scoring


def _fake_response(
    text: str, headers: dict, status_code: int = 200, url: str = "https://tienda-ejemplo.com/", cookies=None
) -> MagicMock:
    resp = MagicMock()
    resp.text = text
    resp.headers = headers
    resp.status_code = status_code
    resp.raise_for_status = MagicMock()
    resp.elapsed_ms = 100
    resp.url = url
    resp.cookies = cookies or []
    return resp


class TestDetectShopify:
    @patch("shopiscan.core._get")
    def test_detects_via_header(self, mock_get):
        mock_get.return_value = _fake_response("<html></html>", {"X-ShopId": "12345"})
        is_shopify, response, method = core.detect_shopify("https://tienda-ejemplo.com")
        assert is_shopify is True
        assert method == "headers"

    @patch("shopiscan.core._get")
    def test_detects_via_cdn(self, mock_get):
        html = '<script src="https://cdn.shopify.com/s/files/1/foo.js"></script>'
        mock_get.return_value = _fake_response(html, {})
        is_shopify, response, method = core.detect_shopify("https://tienda-ejemplo.com")
        assert is_shopify is True
        assert method == "cdn_reference"

    @patch("shopiscan.core._get")
    def test_rejects_non_shopify(self, mock_get):
        mock_get.return_value = _fake_response("<html>Sitio normal</html>", {})
        is_shopify, response, method = core.detect_shopify("https://sitio-normal.com")
        assert is_shopify is False
        assert method is None


class TestScanTheme:
    def test_extracts_theme_object(self):
        html = (
            '<script>var Shopify = Shopify || {}; '
            'Shopify.theme = {"name":"Dawn","id":123456789,"theme_store_id":887,'
            '"role":"main","schema_name":"Dawn","schema_version":"15.0.0"};</script>'
        )
        response = _fake_response(html, {})
        info = core.scan_theme(response)
        assert info["name"] == "Dawn"
        assert info["id"] == "123456789"
        assert info["role"] == "main"
        assert info["theme_store_id"] == "887"

    def test_fallback_to_asset_path_id(self):
        html = '<link href="/t/987654321/assets/theme.css">'
        response = _fake_response(html, {})
        info = core.scan_theme(response)
        assert info["id"] == "987654321"
        assert info["name"] is None

    def test_handles_missing_theme_info(self):
        response = _fake_response("<html>sin info de tema</html>", {})
        info = core.scan_theme(response)
        assert info["id"] is None
        assert info["name"] is None


class TestExtractBalancedJson:
    def test_extracts_nested_braces(self):
        text = 'prefix {"a": {"b": 1}, "c": 2} suffix'
        start = text.find("{")
        result = core._extract_balanced_json(text, start)
        assert result == '{"a": {"b": 1}, "c": 2}'


class TestScanApps:
    def test_detects_app_paths(self):
        html = (
            '<script src="https://tienda.com/apps/reviews-app/widget.js"></script>'
            '<script src="https://tienda.com/apps/upsell/bundle.js"></script>'
        )
        response = _fake_response(html, {})
        apps = core.scan_apps(response)
        assert "reviews-app" in apps
        assert "upsell" in apps

    def test_no_apps_found(self):
        response = _fake_response("<html></html>", {})
        apps = core.scan_apps(response)
        assert apps == []

    def test_own_domain_not_flagged_as_app(self):
        html = '<script src="https://tienda-ejemplo.com/assets/theme.js"></script>'
        response = _fake_response(html, {}, url="https://tienda-ejemplo.com/")
        apps = core.scan_apps(response)
        assert "tienda-ejemplo.com" not in apps


class TestDetectKnownServices:
    def test_detects_klaviyo_and_ga(self):
        html = '<script src="https://static.klaviyo.com/onsite/js/klaviyo.js"></script><script src="https://www.googletagmanager.com/gtm.js"></script>'
        services = core.detect_known_services(html)
        assert "Klaviyo" in services
        assert "Google Analytics / Tag Manager" in services

    def test_detects_service_inside_html_comment(self):
        html = "<!-- Judge.me widget start --> <div id='jdgm'></div>"
        services = core.detect_known_services(html)
        assert "Judge.me" in services

    def test_no_false_positives_on_plain_html(self):
        html = "<html><body><h1>Tienda sin apps</h1></body></html>"
        services = core.detect_known_services(html)
        assert services == []


class TestScanSecurityHeaders:
    def test_reports_present_and_missing(self):
        response = _fake_response("<html></html>", {"Strict-Transport-Security": "max-age=100"})
        present, missing = core.scan_security_headers(response)
        assert "Strict-Transport-Security" in present
        assert "Content-Security-Policy" in missing


class TestPasswordProtection:
    def test_detects_password_page(self):
        response = _fake_response('<form><input name="password"></form>', {})
        assert core.check_password_protection(response) is True

    def test_normal_page_not_flagged(self):
        response = _fake_response("<html>Bienvenido a la tienda</html>", {})
        assert core.check_password_protection(response) is False


class TestGeneratorMeta:
    def test_extracts_generator(self):
        html = '<meta name="generator" content="Shopify">'
        assert core.check_generator_meta(html) == "Shopify"

    def test_returns_none_if_absent(self):
        assert core.check_generator_meta("<html></html>") is None


class TestCookies:
    def test_flags_insecure_cookies(self):
        fake_cookie = MagicMock()
        fake_cookie.name = "session_id"
        fake_cookie.secure = False
        response = _fake_response("<html></html>", {}, cookies=[fake_cookie])
        insecure = core.check_cookies(response)
        assert "session_id" in insecure

    def test_no_insecure_cookies(self):
        fake_cookie = MagicMock()
        fake_cookie.name = "session_id"
        fake_cookie.secure = True
        response = _fake_response("<html></html>", {}, cookies=[fake_cookie])
        insecure = core.check_cookies(response)
        assert insecure == []


class TestBuildFindings:
    def test_high_impact_header_gets_alta_severity(self):
        result = core.ScanResult(url="https://tienda.com", missing_headers=["Content-Security-Policy"])
        findings = core.build_findings(result)
        csp_finding = next(f for f in findings if "Content-Security-Policy" in f["title"])
        assert csp_finding["level"] == "Alta"

    def test_low_impact_header_gets_baja_severity(self):
        result = core.ScanResult(url="https://tienda.com", missing_headers=["Referrer-Policy"])
        findings = core.build_findings(result)
        rp_finding = next(f for f in findings if "Referrer-Policy" in f["title"])
        assert rp_finding["level"] == "Baja"

    def test_no_apps_generates_info_finding(self):
        result = core.ScanResult(url="https://tienda.com")
        findings = core.build_findings(result)
        titles = [f["title"] for f in findings]
        assert any("No se detectaron apps" in t for t in titles)


class TestSecretsScanner:
    def test_detects_shopify_admin_token(self):
        html = '<script>var token = "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";</script>'
        findings = secrets_scanner._scan_text_for_secrets(html, source="test")
        assert any(f["type"] == "Shopify Admin API access token" for f in findings)

    def test_masks_the_secret_value(self):
        html = 'AKIAABCDEFGHIJKLMNOP'
        findings = secrets_scanner._scan_text_for_secrets(html, source="test")
        aws_finding = next(f for f in findings if f["type"] == "AWS Access Key ID")
        assert "AKIA" not in aws_finding["masked_value"] or "*" in aws_finding["masked_value"]
        assert "*" in aws_finding["masked_value"]

    def test_clean_html_has_no_findings(self):
        html = "<html><body>Bienvenido a la tienda, sin secretos aquí.</body></html>"
        findings = secrets_scanner._scan_text_for_secrets(html, source="test")
        assert findings == []

    @patch("shopiscan.secrets_scanner.requests.get")
    def test_scan_for_leaked_secrets_includes_scripts(self, mock_get):
        html = '<script src="https://tienda.com/assets/app.js"></script>'
        script_resp = MagicMock()
        script_resp.status_code = 200
        script_resp.text = 'const key = "sk_live_abcdefghijklmnopqrstuvwx";'
        mock_get.return_value = script_resp

        findings = secrets_scanner.scan_for_leaked_secrets(html, "https://tienda.com/", fetch_scripts=True)
        assert any(f["type"] == "Stripe live secret key" for f in findings)


class TestLibrariesScanner:
    def test_detects_outdated_jquery(self):
        html = '<script src="/assets/jquery-1.9.1.min.js"></script>'
        findings = libraries_scanner.detect_outdated_libraries(html)
        jquery_finding = next(f for f in findings if f["library"] == "jQuery")
        assert jquery_finding["severity"] == "Alta"

    def test_modern_jquery_not_flagged(self):
        html = '<script src="/assets/jquery-3.7.1.min.js"></script>'
        findings = libraries_scanner.detect_outdated_libraries(html)
        assert not any(f["library"] == "jQuery" for f in findings)

    def test_angularjs_always_flagged_eol(self):
        html = '<script src="/assets/angular-1.8.3.min.js"></script>'
        findings = libraries_scanner.detect_outdated_libraries(html)
        assert any(f["library"] == "AngularJS" for f in findings)

    def test_no_libraries_detected_on_clean_html(self):
        html = "<html><body>Sin librerías legacy</body></html>"
        findings = libraries_scanner.detect_outdated_libraries(html)
        assert findings == []


class TestScoring:
    def test_no_findings_gives_zero_score(self):
        result = scoring.compute_risk_score([])
        assert result["score"] == 0
        assert result["label"] == "BAJO"

    def test_critical_finding_pushes_score_up(self):
        findings = [{"level": "Crítica"}]
        result = scoring.compute_risk_score(findings)
        assert result["score"] == 30
        assert result["label"] == "MEDIO"

    def test_score_caps_at_100(self):
        findings = [{"level": "Crítica"} for _ in range(10)]
        result = scoring.compute_risk_score(findings)
        assert result["score"] == 100
        assert result["label"] == "CRÍTICO"

    def test_multiple_severities_breakdown(self):
        findings = [{"level": "Alta"}, {"level": "Alta"}, {"level": "Baja"}]
        result = scoring.compute_risk_score(findings)
        assert result["breakdown"]["ALTA"] == 2
        assert result["breakdown"]["BAJA"] == 1


class TestScanResult:
    def test_to_dict_defaults(self):
        result = core.ScanResult(url="https://tienda.com")
        data = result.to_dict()
        assert data["url"] == "https://tienda.com"
        assert data["theme"]["name"] == "Desconocido"
        assert data["known_services"] == []


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
