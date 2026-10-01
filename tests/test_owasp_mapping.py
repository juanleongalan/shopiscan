"""
Pruebas del módulo owasp_mapping (clasificación OWASP Top 10 2021).

Es 100% basado en reglas: debe funcionar exactamente igual con o sin IA.
"""

from shopiscan import owasp_mapping, scoring


class TestClassify:
    def test_missing_header_is_a05(self):
        cat = owasp_mapping.classify("Falta el header de seguridad Referrer-Policy")
        assert cat == owasp_mapping.OWASP_TOP10_2021["A05"]

    def test_insecure_cookies_is_a02(self):
        cat = owasp_mapping.classify("Cookies enviadas sin el flag Secure")
        assert cat == owasp_mapping.OWASP_TOP10_2021["A02"]

    def test_exposed_storefront_api_is_a01(self):
        cat = owasp_mapping.classify("Endpoints públicos de la Storefront API accesibles")
        assert cat == owasp_mapping.OWASP_TOP10_2021["A01"]

    def test_exposed_env_file_is_a01(self):
        cat = owasp_mapping.classify("Archivo .env accesible públicamente")
        assert cat == owasp_mapping.OWASP_TOP10_2021["A01"]

    def test_outdated_library_is_a06(self):
        cat = owasp_mapping.classify("Librería desactualizada: jQuery 2.2.3")
        assert cat == owasp_mapping.OWASP_TOP10_2021["A06"]

    def test_leaked_credential_is_a07(self):
        cat = owasp_mapping.classify("Posible credencial filtrada: Shopify Admin API access token")
        assert cat == owasp_mapping.OWASP_TOP10_2021["A07"]

    def test_tls_issue_is_a02(self):
        assert owasp_mapping.classify("Certificado TLS expirado") == owasp_mapping.OWASP_TOP10_2021["A02"]
        assert owasp_mapping.classify("Versión de TLS obsoleta (TLSv1)") == owasp_mapping.OWASP_TOP10_2021["A02"]

    def test_shadow_app_is_a05(self):
        cat = owasp_mapping.classify("Posible residuo de app desinstalada: Zendesk (soporte)")
        assert cat == owasp_mapping.OWASP_TOP10_2021["A05"]

    def test_purely_informational_findings_have_no_category(self):
        assert owasp_mapping.classify("Tienda protegida con contraseña") is None
        assert owasp_mapping.classify("No se detectaron apps de terceros") is None
        assert owasp_mapping.classify("Script recurrente sin clasificar: cdn.example.com") is None

    def test_unknown_title_has_no_category(self):
        assert owasp_mapping.classify("Un hallazgo totalmente inventado que no existe") is None


class TestEnrichFindings:
    def test_adds_owasp_category_key_in_place(self):
        findings = [{"level": "Baja", "title": "Cookies enviadas sin el flag Secure"}]
        result = owasp_mapping.enrich_findings_with_owasp(findings)
        assert result is findings  # misma lista, modificada in-place
        assert findings[0]["owasp_category"] == owasp_mapping.OWASP_TOP10_2021["A02"]

    def test_no_key_added_for_informational_findings(self):
        findings = [{"level": "Info", "title": "No se detectaron apps de terceros"}]
        owasp_mapping.enrich_findings_with_owasp(findings)
        assert "owasp_category" not in findings[0]


class TestOwaspBreakdown:
    def test_counts_by_category(self):
        findings = [
            {"title": "Falta el header de seguridad Referrer-Policy"},
            {"title": "Falta el header de seguridad Permissions-Policy"},
            {"title": "Cookies enviadas sin el flag Secure"},
        ]
        owasp_mapping.enrich_findings_with_owasp(findings)
        breakdown = owasp_mapping.owasp_breakdown(findings)
        assert breakdown[owasp_mapping.OWASP_TOP10_2021["A05"]] == 2
        assert breakdown[owasp_mapping.OWASP_TOP10_2021["A02"]] == 1

    def test_empty_for_no_findings(self):
        assert owasp_mapping.owasp_breakdown([]) == {}


class TestScoringIncludesOwaspBreakdown:
    def test_compute_risk_score_includes_owasp_breakdown(self):
        findings = [{"level": "Baja", "title": "Cookies enviadas sin el flag Secure"}]
        owasp_mapping.enrich_findings_with_owasp(findings)
        risk = scoring.compute_risk_score(findings)
        assert "owasp_breakdown" in risk
        assert risk["owasp_breakdown"][owasp_mapping.OWASP_TOP10_2021["A02"]] == 1
