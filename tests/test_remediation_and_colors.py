"""
Pruebas de remediation_mapping.py (sugerencias de solución basadas en
reglas, funcionan igual con o sin IA) y de los colores de severidad
corregidos (Crítica=rojo, Alta=naranja, Media=amarillo, Baja=verde,
Info=azul).
"""

from colorama import Fore

from shopiscan import remediation_mapping, utils


class TestRemediationMapping:
    def test_missing_header_has_remediation(self):
        rem = remediation_mapping.get_remediation("Falta el header de seguridad Referrer-Policy")
        assert rem is not None
        assert "Referrer-Policy" in rem

    def test_leaked_credential_has_remediation(self):
        rem = remediation_mapping.get_remediation("Posible credencial filtrada: Shopify Admin API access token")
        assert rem is not None
        assert "revoca" in rem.lower() or "regenera" in rem.lower()

    def test_outdated_library_has_remediation(self):
        rem = remediation_mapping.get_remediation("Librería desactualizada: jQuery 2.2.3")
        assert rem is not None
        assert "actualiza" in rem.lower()

    def test_insecure_cookies_has_remediation(self):
        rem = remediation_mapping.get_remediation("Cookies enviadas sin el flag Secure")
        assert rem is not None

    def test_exposed_env_has_remediation(self):
        rem = remediation_mapping.get_remediation("Archivo .env accesible públicamente")
        assert rem is not None
        assert "rota" in rem.lower()

    def test_unknown_title_returns_none(self):
        assert remediation_mapping.get_remediation("Un hallazgo inventado sin regla") is None


class TestEnrichFindingsWithRemediation:
    def test_adds_remediation_key_in_place(self):
        findings = [{"level": "Baja", "title": "Cookies enviadas sin el flag Secure"}]
        result = remediation_mapping.enrich_findings_with_remediation(findings)
        assert result is findings
        assert "remediation" in findings[0]

    def test_no_key_for_unmatched_findings(self):
        findings = [{"level": "Info", "title": "Un hallazgo inventado sin regla"}]
        remediation_mapping.enrich_findings_with_remediation(findings)
        assert "remediation" not in findings[0]


class TestSeverityColors:
    def test_critica_is_red(self):
        assert utils.severity_color("Crítica") == Fore.RED

    def test_alta_is_orange(self):
        assert utils.severity_color("Alta") == utils._ORANGE
        assert "208" in utils._ORANGE  # código ANSI 256 de naranja

    def test_media_is_yellow(self):
        assert utils.severity_color("Media") == Fore.YELLOW

    def test_baja_is_green(self):
        assert utils.severity_color("Baja") == Fore.GREEN

    def test_info_is_blue(self):
        assert utils.severity_color("Info") == Fore.BLUE
