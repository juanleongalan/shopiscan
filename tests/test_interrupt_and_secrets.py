"""
Pruebas del prompt de interrupción por Ctrl+C y de la severidad revisada
de credenciales filtradas (Google API key / Mailchimp: Media -> Alta).
"""

from unittest.mock import patch

from shopiscan import secrets_scanner
from shopiscan import _prompt_continue_after_interrupt


class TestPromptContinueAfterInterrupt:
    def test_continue_on_s(self):
        with patch("builtins.input", return_value="s"):
            assert _prompt_continue_after_interrupt("contexto de prueba") is True

    def test_continue_on_yes_variants(self):
        for answer in ["si", "sí", "y", "yes", "S"]:
            with patch("builtins.input", return_value=answer):
                assert _prompt_continue_after_interrupt("ctx") is True

    def test_stop_on_n(self):
        with patch("builtins.input", return_value="n"):
            assert _prompt_continue_after_interrupt("contexto de prueba") is False

    def test_stop_on_empty_answer(self):
        with patch("builtins.input", return_value=""):
            assert _prompt_continue_after_interrupt("contexto de prueba") is False

    def test_stop_on_second_ctrl_c(self):
        with patch("builtins.input", side_effect=KeyboardInterrupt):
            assert _prompt_continue_after_interrupt("contexto de prueba") is False


class TestLeakedCredentialSeverity:
    def test_google_api_key_is_alta(self):
        html = "const key = 'AIzaSyABCDEFGHIJKLMNOPQRSTUVWXYZ1234567';"
        findings = secrets_scanner._scan_text_for_secrets(html, source="test")
        finding = next(f for f in findings if f["type"] == "Google API key")
        assert finding["severity"] == "Alta"

    def test_mailchimp_key_is_alta(self):
        html = "MC_KEY=abcdef0123456789abcdef0123456789-us12"
        findings = secrets_scanner._scan_text_for_secrets(html, source="test")
        finding = next(f for f in findings if f["type"] == "Mailchimp API key")
        assert finding["severity"] == "Alta"

    def test_shopify_admin_token_still_critica(self):
        html = 'var token = "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";'
        findings = secrets_scanner._scan_text_for_secrets(html, source="test")
        finding = next(f for f in findings if f["type"] == "Shopify Admin API access token")
        assert finding["severity"] == "Crítica"
