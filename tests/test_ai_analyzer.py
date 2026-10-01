"""
Pruebas unitarias del módulo ai_analyzer (Ollama, IA local).

No se hace ninguna llamada real a Ollama: se testea la resolución de
configuración desde variables de entorno, el degradado con gracia cuando
Ollama no está disponible, y el flujo de generación con un cliente
simulado.
"""

import json
from unittest.mock import MagicMock, patch

from shopiscan.ai_analyzer import (
    AIAnalyzerError,
    _load_config,
    _friendly_error_message,
    _report_schema,
    generate_executive_report,
    get_embedding,
)


class TestLoadConfig:
    def test_defaults(self, monkeypatch):
        for var in ["OLLAMA_URL", "OLLAMA_CHAT_MODEL", "OLLAMA_EMBED_MODEL", "OLLAMA_FALLBACK_MODEL"]:
            monkeypatch.delenv(var, raising=False)
        config = _load_config()
        assert config.base_url == "http://127.0.0.1:11434"
        assert config.chat_model == "llama3.1"
        assert config.embed_model == "nomic-embed-text"
        assert config.model_chain() == ["llama3.1"]

    def test_env_overrides(self, monkeypatch):
        monkeypatch.setenv("OLLAMA_URL", "http://ollama:11434")
        monkeypatch.setenv("OLLAMA_CHAT_MODEL", "mistral")
        config = _load_config()
        assert config.base_url == "http://ollama:11434"
        assert config.chat_model == "mistral"

    def test_explicit_model_wins(self, monkeypatch):
        monkeypatch.setenv("OLLAMA_CHAT_MODEL", "mistral")
        config = _load_config(model="llama3.2")
        assert config.chat_model == "llama3.2"

    def test_fallback_chain(self, monkeypatch):
        monkeypatch.setenv("OLLAMA_CHAT_MODEL", "llama3.1")
        monkeypatch.setenv("OLLAMA_FALLBACK_MODEL", "llama3.2")
        config = _load_config()
        assert config.model_chain() == ["llama3.1", "llama3.2"]


class TestReportSchema:
    def test_schema_has_expected_keys(self):
        schema = _report_schema()
        props = schema.get("properties", {})
        assert "executive_summary" in props
        assert "overall_risk_level" in props
        assert "findings" in props
        assert "quick_wins" in props


class TestFriendlyErrorMessage:
    def test_connection_refused_message(self):
        cfg = _load_config()
        msg = _friendly_error_message(ConnectionRefusedError("Connection refused"), cfg, "llama3.1")
        assert "ollama serve" in msg.lower() or "ollama desktop" in msg.lower()

    def test_model_not_found_message(self):
        cfg = _load_config()
        msg = _friendly_error_message(Exception("model 'llama3.1' not found, try pulling it"), cfg, "llama3.1")
        assert "ollama pull" in msg


class TestGenerateExecutiveReport:
    def test_degrades_gracefully_when_ollama_unavailable(self):
        with patch(
            "shopiscan.ai_analyzer._get_client",
            side_effect=AIAnalyzerError("ollama no instalado"),
        ):
            result = generate_executive_report({"url": "https://tienda.com"})
        assert result is None

    def test_successful_report(self):
        fake_report = {
            "executive_summary": "ok",
            "overall_risk_level": "MEDIO",
            "findings": [],
            "quick_wins": [],
        }
        fake_client = MagicMock()
        fake_client.chat.return_value = {"message": {"content": json.dumps(fake_report)}}
        with patch("shopiscan.ai_analyzer._get_client", return_value=fake_client):
            report = generate_executive_report({"url": "https://tienda.com", "findings": []})
        assert report is not None
        assert report["overall_risk_level"] == "MEDIO"
        assert report["_model_used"] == "llama3.1"

    def test_similar_findings_included_in_prompt(self):
        fake_report = {"executive_summary": "ok", "overall_risk_level": "BAJO", "findings": [], "quick_wins": []}
        fake_client = MagicMock()
        fake_client.chat.return_value = {"message": {"content": json.dumps(fake_report)}}
        with patch("shopiscan.ai_analyzer._get_client", return_value=fake_client):
            generate_executive_report(
                {"url": "https://tienda.com", "findings": []},
                similar_findings=[{"title": "Falta CSP", "severity": "Alta", "similarity": 0.9}],
            )
        user_msg = fake_client.chat.call_args.kwargs["messages"][1]["content"]
        assert "0.9" in user_msg or "vectorial" in user_msg


class TestGetEmbedding:
    def test_returns_vector_via_current_embed_api(self):
        """API actual: client.embed(model=, input=) -> {"embeddings": [[...]]}"""
        fake_client = MagicMock()
        fake_client.embed.return_value = {"embeddings": [[0.1, 0.2, 0.3]]}
        with patch("shopiscan.ai_analyzer._get_client", return_value=fake_client):
            emb = get_embedding("texto")
        assert emb == [0.1, 0.2, 0.3]
        fake_client.embeddings.assert_not_called()  # no debería hacer falta el fallback

    def test_falls_back_to_legacy_embeddings_api(self):
        """Si client.embed() no existe (librería 'ollama' antigua) o falla,
        debe caer automáticamente a client.embeddings() (API legacy)."""
        fake_client = MagicMock()
        fake_client.embed.side_effect = AttributeError("no embed method")
        fake_client.embeddings.return_value = {"embedding": [0.4, 0.5, 0.6]}
        with patch("shopiscan.ai_analyzer._get_client", return_value=fake_client):
            emb = get_embedding("texto")
        assert emb == [0.4, 0.5, 0.6]

    def test_falls_back_when_embed_raises_other_exception(self):
        fake_client = MagicMock()
        fake_client.embed.side_effect = Exception("modelo no encontrado")
        fake_client.embeddings.return_value = {"embedding": [0.7, 0.8]}
        with patch("shopiscan.ai_analyzer._get_client", return_value=fake_client):
            emb = get_embedding("texto")
        assert emb == [0.7, 0.8]

    def test_returns_none_when_both_apis_fail(self):
        fake_client = MagicMock()
        fake_client.embed.side_effect = Exception("fallo 1")
        fake_client.embeddings.side_effect = Exception("fallo 2")
        with patch("shopiscan.ai_analyzer._get_client", return_value=fake_client):
            emb = get_embedding("texto")
        assert emb is None

    def test_returns_none_when_embed_returns_empty_list(self):
        fake_client = MagicMock()
        fake_client.embed.return_value = {"embeddings": []}
        fake_client.embeddings.return_value = {"embedding": None}
        with patch("shopiscan.ai_analyzer._get_client", return_value=fake_client):
            emb = get_embedding("texto")
        assert emb is None

    def test_returns_none_on_client_creation_error(self):
        with patch("shopiscan.ai_analyzer._get_client", side_effect=AIAnalyzerError("no disponible")):
            emb = get_embedding("texto")
        assert emb is None


class TestGetEmbeddingVerbose:
    """Regresión: cuando la indexación vectorial fallaba (p. ej. porque
    'nomic-embed-text' no se había descargado en el volumen de Ollama del
    contenedor Docker, aunque 'llama3.1' sí), el único rastro quedaba en
    los logs del servidor — invisible desde la interfaz web. Ahora el
    motivo real se puede propagar hasta la UI."""

    def test_success_returns_embedding_and_none_reason(self):
        from shopiscan.ai_analyzer import get_embedding_verbose

        fake_client = MagicMock()
        fake_client.embed.return_value = {"embeddings": [[0.1, 0.2]]}
        with patch("shopiscan.ai_analyzer._get_client", return_value=fake_client):
            emb, reason = get_embedding_verbose("texto")
        assert emb == [0.1, 0.2]
        assert reason is None

    def test_model_not_found_gives_actionable_docker_hint(self):
        from shopiscan.ai_analyzer import get_embedding_verbose

        fake_client = MagicMock()
        fake_client.embed.side_effect = Exception('model "nomic-embed-text" not found, try pulling it first')
        fake_client.embeddings.side_effect = Exception('model "nomic-embed-text" not found, try pulling it first')
        with patch("shopiscan.ai_analyzer._get_client", return_value=fake_client):
            emb, reason = get_embedding_verbose("texto")
        assert emb is None
        assert "docker exec shopiscan_ollama ollama pull" in reason
        assert "volumen distinto" in reason

    def test_generic_failure_returns_reason_without_docker_hint(self):
        from shopiscan.ai_analyzer import get_embedding_verbose

        fake_client = MagicMock()
        fake_client.embed.side_effect = Exception("connection refused")
        fake_client.embeddings.side_effect = Exception("connection refused")
        with patch("shopiscan.ai_analyzer._get_client", return_value=fake_client):
            emb, reason = get_embedding_verbose("texto")
        assert emb is None
        assert "connection refused" in reason
        assert "docker exec" not in reason


class TestAutoModelDiscovery:
    def test_falls_back_to_any_installed_model_when_configured_one_is_missing(self, monkeypatch):
        monkeypatch.setenv("OLLAMA_CHAT_MODEL", "llama3.1")
        monkeypatch.delenv("OLLAMA_FALLBACK_MODEL", raising=False)

        fake_report = {"executive_summary": "ok", "overall_risk_level": "BAJO", "findings": [], "quick_wins": []}

        def fake_chat(model, messages, format, options):
            if model == "llama3.1":
                raise Exception('model "llama3.1" not found, try pulling it first')
            return {"message": {"content": json.dumps(fake_report)}}

        fake_client = MagicMock()
        fake_client.chat.side_effect = fake_chat
        fake_client.list.return_value = {"models": [{"name": "mistral:latest"}, {"name": "nomic-embed-text:latest"}]}

        with patch("shopiscan.ai_analyzer._get_client", return_value=fake_client):
            from shopiscan.ai_analyzer import generate_executive_report
            report = generate_executive_report({"url": "https://tienda.com"})

        assert report is not None
        assert report["_model_used"] == "mistral:latest"

    def test_embedding_model_excluded_from_discovery(self):
        from shopiscan.ai_analyzer import _list_installed_chat_models

        fake_client = MagicMock()
        fake_client.list.return_value = {"models": [{"name": "nomic-embed-text:latest"}, {"name": "llama3.2:latest"}]}
        models = _list_installed_chat_models(fake_client, "nomic-embed-text")
        assert models == ["llama3.2:latest"]

    def test_discovery_never_raises_on_error(self):
        from shopiscan.ai_analyzer import _list_installed_chat_models

        fake_client = MagicMock()
        fake_client.list.side_effect = Exception("connection error")
        assert _list_installed_chat_models(fake_client, "nomic-embed-text") == []

    def test_does_not_discover_for_non_not_found_errors(self, monkeypatch):
        """Si el error no es de tipo 'modelo no encontrado' (p. ej. Ollama caído),
        no tiene sentido buscar otros modelos: no habría con qué conectar."""
        monkeypatch.setenv("OLLAMA_CHAT_MODEL", "llama3.1")
        monkeypatch.delenv("OLLAMA_FALLBACK_MODEL", raising=False)

        fake_client = MagicMock()
        fake_client.chat.side_effect = ConnectionRefusedError("Connection refused")

        with patch("shopiscan.ai_analyzer._get_client", return_value=fake_client):
            from shopiscan.ai_analyzer import generate_executive_report
            report = generate_executive_report({"url": "https://tienda.com"})

        assert report is None
        fake_client.list.assert_not_called()


class TestOllamaClientTimeout:
    """Regresión: 'Failed to connect to Ollama' con Ollama confirmado en
    marcha era, en realidad, un timeout demasiado corto (~5s, el valor
    por defecto de httpx) para cargar un modelo grande en memoria en la
    primera petición. El cliente ahora usa un timeout generoso."""

    def test_client_created_with_generous_default_timeout(self, monkeypatch):
        monkeypatch.delenv("OLLAMA_TIMEOUT_SECONDS", raising=False)
        import shopiscan.ai_analyzer as ai_analyzer

        fake_ollama = MagicMock()
        fake_module = MagicMock()
        fake_module.Client = fake_ollama

        with patch.dict("sys.modules", {"ollama": fake_module}):
            config = ai_analyzer._load_config()
            ai_analyzer._get_client(config)

        _, kwargs = fake_ollama.call_args
        assert kwargs["timeout"] == ai_analyzer.OLLAMA_CLIENT_TIMEOUT_SECONDS
        assert kwargs["timeout"] >= 60  # muy por encima del default de httpx (~5s)

    def test_timeout_configurable_via_env(self, monkeypatch):
        monkeypatch.setenv("OLLAMA_TIMEOUT_SECONDS", "600")
        import shopiscan.ai_analyzer as ai_analyzer

        fake_ollama = MagicMock()
        fake_module = MagicMock()
        fake_module.Client = fake_ollama

        with patch.dict("sys.modules", {"ollama": fake_module}):
            config = ai_analyzer._load_config()
            ai_analyzer._get_client(config)

        _, kwargs = fake_ollama.call_args
        assert kwargs["timeout"] == 600.0
