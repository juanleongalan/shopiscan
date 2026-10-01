"""
Pruebas de _load_dotenv_if_available(): debe cargar el .env con
normalidad y, si hay líneas mal formadas, mostrar UN aviso claro de
ShopiScan en vez de los mensajes crudos de python-dotenv por cada línea.
"""

import os

import shopiscan


class TestLoadDotenv:
    def test_loads_valid_env_file(self, tmp_path, monkeypatch):
        env_file = tmp_path / ".env"
        env_file.write_text("OLLAMA_URL=http://example:1234\n")
        monkeypatch.chdir(tmp_path)
        monkeypatch.delenv("OLLAMA_URL", raising=False)

        result = shopiscan._load_dotenv_if_available()

        assert result is True
        assert os.environ.get("OLLAMA_URL") == "http://example:1234"
        monkeypatch.delenv("OLLAMA_URL", raising=False)

    def test_malformed_lines_do_not_prevent_loading_the_rest(self, tmp_path, monkeypatch):
        env_file = tmp_path / ".env"
        env_file.write_text(
            "# comentario\n"
            "   ollama pull llama3.1\n"
            "   ollama pull nomic-embed-text\n"
            "OLLAMA_CHAT_MODEL=llama3.2\n"
        )
        monkeypatch.chdir(tmp_path)
        monkeypatch.delenv("OLLAMA_CHAT_MODEL", raising=False)

        result = shopiscan._load_dotenv_if_available()

        assert result is True
        assert os.environ.get("OLLAMA_CHAT_MODEL") == "llama3.2"
        monkeypatch.delenv("OLLAMA_CHAT_MODEL", raising=False)

    def test_returns_false_when_no_env_file_found(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        result = shopiscan._load_dotenv_if_available()
        assert result is False
