"""
Pruebas unitarias del módulo history (comparación entre escaneos).

Usamos monkeypatch para redirigir HISTORY_DIR a un directorio temporal:
no se escribe nada en el ~/.shopiscan real del usuario que ejecute los tests.
"""

from shopiscan import history


def _fake_result(score: int, label: str, titles: list[str]) -> dict:
    return {
        "url": "https://tienda-ejemplo.com",
        "risk": {"score": score, "label": label},
        "findings": [{"title": t} for t in titles],
        "leaked_secrets": [],
        "outdated_libraries": [],
        "shadow_apps": [],
        "missing_headers": [],
    }


class TestHistory:
    def test_no_previous_snapshot_returns_none(self, tmp_path, monkeypatch):
        monkeypatch.setattr(history, "HISTORY_DIR", tmp_path)
        assert history.load_previous_snapshot("tienda-nueva.com") is None

    def test_save_and_load_snapshot_roundtrip(self, tmp_path, monkeypatch):
        monkeypatch.setattr(history, "HISTORY_DIR", tmp_path)
        result = _fake_result(30, "MEDIO", ["Falta CSP"])
        history.save_snapshot("tienda.com", result)

        loaded = history.load_previous_snapshot("tienda.com")
        assert loaded is not None
        assert loaded["score"] == 30
        assert loaded["label"] == "MEDIO"
        assert "Falta CSP" in loaded["finding_titles"]

    def test_load_returns_latest_of_multiple_snapshots(self, tmp_path, monkeypatch):
        monkeypatch.setattr(history, "HISTORY_DIR", tmp_path)
        history.save_snapshot("tienda.com", _fake_result(50, "ALTO", ["A"]))
        history.save_snapshot("tienda.com", _fake_result(10, "BAJO", ["B"]))

        loaded = history.load_previous_snapshot("tienda.com")
        assert loaded["score"] == 10
        assert loaded["label"] == "BAJO"

    def test_compare_detects_score_improvement(self, tmp_path, monkeypatch):
        monkeypatch.setattr(history, "HISTORY_DIR", tmp_path)
        previous = history._snapshot_from_result(_fake_result(50, "ALTO", ["A", "B"]))
        current = _fake_result(20, "MEDIO", ["A"])

        comparison = history.compare(previous, current)
        assert comparison.score_delta == -30
        assert comparison.resolved_findings == ["B"]
        assert comparison.new_findings == []

    def test_compare_detects_new_findings(self, tmp_path, monkeypatch):
        monkeypatch.setattr(history, "HISTORY_DIR", tmp_path)
        previous = history._snapshot_from_result(_fake_result(10, "BAJO", ["A"]))
        current = _fake_result(40, "MEDIO", ["A", "C"])

        comparison = history.compare(previous, current)
        assert comparison.score_delta == 30
        assert comparison.new_findings == ["C"]
        assert comparison.resolved_findings == []
