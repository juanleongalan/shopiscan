"""
Pruebas del módulo local_vuln_db (base de datos local incremental).

Usamos monkeypatch para redirigir DB_PATH a un archivo temporal: no se
escribe nada en el ~/.shopiscan real del usuario que ejecute los tests.
"""

from shopiscan import local_vuln_db


def _fake_result(theme_name, score, apps_generic=None, findings=None, url="https://tienda.com"):
    return {
        "url": url,
        "theme": {"name": theme_name},
        "risk": {"score": score, "label": "BAJO"},
        "apps_generic": apps_generic or [],
        "findings": findings or [],
    }


class TestRecordAndStats:
    def test_records_theme_stats(self, tmp_path, monkeypatch):
        monkeypatch.setattr(local_vuln_db, "DB_PATH", tmp_path / "db.sqlite3")
        local_vuln_db.record_scan(_fake_result("Dawn", 20))
        stats = local_vuln_db.get_stats_summary()
        assert stats["themes_tracked"] == 1

    def test_unknown_theme_not_tracked(self, tmp_path, monkeypatch):
        monkeypatch.setattr(local_vuln_db, "DB_PATH", tmp_path / "db.sqlite3")
        local_vuln_db.record_scan(_fake_result("Desconocido", 20))
        stats = local_vuln_db.get_stats_summary()
        assert stats["themes_tracked"] == 0

    def test_records_finding_frequency(self, tmp_path, monkeypatch):
        monkeypatch.setattr(local_vuln_db, "DB_PATH", tmp_path / "db.sqlite3")
        findings = [{"title": "Falta CSP", "level": "Alta"}]
        local_vuln_db.record_scan(_fake_result("Dawn", 20, findings=findings))
        local_vuln_db.record_scan(_fake_result("Dawn", 20, findings=findings, url="https://otra.com"))
        stats = local_vuln_db.get_stats_summary()
        assert stats["findings_tracked"] == 1
        assert stats["top_findings"][0]["times_seen"] == 2


class TestEnrichTheme:
    def test_no_enrichment_below_min_observations(self, tmp_path, monkeypatch):
        monkeypatch.setattr(local_vuln_db, "DB_PATH", tmp_path / "db.sqlite3")
        local_vuln_db.record_scan(_fake_result("RiskyTheme", 90))
        extra = local_vuln_db.enrich_findings({"theme": {"name": "RiskyTheme"}, "apps_generic": []})
        assert extra == []  # solo 1 observación: no es suficiente

    def test_enrichment_after_min_observations_with_high_avg_score(self, tmp_path, monkeypatch):
        monkeypatch.setattr(local_vuln_db, "DB_PATH", tmp_path / "db.sqlite3")
        local_vuln_db.record_scan(_fake_result("RiskyTheme", 90, url="https://a.com"))
        local_vuln_db.record_scan(_fake_result("RiskyTheme", 90, url="https://b.com"))
        extra = local_vuln_db.enrich_findings({"theme": {"name": "RiskyTheme"}, "apps_generic": []})
        assert any("historial local de riesgo elevado" in f["title"] for f in extra)

    def test_no_enrichment_for_low_avg_score_theme(self, tmp_path, monkeypatch):
        monkeypatch.setattr(local_vuln_db, "DB_PATH", tmp_path / "db.sqlite3")
        local_vuln_db.record_scan(_fake_result("SafeTheme", 5, url="https://a.com"))
        local_vuln_db.record_scan(_fake_result("SafeTheme", 5, url="https://b.com"))
        extra = local_vuln_db.enrich_findings({"theme": {"name": "SafeTheme"}, "apps_generic": []})
        assert extra == []


class TestEnrichScripts:
    def test_recurring_script_flagged_after_threshold(self, tmp_path, monkeypatch):
        monkeypatch.setattr(local_vuln_db, "DB_PATH", tmp_path / "db.sqlite3")
        for i in range(local_vuln_db.RECURRING_SCRIPT_THRESHOLD):
            local_vuln_db.record_scan(
                _fake_result("Desconocido", 10, apps_generic=["mystery.com"], url=f"https://store{i}.com")
            )
        extra = local_vuln_db.enrich_findings({"theme": {}, "apps_generic": ["mystery.com"]})
        assert any("mystery.com" in f["title"] for f in extra)

    def test_no_flag_below_threshold(self, tmp_path, monkeypatch):
        monkeypatch.setattr(local_vuln_db, "DB_PATH", tmp_path / "db.sqlite3")
        local_vuln_db.record_scan(
            _fake_result("Desconocido", 10, apps_generic=["mystery.com"], url="https://store0.com")
        )
        extra = local_vuln_db.enrich_findings({"theme": {}, "apps_generic": ["mystery.com"]})
        assert extra == []
