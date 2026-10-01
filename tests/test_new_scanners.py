"""
Pruebas de los módulos añadidos en v3:
  - exposed_paths_scanner (rutas sensibles + soft-404)
  - ssl_tls_scanner (helpers de expiración/versión, sin red real)
  - metrics (textfile collector de Prometheus)
  - vector_db (degradado sin DATABASE_URL)
  - core._site_root (bugfix de resolución de raíz de dominio)
"""

from unittest.mock import MagicMock, patch

from shopiscan import exposed_paths_scanner, ssl_tls_scanner, metrics, vector_db, utils
from shopiscan.core import _site_root


class TestSiteRoot:
    def test_strips_subpath_and_query(self):
        assert _site_root("https://t.com/products/x?variant=1") == "https://t.com"
        assert _site_root("https://t.com/?shpxid=abc") == "https://t.com"
        assert _site_root("https://t.com") == "https://t.com"

    def test_preserves_scheme_and_port(self):
        assert _site_root("http://t.com:8080/a/b") == "http://t.com:8080"


class TestExposedPaths:
    def _get_func(self, env_exposed=False, soft_404=False):
        def get(url):
            resp = MagicMock()
            if soft_404:
                resp.status_code = 200
                resp.text = "<html>404 pero devuelvo 200</html>"
            elif "/.env" in url and env_exposed:
                resp.status_code = 200
                resp.text = "DB_PASSWORD=secreto\nAPI_KEY=xxx"
            else:
                resp.status_code = 404
                resp.text = ""
            return resp
        return get

    def test_detects_real_env_exposure(self):
        findings = exposed_paths_scanner.scan_exposed_paths("https://t.com", self._get_func(env_exposed=True))
        assert any(".env" in f["title"] for f in findings)
        assert findings[0]["level"] == "Crítica"

    def test_soft_404_suppresses_findings(self):
        findings = exposed_paths_scanner.scan_exposed_paths("https://t.com", self._get_func(soft_404=True))
        assert findings == []

    def test_clean_site_no_findings(self):
        findings = exposed_paths_scanner.scan_exposed_paths("https://t.com", self._get_func())
        assert findings == []

    def test_html_page_with_200_is_not_a_false_positive(self):
        """Regresión: si /.env (pero NO la ruta de sondeo aleatoria) responde
        200 con una página HTML normal -- p. ej. el propio tema de la tienda,
        o una página de un proxy/WAF -- NO debe marcarse como fuga. Esto
        replica el caso real reportado: dentimiau.myshopify.com marcaba
        /.env como CRÍTICA aunque en realidad era una página HTML normal."""
        def get(url):
            resp = MagicMock()
            if "__shopiscan_probe_" in url:
                resp.status_code = 404  # el sondeo aleatorio SÍ da 404 real
                resp.text = ""
            elif "/.env" in url:
                resp.status_code = 200  # pero /.env en concreto da 200...
                resp.text = "<!DOCTYPE html><html><head></head><body>Tienda</body></html>"
            else:
                resp.status_code = 404
                resp.text = ""
            return resp
        findings = exposed_paths_scanner.scan_exposed_paths("https://dentimiau.myshopify.com", get)
        assert findings == [], f"Falso positivo reproducido: {findings}"

    def test_empty_body_200_not_flagged(self):
        def get(url):
            resp = MagicMock()
            resp.status_code = 404 if "probe" in url else 200
            resp.text = ""  # cuerpo vacío: no es una fuga real
            return resp
        findings = exposed_paths_scanner.scan_exposed_paths("https://t.com", get)
        assert findings == []


class TestSslTlsHelpers:
    def test_obsolete_tls_version_flagged(self):
        findings = ssl_tls_scanner._check_tls_version("TLSv1")
        assert findings and findings[0]["level"] == "Alta"

    def test_modern_tls_version_ok(self):
        assert ssl_tls_scanner._check_tls_version("TLSv1.3") == []

    def test_expired_cert_is_critica(self):
        cert = {"notAfter": "Jan 1 00:00:00 2020 GMT"}
        findings = ssl_tls_scanner._check_cert_expiry(cert)
        assert findings and findings[0]["level"] == "Crítica"

    def test_cert_far_from_expiry_ok(self):
        cert = {"notAfter": "Jan 1 00:00:00 2099 GMT"}
        assert ssl_tls_scanner._check_cert_expiry(cert) == []


class TestMetrics:
    def test_no_dir_no_write(self, monkeypatch):
        monkeypatch.delenv("PROMETHEUS_TEXTFILE_DIR", raising=False)
        assert metrics.write_scan_metrics({"url": "https://t.com", "risk": {}}) is None

    def test_writes_prom_file(self, tmp_path):
        result = {
            "url": "https://t.com",
            "risk": {"score": 30, "label": "MEDIO"},
            "findings": [{"level": "Alta", "title": "x"}],
            "leaked_secrets": [],
            "shadow_apps": [],
        }
        path = metrics.write_scan_metrics(result, duration_seconds=1.5, metrics_dir=str(tmp_path))
        assert path is not None
        content = open(path).read()
        assert 'shopiscan_risk_score{store="t.com"} 30' in content
        assert 'shopiscan_findings_total{store="t.com",severity="Alta"} 1' in content


class TestVectorDbDegrades:
    def test_find_similar_returns_empty_without_database_url(self, monkeypatch):
        monkeypatch.delenv("DATABASE_URL", raising=False)
        assert vector_db.find_similar_for_scan({"url": "https://t.com", "findings": [{"title": "x"}]}) == []

    def test_index_returns_zero_without_database_url(self, monkeypatch):
        monkeypatch.delenv("DATABASE_URL", raising=False)
        count, reason = vector_db.index_findings("https://t.com", [{"title": "x", "detail": "y"}])
        assert count == 0
        assert reason is not None

    def test_is_available_false_without_url(self, monkeypatch):
        monkeypatch.delenv("DATABASE_URL", raising=False)
        assert vector_db.is_available() is False


class TestMetricsPushgateway:
    def test_noop_without_pushgateway_url(self, monkeypatch):
        monkeypatch.delenv("PROMETHEUS_PUSHGATEWAY_URL", raising=False)
        result = {"url": "https://t.com", "risk": {"score": 10}, "findings": []}
        assert metrics.push_scan_metrics(result) is False

    def test_pushes_to_gateway_when_configured(self):
        import shopiscan.metrics as metrics_mod
        result = {"url": "https://t.com", "risk": {"score": 55, "label": "ALTO"}, "findings": [{"level": "Alta", "title": "x"}]}
        sent = {}

        def fake_put(url, data, timeout):
            sent["url"] = url
            sent["data"] = data.decode("utf-8")
            resp = MagicMock()
            resp.status_code = 200
            return resp

        with patch("requests.put", side_effect=fake_put):
            ok = metrics_mod.push_scan_metrics(result, duration_seconds=1.0, pushgateway_url="http://localhost:9091")

        assert ok is True
        assert sent["url"] == "http://localhost:9091/metrics/job/shopiscan/instance/t_com"
        assert 'shopiscan_risk_score{store="t.com"} 55' in sent["data"]

    def test_failed_push_returns_false(self):
        import shopiscan.metrics as metrics_mod
        result = {"url": "https://t.com", "risk": {"score": 10}, "findings": []}

        def fake_put(url, data, timeout):
            resp = MagicMock()
            resp.status_code = 500
            return resp

        with patch("requests.put", side_effect=fake_put):
            ok = metrics_mod.push_scan_metrics(result, pushgateway_url="http://localhost:9091")
        assert ok is False


class TestVectorDbSqlCasts:
    """Regresión: 'operator does not exist: vector <=> double precision[]'.
    INSERT funcionaba por el cast implícito de asignación de Postgres, pero
    la comparación con el operador <=> en el SELECT exige un cast explícito
    a ::vector en el parámetro. Verificamos que las consultas lo llevan."""

    def _fake_conn(self, monkeypatch):
        fake_cursor = MagicMock()
        fake_cursor.__enter__ = MagicMock(return_value=fake_cursor)
        fake_cursor.__exit__ = MagicMock(return_value=False)
        fake_cursor.fetchall.return_value = []
        fake_conn = MagicMock()
        fake_conn.cursor.return_value = fake_cursor
        monkeypatch.setattr(vector_db, "_connect", lambda: fake_conn)
        monkeypatch.setattr(vector_db.ai_analyzer, "get_embedding", lambda text: [0.1, 0.2, 0.3])
        monkeypatch.setattr(vector_db.ai_analyzer, "get_embedding_verbose", lambda text: ([0.1, 0.2, 0.3], None))
        return fake_cursor

    def test_select_query_casts_embedding_to_vector(self, monkeypatch):
        cursor = self._fake_conn(monkeypatch)
        vector_db.find_similar_findings({"title": "x", "detail": "y"})
        sql = cursor.execute.call_args[0][0]
        assert "<=> %s::vector" in sql, f"Falta el cast ::vector en la consulta SELECT: {sql}"

    def test_select_query_casts_exclude_url_to_text(self, monkeypatch):
        """Regresión: 'could not determine data type of parameter $2'.
        '%s IS NULL' por sí solo no le da a Postgres ninguna pista de tipo
        (IS NULL vale para cualquier tipo), así que hace falta un cast
        explícito a ::text para que el parámetro sea resoluble."""
        cursor = self._fake_conn(monkeypatch)
        vector_db.find_similar_findings({"title": "x", "detail": "y"}, exclude_url="https://a.com")
        sql = cursor.execute.call_args[0][0]
        assert "%s::text IS NULL" in sql, f"Falta el cast ::text en el parámetro exclude_url: {sql}"

    def test_insert_query_casts_embedding_to_vector(self, monkeypatch):
        cursor = self._fake_conn(monkeypatch)
        vector_db.index_findings("https://t.com", [{"title": "x", "detail": "y", "level": "Alta"}])
        sql = cursor.execute.call_args[0][0]
        assert "%s::vector" in sql, f"Falta el cast ::vector en la consulta INSERT: {sql}"


class TestMetricsOwaspBreakdown:
    def test_owasp_metric_included_when_findings_have_category(self):
        from shopiscan import owasp_mapping

        findings = [{"level": "Baja", "title": "Cookies enviadas sin el flag Secure"}]
        owasp_mapping.enrich_findings_with_owasp(findings)
        result = {"url": "https://t.com", "risk": {"score": 3}, "findings": findings}
        text, _ = metrics._build_metrics_text(result, 1.0)
        assert "shopiscan_owasp_findings_total" in text
        assert 'category="A02:2021"' in text

    def test_no_owasp_metric_when_no_categorized_findings(self):
        result = {"url": "https://t.com", "risk": {"score": 0}, "findings": []}
        text, _ = metrics._build_metrics_text(result, 1.0)
        assert "shopiscan_owasp_findings_total" not in text


class TestVectorDbWarningDeduplication:
    """Regresión: el aviso 'PostgreSQL/pgvector no disponibles' se repetía
    hasta 8 veces por escaneo (una por cada llamada a _connect(), y
    find_similar_for_scan() llama a _connect() una vez por hallazgo).
    Ahora solo debe avisar una vez por proceso."""

    def test_warns_only_once_across_multiple_connect_calls(self, monkeypatch):
        monkeypatch.setenv("DATABASE_URL", "postgresql://fake:fake@localhost/fake")
        vector_db._deps_available = None

        calls = []
        original_warning = utils.warning
        monkeypatch.setattr(utils, "warning", lambda msg: calls.append(msg))

        import builtins
        real_import = builtins.__import__

        def fake_import(name, *args, **kwargs):
            if name in ("psycopg", "pgvector.psycopg"):
                raise ImportError(f"no {name}")
            return real_import(name, *args, **kwargs)

        with patch("builtins.__import__", side_effect=fake_import):
            for _ in range(8):
                vector_db._connect()

        pgvector_warnings = [c for c in calls if "PostgreSQL/pgvector no disponibles" in c]
        assert len(pgvector_warnings) == 1, f"Se avisó {len(pgvector_warnings)} veces, debería ser 1"

        vector_db._deps_available = None  # limpieza para no afectar otros tests
