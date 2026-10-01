"""
Pruebas del servidor HTTP (server.py): la orquestación _run_full_scan()
(compartida entre la API JSON y la interfaz web /scan/ui), el guardado en
disco y el degradado correcto cuando FastAPI no está instalado.
"""

from unittest.mock import MagicMock, patch

from shopiscan import server


def _fake_scan_result(is_shopify=True):
    result = MagicMock()
    result.is_shopify = is_shopify
    result.url = "https://tienda.com"
    result.findings = []
    result.risk = {"score": 5, "label": "BAJO", "breakdown": {}, "owasp_breakdown": {}}
    result.to_dict.return_value = {
        "url": "https://tienda.com",
        "risk": result.risk,
        "findings": [],
        "apps_generic": [],
        "shadow_apps": [],
        "theme": {"name": "Dawn"},
    }
    return result


class TestRunFullScan:
    def test_non_shopify_short_circuits(self):
        with patch("shopiscan.server.core.run_scan", return_value=_fake_scan_result(is_shopify=False)):
            result, ai_report, comparison, saved_paths, vector_db_note = server._run_full_scan(
                "https://noshopify.com", use_ai=False, use_history=False,
                use_local_db=False, use_vector_db=False,
            )
        assert result.is_shopify is False
        assert ai_report is None
        assert comparison is None
        assert saved_paths == {}

    def test_shopify_scan_without_extras_returns_none_ai_and_comparison(self):
        with patch("shopiscan.server.core.run_scan", return_value=_fake_scan_result()):
            result, ai_report, comparison, saved_paths, vector_db_note = server._run_full_scan(
                "https://tienda.com", use_ai=False, use_history=False,
                use_local_db=False, use_vector_db=False,
            )
        assert result.is_shopify is True
        assert ai_report is None
        assert comparison is None
        assert saved_paths == {}

    def test_ai_flag_triggers_executive_report(self):
        fake_report = {"executive_summary": "ok", "overall_risk_level": "BAJO", "findings": [], "quick_wins": []}
        with patch("shopiscan.server.core.run_scan", return_value=_fake_scan_result()), \
             patch("shopiscan.server.ai_analyzer.generate_executive_report", return_value=fake_report) as mock_ai:
            result, ai_report, comparison, saved_paths, vector_db_note = server._run_full_scan(
                "https://tienda.com", use_ai=True, use_history=False,
                use_local_db=False, use_vector_db=False,
            )
        assert ai_report == fake_report
        mock_ai.assert_called_once()

    def test_save_files_writes_json_and_html(self, tmp_path):
        with patch("shopiscan.server.core.run_scan", return_value=_fake_scan_result()):
            result, ai_report, comparison, saved_paths, vector_db_note = server._run_full_scan(
                "https://tienda.com", use_ai=False, use_history=False,
                use_local_db=False, use_vector_db=False,
                save_files=True, output_dir=str(tmp_path),
            )
        assert saved_paths
        assert (tmp_path / "tienda.com").exists()
        json_path = saved_paths["json"]
        html_path = saved_paths["html"]
        import os
        assert os.path.exists(json_path)
        assert os.path.exists(html_path)

    def test_no_save_files_by_default(self):
        with patch("shopiscan.server.core.run_scan", return_value=_fake_scan_result()):
            result, ai_report, comparison, saved_paths, vector_db_note = server._run_full_scan(
                "https://tienda.com", use_ai=False, use_history=False,
                use_local_db=False, use_vector_db=False,
            )
        assert saved_paths == {}

    def test_notify_called_when_score_regresses(self):
        fake_comparison = MagicMock()
        fake_comparison.to_dict.return_value = {"score_delta": 10}
        with patch("shopiscan.server.core.run_scan", return_value=_fake_scan_result()), \
             patch("shopiscan.history.load_previous_snapshot", return_value={"score": 0}), \
             patch("shopiscan.history.compare", return_value=fake_comparison), \
             patch("shopiscan.history.save_snapshot"), \
             patch("shopiscan.notifications.notify_score_regression") as mock_notify:
            server._run_full_scan(
                "https://tienda.com", use_ai=False, use_history=True,
                use_local_db=False, use_vector_db=False, use_notify=True, notify_threshold=5,
            )
        mock_notify.assert_called_once()


class TestCreateAppDegradesWithoutFastAPI:
    def test_raises_runtime_error_when_fastapi_missing(self):
        import builtins
        real_import = builtins.__import__

        def fake_import(name, *args, **kwargs):
            if name == "fastapi":
                raise ImportError("no fastapi")
            return real_import(name, *args, **kwargs)

        with patch("builtins.__import__", side_effect=fake_import):
            try:
                server.create_app()
                raise AssertionError("debería haber lanzado RuntimeError")
            except RuntimeError as exc:
                assert "server" in str(exc)


class TestIndexHtmlContainsAllOptions:
    def test_all_scan_options_present_in_form(self):
        html = server._INDEX_HTML
        for field in [
            'name="url"', 'name="ai"', 'name="model"', 'name="fetch_scripts"',
            'name="use_history"', 'name="use_local_db"', 'name="use_vector_db"',
            'name="use_metrics"', 'name="save_files"', 'name="authorized"',
        ]:
            assert field in html, f"Falta el campo {field} en el formulario"

    def test_notify_fields_intentionally_absent_from_ui(self):
        """'Ajustes avanzados' (notificaciones) se ocultó de la interfaz web
        a petición explícita, pero la funcionalidad sigue activa en el
        backend (API JSON, _run_full_scan) por si se reactiva más adelante."""
        html = server._INDEX_HTML
        assert "Ajustes avanzados" not in html
        assert 'name="use_notify"' not in html
        assert 'name="notify_threshold"' not in html
        # Pero el backend SÍ sigue soportando estos parámetros:
        import inspect

        sig = inspect.signature(server._run_full_scan)
        assert "use_notify" in sig.parameters
        assert "notify_threshold" in sig.parameters

    def test_severity_color_legend_present(self):
        html = server._INDEX_HTML
        # Colores del tema oscuro (más vibrantes para legibilidad sobre fondo
        # oscuro que los del informe HTML en sí, pero mismo orden semántico:
        # rojo=Critica, naranja=Alta, amarillo=Media, verde=Baja, azul=Info).
        for color in ["#f87171", "#fb923c", "#facc15", "#34d399", "#38bdf8"]:
            assert color in html
        legend_pos = html.find('class="legend"')
        legend_block = html[legend_pos:legend_pos + 600]
        assert "Critica" in legend_block
        assert "Alta" in legend_block
        assert "Media" in legend_block
        assert "Baja" in legend_block
        assert "Info" in legend_block


class TestServerLoadsDotenv:
    """Regresión: server.py nunca llamaba a _load_dotenv_if_available(),
    a diferencia de la CLI — así que OLLAMA_URL/DATABASE_URL definidos en
    .env se ignoraban silenciosamente al usar 'shopiscan-server'."""

    def test_main_loads_dotenv_before_starting(self, monkeypatch, tmp_path):
        env_file = tmp_path / ".env"
        env_file.write_text("OLLAMA_URL=http://example-from-dotenv:11434\n")
        monkeypatch.chdir(tmp_path)
        monkeypatch.delenv("OLLAMA_URL", raising=False)

        import types
        fake_uvicorn = types.ModuleType("uvicorn")
        fake_uvicorn.run = lambda app, host, port: None

        with patch.dict("sys.modules", {"uvicorn": fake_uvicorn}), \
             patch("shopiscan.server.create_app", return_value=MagicMock()):
            server.main()

        import os
        assert os.environ.get("OLLAMA_URL") == "http://example-from-dotenv:11434"
        monkeypatch.delenv("OLLAMA_URL", raising=False)


class TestVectorDbNoteDiagnostic:
    """Regresión: si la búsqueda vectorial fallaba (p. ej. por el cambio de
    API de embeddings de Ollama), no había ninguna señal visible para el
    usuario — solo un aviso en los logs del contenedor, invisible desde la
    interfaz web. Ahora _run_full_scan() devuelve un motivo explícito."""

    def test_no_note_when_vector_db_disabled(self):
        with patch("shopiscan.server.core.run_scan", return_value=_fake_scan_result()):
            result = server._run_full_scan(
                "https://tienda.com", use_ai=False, use_history=False,
                use_local_db=False, use_vector_db=False,
            )
        assert result[4] is None

    def test_note_when_database_not_available(self):
        with patch("shopiscan.server.core.run_scan", return_value=_fake_scan_result()), \
             patch("shopiscan.server.vector_db.ensure_schema"), \
             patch("shopiscan.server.vector_db.find_similar_for_scan", return_value=[]), \
             patch("shopiscan.server.vector_db.is_available", return_value=False):
            result = server._run_full_scan(
                "https://tienda.com", use_ai=False, use_history=False,
                use_local_db=False, use_vector_db=True,
            )
        assert result[4] is not None
        assert "no disponible" in result[4].lower()

    def test_note_when_zero_findings_indexed(self):
        scan_result = _fake_scan_result()
        scan_result.findings = [{"title": "x", "level": "Baja"}]
        with patch("shopiscan.server.core.run_scan", return_value=scan_result), \
             patch("shopiscan.server.vector_db.ensure_schema"), \
             patch("shopiscan.server.vector_db.find_similar_for_scan", return_value=[]), \
             patch("shopiscan.server.vector_db.is_available", return_value=True), \
             patch("shopiscan.server.vector_db.index_findings", return_value=(0, "modelo de embeddings no encontrado")):
            result = server._run_full_scan(
                "https://tienda.com", use_ai=False, use_history=False,
                use_local_db=False, use_vector_db=True,
            )
        assert result[4] is not None
        assert "modelo de embeddings no encontrado" in result[4]

    def test_no_note_when_indexing_succeeds(self):
        scan_result = _fake_scan_result()
        scan_result.findings = [{"title": "x", "level": "Baja"}]
        with patch("shopiscan.server.core.run_scan", return_value=scan_result), \
             patch("shopiscan.server.vector_db.ensure_schema"), \
             patch("shopiscan.server.vector_db.find_similar_for_scan", return_value=[]), \
             patch("shopiscan.server.vector_db.is_available", return_value=True), \
             patch("shopiscan.server.vector_db.index_findings", return_value=(1, None)):
            result = server._run_full_scan(
                "https://tienda.com", use_ai=False, use_history=False,
                use_local_db=False, use_vector_db=True,
            )
        assert result[4] is None


class TestIndexHtmlUxFixes:
    """Regresiones de UX reportadas por el usuario tras usar la interfaz web."""

    def test_authorization_checkbox_not_checked_by_default(self):
        html = server._INDEX_HTML
        start = html.find('name="authorized"')
        assert start != -1
        tag = html[max(0, start - 80):start + 100]
        assert "checked" not in tag, "La casilla de autorización no debe venir marcada por defecto"

    def test_form_resets_on_pageshow_to_avoid_browser_autofill_restoring_checkbox(self):
        html = server._INDEX_HTML
        assert "pageshow" in html
        assert "form.reset()" in html

    def test_top_scan_button_present_right_after_url_field(self):
        html = server._INDEX_HTML
        url_pos = html.find('name="url"')
        top_btn_pos = html.find('id="submitBtnTop"')
        scope_section_pos = html.find("Alcance del escaneo")
        assert url_pos < top_btn_pos < scope_section_pos

    def test_scope_section_before_ai_section(self):
        html = server._INDEX_HTML
        assert html.find("Alcance del escaneo") < html.find("Inteligencia artificial")

    def test_two_submit_buttons_disabled_together_during_scan(self):
        html = server._INDEX_HTML
        assert "submitBtnTop.disabled = true" in html
        assert "submitBtn.disabled = true" in html


class TestResultsCache:
    """La interfaz ahora redirige a una página de resultados independiente
    (/scan/result/<id>) en vez de mostrar el informe en un iframe dentro
    de la misma página. Estos tests cubren esa caché en memoria."""

    def setup_method(self):
        server._RESULTS_CACHE.clear()

    def test_store_and_retrieve(self):
        rid = server._store_result_html("<html>x</html>")
        assert server._get_result_html(rid) == "<html>x</html>"

    def test_missing_id_returns_none(self):
        assert server._get_result_html("no-existe") is None

    def test_cache_is_bounded(self):
        ids = [server._store_result_html(f"c{i}") for i in range(server._RESULTS_CACHE_MAX + 3)]
        assert len(server._RESULTS_CACHE) == server._RESULTS_CACHE_MAX
        assert server._get_result_html(ids[0]) is None
        assert server._get_result_html(ids[-1]) is not None

    def test_ids_are_unique(self):
        ids = {server._store_result_html("x") for _ in range(20)}
        assert len(ids) == 20


class TestStandalonePage:
    def test_not_shopify_message_text(self):
        page = server._standalone_page("Sin resultados", "No se ha detectado tienda Shopify.")
        assert "No se ha detectado tienda Shopify." in page
        assert "no parece ser una tienda Shopify" not in page

    def test_includes_back_navigation(self):
        page = server._standalone_page("Titulo", "mensaje")
        assert "ShopiScan" in page
        assert 'href="/"' in page

    def test_error_page_uses_red_color(self):
        page = server._standalone_page("Error", "algo falló", is_error=True)
        assert "#f87171" in page


class TestBackNavInsertion:
    def test_back_nav_inserted_right_after_body_tag(self):
        fake_report = "<html><head></head><body><header>Informe real</header></body></html>"
        result = fake_report.replace("<body>", "<body>" + server._BACK_NAV_HTML, 1)
        assert result.index("ShopiScan") < result.index("Informe real")


class TestReorderedTopBlockAndAccordions:
    """Cambios pedidos: la casilla de autorización y la leyenda de colores
    suben justo debajo del botón superior, las secciones pasan a ser
    menús desplegables, y los botones quedan centrados."""

    def test_auth_box_right_after_top_button(self):
        html = server._INDEX_HTML
        top_btn_pos = html.find('id="submitBtnTop"')
        auth_pos = html.find('class="auth-box"')
        first_accordion_pos = html.find('<details class="accordion">')
        assert top_btn_pos < auth_pos < first_accordion_pos

    def test_legend_after_auth_box_before_accordions(self):
        html = server._INDEX_HTML
        auth_pos = html.find('class="auth-box"')
        legend_pos = html.find('class="legend"')
        hint_pos = html.find("O ajusta los parametros abajo")
        first_accordion_pos = html.find('<details class="accordion">')
        assert auth_pos < legend_pos < hint_pos < first_accordion_pos

    def test_sections_are_collapsible_details_elements(self):
        html = server._INDEX_HTML
        for section in ["Alcance del escaneo", "Inteligencia artificial", "Observabilidad", "Guardado"]:
            pos = html.find(section)
            assert pos != -1, f"Falta la sección {section}"
            # Debe estar dentro de un <summary> de un <details>
            preceding = html[max(0, pos - 200):pos]
            assert "<summary>" in preceding, f"'{section}' no está dentro de un <summary> desplegable"

    def test_accordions_closed_by_default(self):
        html = server._INDEX_HTML
        # Ningún <details> debe llevar el atributo 'open' (colapsados por defecto)
        assert "<details open" not in html
        assert html.count("<details class=\"accordion\">") == 4

    def test_buttons_are_centered(self):
        html = server._INDEX_HTML
        assert html.count('class="btn-row"') == 2
        assert "justify-content: center" in html
