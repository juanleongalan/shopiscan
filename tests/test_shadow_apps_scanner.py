"""Pruebas unitarias del detector de shadow apps (residuos de apps desinstaladas)."""

from shopiscan import shadow_apps_scanner


class TestShadowAppsScanner:
    def test_detects_residue_without_active_script(self):
        html = '<div id="loox-reviews-widget"></div>'  # marcador sin script activo
        findings = shadow_apps_scanner.detect_shadow_apps(html)
        assert any(f["app"].startswith("Loox") for f in findings)

    def test_no_flag_when_app_is_actively_loaded(self):
        html = (
            '<div id="loox-reviews-widget"></div>'
            '<script src="https://loox.io/widget.js"></script>'
        )
        findings = shadow_apps_scanner.detect_shadow_apps(html)
        assert not any(f["app"].startswith("Loox") for f in findings)

    def test_clean_html_has_no_findings(self):
        html = "<html><body>Tienda limpia, sin apps.</body></html>"
        findings = shadow_apps_scanner.detect_shadow_apps(html)
        assert findings == []

    def test_multiple_shadow_apps_detected_independently(self):
        html = (
            '<div id="loox-reviews-widget"></div>'
            '<div id="judgeme-widget"></div>'
        )
        findings = shadow_apps_scanner.detect_shadow_apps(html)
        app_names = {f["app"] for f in findings}
        assert any(name.startswith("Loox") for name in app_names)
        assert any(name.startswith("Judge.me") for name in app_names)


class TestGenericMinifiedCodeFalsePositives:
    """Regresión: en un análisis de más de 30 escaneos reales, ~74% de las
    tiendas (incluidas grandes marcas con bundles JS pesados: The Body
    Shop, Carhartt, Harley-Davidson, Delta, Equinix...) marcaban Zendesk
    como shadow app aunque nunca lo hubieran instalado. La causa: los
    marcadores 'zE\\(' y 'hj\\(' eran llamadas de función de solo 2
    caracteres, que coinciden por pura casualidad con identificadores
    internos de bundlers minificados (webpack/rollup) en cualquier sitio
    grande, sin relación alguna con Zendesk o Hotjar."""

    def test_minified_bundle_code_does_not_trigger_zendesk(self):
        # HTML típico de un bundle minificado grande, sin Zendesk instalado
        noisy_html = (
            "<script>!function(e){var zE=function(t,n){return e[t](n)};"
            "var xyz = zE(123, 456);}(window)</script>"
        )
        findings = shadow_apps_scanner.detect_shadow_apps(noisy_html)
        assert not any(f["app"].startswith("Zendesk") for f in findings)

    def test_minified_bundle_code_does_not_trigger_hotjar(self):
        noisy_html = "<script>function hj(a,b){return a+b} var r = hj(1,2);</script>"
        findings = shadow_apps_scanner.detect_shadow_apps(noisy_html)
        assert not any(f["app"].startswith("Hotjar") for f in findings)

    def test_real_zendesk_webwidget_call_still_detected_as_shadow(self):
        html = "<script>zE('webWidget', 'show');</script>"
        findings = shadow_apps_scanner.detect_shadow_apps(html)
        assert any(f["app"].startswith("Zendesk") for f in findings)

    def test_real_hotjar_trigger_call_still_detected_as_shadow(self):
        html = "<script>hj('trigger', 'my_event');</script>"
        findings = shadow_apps_scanner.detect_shadow_apps(html)
        assert any(f["app"].startswith("Hotjar") for f in findings)

    def test_zendesk_id_marker_still_detected(self):
        html = '<div id="zendesk-widget"></div>'
        findings = shadow_apps_scanner.detect_shadow_apps(html)
        assert any(f["app"].startswith("Zendesk") for f in findings)

    def test_active_zendesk_script_not_flagged_as_shadow(self):
        html = '<div id="zendesk-widget"></div><script src="https://static.zdassets.com/x.js"></script>'
        findings = shadow_apps_scanner.detect_shadow_apps(html)
        assert not any(f["app"].startswith("Zendesk") for f in findings)
