"""
Pruebas de report_html.py: tema oscuro coherente con la interfaz web, y
layout en cuadrícula (no todo apilado en una sola columna estrecha).
"""

from shopiscan import report_html


def _fake_result(findings=None):
    return {
        "url": "https://tienda.com",
        "theme": {"name": "Dawn", "id": "1", "role": "main", "version": "15.0"},
        "risk": {"score": 20, "label": "MEDIO"},
        "findings": findings or [],
        "known_services": ["Klaviyo"],
        "apps_generic": [],
        "shadow_apps": [],
    }


class TestDarkTheme:
    def test_dark_background_color_present(self):
        html = report_html.generate_html_report(_fake_result())
        assert "#05070d" in html
        assert "color-scheme: dark" in html

    def test_panel_colors_present(self):
        html = report_html.generate_html_report(_fake_result())
        assert "#10151f" in html  # --panel
        assert "#141a26" in html  # --panel-2

    def test_no_leftover_light_theme_colors(self):
        html = report_html.generate_html_report(_fake_result())
        # Colores de fondo claro de la versión anterior no deben quedar
        assert "#f5f6fa" not in html
        assert "background: white" not in html

    def test_severity_badge_colors_still_correct_semantics(self):
        assert report_html.SEVERITY_COLORS["CRÍTICA"].lower() in ("#f87171",)
        assert report_html.SEVERITY_COLORS["BAJA"].lower() in ("#34d399",)
        assert report_html.SEVERITY_COLORS["INFO"].lower() in ("#38bdf8",)


class TestWiderGridLayout:
    def test_container_max_width_increased(self):
        html = report_html.generate_html_report(_fake_result())
        assert "max-width: 1240px" in html

    def test_top_grid_present_for_score_theme_services(self):
        html = report_html.generate_html_report(_fake_result())
        assert "top-grid" in html
        assert "grid-template-columns" in html

    def test_findings_use_card_grid_not_stacked_list(self):
        findings = [
            {"level": "Baja", "title": "Hallazgo 1", "detail": "x"},
            {"level": "Alta", "title": "Hallazgo 2", "detail": "y"},
        ]
        html = report_html.generate_html_report(_fake_result(findings))
        assert "findings-grid" in html
        assert html.count("finding-card") >= 2

    def test_owasp_and_history_share_a_row_when_both_present(self):
        from unittest.mock import MagicMock

        comparison = MagicMock()
        comparison.to_dict.return_value = {
            "score_delta": 5, "previous_date": "2026-01-01", "previous_score": 10,
            "previous_label": "BAJO", "current_score": 15, "current_label": "BAJO",
            "new_findings": [], "resolved_findings": [],
        }
        findings = [{"level": "Baja", "title": "x", "detail": "y"}]
        html = report_html.generate_html_report(_fake_result(findings), comparison=comparison)
        assert "two-col" in html
