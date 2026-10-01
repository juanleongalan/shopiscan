"""
Pruebas de la organización de informes en carpetas por escaneo
(<output_dir>/<tienda>/<fecha_hora>/) en vez de acumularlos sueltos en el
directorio de trabajo.
"""

import argparse
from unittest.mock import MagicMock, patch

import shopiscan


def _fake_scan_result(url="https://tienda.com"):
    result = MagicMock()
    result.is_shopify = True
    result.url = url
    result.theme_name = "Dawn"
    result.theme_id = "1"
    result.theme_role = "main"
    result.known_services = []
    result.apps_generic = []
    result.missing_headers = []
    result.present_headers = ["Strict-Transport-Security"]
    result.leaked_secrets = []
    result.outdated_libraries = []
    result.shadow_apps = []
    result.exposed_paths = []
    result.findings = []
    result.risk = {"score": 5, "label": "BAJO", "breakdown": {}, "owasp_breakdown": {}}
    result.to_dict.return_value = {
        "url": url,
        "risk": result.risk,
        "findings": [],
        "apps_generic": [],
        "shadow_apps": [],
        "theme": {"name": "Dawn"},
    }
    return result


class TestPerScanOutputFolders:
    def _base_args(self, tmp_path, **overrides):
        defaults = dict(
            url="https://tienda.com",
            url_file=None,
            ai=False,
            model=None,
            json=True,
            output=None,
            output_dir=str(tmp_path / "reports"),
            html_report=True,
            no_fetch_scripts=True,
            no_history=True,
            no_local_db=True,
            no_vector_db=True,
            no_metrics=True,
            metrics_dir=None,
            no_notify=True,
            notify_threshold=0,
        )
        defaults.update(overrides)
        return argparse.Namespace(**defaults)

    def test_creates_dedicated_folder_per_scan(self, tmp_path):
        args = self._base_args(tmp_path)
        with patch("shopiscan.core.run_scan", return_value=_fake_scan_result()):
            shopiscan.scan_one("https://tienda.com", args)

        store_dir = tmp_path / "reports" / "tienda.com"
        assert store_dir.exists()
        subfolders = list(store_dir.iterdir())
        assert len(subfolders) == 1
        assert (subfolders[0] / "report.json").exists()
        assert (subfolders[0] / "report.html").exists()

    def test_two_scans_get_different_folders(self, tmp_path):
        args = self._base_args(tmp_path)
        with patch("shopiscan.core.run_scan", return_value=_fake_scan_result()):
            shopiscan.scan_one("https://tienda.com", args)
            import time as _t
            _t.sleep(1.1)  # asegura timestamp distinto (resolución de segundos)
            shopiscan.scan_one("https://tienda.com", args)

        store_dir = tmp_path / "reports" / "tienda.com"
        subfolders = list(store_dir.iterdir())
        assert len(subfolders) == 2, "cada escaneo debe tener su propia carpeta, no sobrescribir"

    def test_explicit_output_path_overrides_folder_behavior(self, tmp_path):
        exact_path = tmp_path / "custom_name.json"
        args = self._base_args(tmp_path, output=str(exact_path), html_report=False)
        with patch("shopiscan.core.run_scan", return_value=_fake_scan_result()):
            shopiscan.scan_one("https://tienda.com", args)

        assert exact_path.exists()
        assert not (tmp_path / "reports" / "tienda.com").exists()

    def test_different_stores_get_different_subfolders(self, tmp_path):
        args = self._base_args(tmp_path)
        with patch("shopiscan.core.run_scan", return_value=_fake_scan_result("https://otra-tienda.com")):
            shopiscan.scan_one("https://otra-tienda.com", args)

        assert (tmp_path / "reports" / "otra-tienda.com").exists()
