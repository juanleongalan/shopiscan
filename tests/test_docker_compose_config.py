"""
Regresión: 'shopiscan_reports' estaba declarado como volumen NOMBRADO de
Docker (gestionado internamente, solo accesible con `docker cp`/`docker
exec`) en vez de un bind mount a una carpeta real del host. El usuario
veía el mensaje "Informe guardado también en: shopiscan_reports/..." pero
nunca encontraba el archivo en su disco, porque en realidad vivía dentro
de un volumen de Docker invisible desde fuera del contenedor.
"""

import os

try:
    import yaml
except ImportError:
    yaml = None

COMPOSE_PATH = os.path.join(os.path.dirname(__file__), "..", "deploy", "docker-compose.yml")

pytestmark_skip_reason = "pyyaml no está instalado ('pip install pyyaml' o 'pip install -e \".[dev]\"')"


def _load_compose():
    if yaml is None:
        return None  # pyyaml no instalado: los tests de este módulo se omiten con gracia
    with open(COMPOSE_PATH) as f:
        return yaml.safe_load(f)


class TestShopiscanReportsIsABindMount:
    def test_shopiscan_reports_volume_is_a_relative_bind_mount(self):
        compose = _load_compose()
        if compose is None:
            return
        volumes = compose["services"]["shopiscan"]["volumes"]
        reports_mounts = [v for v in volumes if v.endswith(":/app/shopiscan_reports")]
        assert reports_mounts, "Falta el mount de shopiscan_reports en el servicio 'shopiscan'"
        mount = reports_mounts[0]
        host_path = mount.split(":")[0]
        assert host_path.startswith("./") or host_path.startswith("../") or host_path.startswith("/"), (
            f"El host_path '{host_path}' no parece una ruta real del sistema de archivos "
            "(¿sigue siendo un volumen nombrado de Docker por error?)"
        )

    def test_shopiscan_reports_is_not_declared_as_named_volume(self):
        compose = _load_compose()
        if compose is None:
            return
        named_volumes = compose.get("volumes") or {}
        assert "shopiscan_reports" not in named_volumes, (
            "shopiscan_reports no debe estar en la lista de volúmenes nombrados de Docker: "
            "debe ser un bind mount a una carpeta real (ver el mount del servicio 'shopiscan')."
        )

    def test_shopiscan_home_remains_a_named_volume(self):
        """El histórico/SQLite sí debe seguir siendo un volumen nombrado
        (no necesita ser navegable por el usuario, solo persistir)."""
        compose = _load_compose()
        if compose is None:
            return
        named_volumes = compose.get("volumes") or {}
        assert "shopiscan_home" in named_volumes
