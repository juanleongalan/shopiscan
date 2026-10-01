#!/usr/bin/env bash
# Arranca (o actualiza) el stack completo de ShopiScan, SIEMPRE reconstruyendo
# la imagen del servidor con el código actual. Evita el problema más común
# al actualizar ShopiScan: "docker compose up -d" sin --build reutiliza una
# imagen vieja, y la interfaz web nueva no aparece (error 404 "Not Found"
# al abrir http://localhost:8000).
#
# Uso:
#   cd deploy
#   ./up.sh
set -euo pipefail
cd "$(dirname "$0")"

echo "==> Deteniendo contenedores previos (si los hay)..."
docker compose down

echo "==> Reconstruyendo la imagen de ShopiScan con el código actual..."
docker compose build --no-cache shopiscan

echo "==> Levantando el stack completo..."
docker compose up -d

echo ""
echo "Listo. Comprueba la versión realmente en marcha con:"
echo "  curl http://localhost:8000/health"
echo ""
echo "Interfaz web:  http://localhost:8000"
echo "Grafana:       http://localhost:3000  (admin/admin)"
echo "Prometheus:    http://localhost:9090"
