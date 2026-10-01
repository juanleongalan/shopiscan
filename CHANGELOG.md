# Registro de cambios

Formato basado en [Keep a Changelog](https://keepachangelog.com/es-ES/1.1.0/).

## [3.0.0] — Versión de publicación open source

### Añadido
- IA 100% local con Ollama (Informe Ejecutivo de Riesgo), sin API keys ni envío de datos a terceros.
- Búsqueda vectorial de hallazgos similares con PostgreSQL + pgvector (RAG).
- Observabilidad con Prometheus + Grafana (métricas y dashboards por tienda).
- Servidor HTTP opcional (FastAPI): API REST y interfaz web propia con tema oscuro, secciones desplegables y página de resultados independiente.
- Clasificación automática de cada hallazgo según OWASP Top 10 (2021), basada en reglas e independiente de la IA.
- Sugerencias de remediación basadas en reglas (funcionan sin IA).
- Comparación histórica entre escaneos de una misma tienda.
- Base de datos local incremental (SQLite) de patrones recurrentes.
- Notificaciones por Slack/email cuando el score de riesgo empeora.
- Detección de certificado/protocolo TLS, rutas sensibles (`.env`, `.git`) con protección anti falso-positivo, y más de 20 firmas de "shadow apps".
- Despliegue completo con Docker Compose (`./up.sh`), con reconstrucción automática de la imagen.
- Integración CI/CD con GitHub Actions (tests + escaneo periódico programado).
- Suite de más de 200 pruebas automatizadas.
- `SECURITY.md` y `CONTRIBUTING.md` para la publicación como proyecto open source.

### Corregido
- Falso positivo sistemático en la detección de la shadow app Zendesk (afectaba a ~84% de las tiendas analizadas) — patrón de coincidencia demasiado genérico, sustituido por la firma real de su API.
- Error de resolución de tipos en las consultas de similitud vectorial de PostgreSQL (`operator does not exist: vector <=> double precision[]`).
- Cambio de comportamiento del aprovisionamiento de datasources de Grafana entre versiones (campo `database` movido a `jsonData`).
- Bug de resolución de la URL raíz del dominio que generaba falsos positivos silenciosos en rutas conocidas al escanear URLs con subruta o query string.
- Migración de la API de embeddings de Ollama (`/api/embeddings` deprecada → `/api/embed`), con respaldo automático a la API antigua.
- `shopiscan-server` no cargaba el `.env`, a diferencia de la CLI.
- El volumen `shopiscan_reports` de Docker Compose era un volumen nombrado (no navegable desde el host) en vez de un bind mount.

## [1.0.0] — Versión inicial

- Motor de escaneo pasivo: cabeceras HTTP, cookies, credenciales filtradas, librerías JS desactualizadas, detección de Shopify y tema activo.
- CLI con modo batch (`--url-file`), exportación a JSON y HTML.
- Score de riesgo 0-100 transparente, con niveles Crítica/Alta/Media/Baja/Info.
