# Arquitectura de ShopiScan (v3)

## 1. Visión general

ShopiScan sigue una arquitectura en capas con un principio de diseño
transversal: **todo lo externo es opcional y degrada con elegancia**. El
escaneo técnico funciona de forma completamente autónoma (sin más red que
el propio objetivo) aunque falten Ollama, PostgreSQL, Prometheus o
cualquier otra pieza.

1. **Capa de recolección** (`core.py` y los `*_scanner.py`): obtiene datos
   públicos del objetivo (HTML, headers, cookies, endpoints, scripts,
   certificado TLS, rutas sensibles) sin ninguna acción ofensiva/activa.
2. **Capa de puntuación** (`scoring.py`): convierte los hallazgos en un
   score de riesgo 0-100 transparente y explicable.
3. **Capa de razonamiento con IA** (`ai_analyzer.py`): opcional; envía el
   JSON de hallazgos a un modelo **local de Ollama** y devuelve un Informe
   Ejecutivo de Riesgo. Sin API keys ni servicios externos.
4. **Capa de persistencia/inteligencia** (`history.py`, `local_vuln_db.py`,
   `vector_db.py`): histórico por tienda, base de datos local incremental
   (SQLite) y búsqueda semántica (PostgreSQL + pgvector) para contexto RAG.
5. **Capa de observabilidad/notificación** (`metrics.py`,
   `metrics_prom.py`, `notifications.py`): métricas Prometheus y alertas
   Slack/email.
6. **Capa de presentación/entrada** (`utils.py`, `report_html.py`,
   `__init__.py` para la CLI, `server.py` para el modo HTTP).

## 2. Diagrama de componentes

```mermaid
flowchart TD
    CLI["__init__.py (CLI)"]
    SRV["server.py (FastAPI)"]
    CORE["core.py (motor de escaneo)"]
    SCAN["secrets / libraries / shadow_apps / ssl_tls / exposed_paths"]
    SCORE["scoring.py"]
    AI["ai_analyzer.py (Ollama local)"]
    HIST["history.py"]
    LDB["local_vuln_db.py (SQLite)"]
    VDB["vector_db.py (pgvector)"]
    MET["metrics.py / metrics_prom.py"]
    NOTIF["notifications.py"]
    HTML["report_html.py"]

    CLI --> CORE
    SRV --> CORE
    CORE --> SCAN
    CORE --> SCORE
    CLI --> HIST
    CLI --> LDB
    CLI --> VDB
    VDB -->|RAG| AI
    CLI --> AI
    CLI --> NOTIF
    CLI --> MET
    SRV --> MET
    CLI --> HTML
    MET --> PROM["Prometheus"]
    PROM --> GRAF["Grafana"]
    VDB --> PG[("PostgreSQL + pgvector")]
```

## 3. Flujo de datos de un escaneo (CLI con --ai)

```mermaid
sequenceDiagram
    participant U as Usuario
    participant CLI as CLI (__init__.py)
    participant Core as core.run_scan()
    participant Score as scoring
    participant VDB as vector_db (pgvector)
    participant AI as ai_analyzer (Ollama)
    participant Out as Salida (consola/JSON/HTML/metrics)

    U->>CLI: shopiscan -u https://tienda.com --ai
    CLI->>CLI: confirm_authorization()
    CLI->>Core: run_scan()
    Core->>Core: detección + escáneres (headers, TLS, secrets, ...)
    Core->>Score: compute_risk_score(findings)
    Core-->>CLI: ScanResult
    CLI->>VDB: find_similar_for_scan()  (contexto RAG)
    VDB-->>CLI: hallazgos similares
    CLI->>AI: generate_executive_report(scan, similar)
    AI->>AI: Ollama chat (llama3.1, local)
    AI-->>CLI: Informe Ejecutivo (JSON)
    CLI->>VDB: index_findings()  (embeddings -> pgvector)
    CLI->>Out: consola + JSON + HTML + métricas .prom
```

## 4. Decisiones de diseño clave

- **IA local por defecto (Ollama).** Se eligió frente a una API en la nube
  por privacidad (los datos de tiendas de terceros no salen de la máquina),
  coste (gratis) y ausencia de límites de cuota. `ai_analyzer.get_embedding()`
  reutiliza Ollama también para los embeddings de pgvector.
- **Degradado en cascada.** Cada dependencia externa (Ollama, PostgreSQL,
  Prometheus, dotenv, notificaciones) se importa de forma perezosa y su
  ausencia produce un aviso, nunca una excepción que tumbe el escaneo.
- **Dos vías de métricas.** `metrics.py` (textfile collector) para la CLI
  puntual/batch; `metrics_prom.py` (prometheus_client + endpoint HTTP)
  para el servidor de larga vida. Misma semántica, distinto transporte.
- **Bug corregido en la resolución de la raíz del dominio** (`_site_root`):
  las comprobaciones de rutas conocidas (`/sitemap.xml`, `/products.json`,
  `/.env`...) se hacen siempre contra `scheme://netloc`, no concatenando
  sobre una URL con subpath/query, lo que antes causaba falsos positivos
  silenciosos al escanear una URL profunda.
- **Anti-soft-404.** `exposed_paths_scanner` sondea primero una ruta
  aleatoria inexistente; si el sitio responde 200 a todo, se omiten las
  comprobaciones de rutas sensibles para no generar falsos positivos.

## 5. Stack de despliegue (deploy/)

`docker compose` levanta cinco servicios que reflejan las directrices del
proyecto: **PostgreSQL+pgvector** (búsquedas vectorizadas), **Ollama**
(IA local, con descarga automática de modelos), el **servidor ShopiScan**
(FastAPI, expone `/metrics`), **Prometheus** (scrapea las métricas) y
**Grafana** (dashboards, con datasources Prometheus + Postgres y un
dashboard ya provisionados).
