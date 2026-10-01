"""
ai_analyzer.py
---------------
Motor de análisis post-escaneo de ShopiScan — 100% LOCAL con Ollama.

Este módulo NO es un chatbot: toma la salida estructurada del escáner
(headers faltantes, cookies inseguras, scripts externos, secretos
filtrados, librerías desactualizadas, "shadow apps", TLS, rutas
sensibles...) y se la pasa a un modelo de lenguaje servido por **Ollama**
(local, sin API keys, sin cuotas, sin enviar datos a servicios externos)
con un prompt de rol fijo para que actúe como consultor de ciberseguridad
senior. El resultado es un **Informe Ejecutivo de Riesgo** estructurado.

Requiere tener Ollama en marcha (Ollama Desktop o `ollama serve`) y el
modelo de chat descargado (`ollama pull llama3.1` o el que configures en
OLLAMA_CHAT_MODEL). Si Ollama no está disponible, ShopiScan sigue
funcionando en modo "solo escaneo": la IA es un módulo opcional, nunca
una dependencia dura del núcleo de escaneo.

Este módulo también expone `get_embedding()`, usado por `vector_db.py`
para generar embeddings (con el modelo configurado en OLLAMA_EMBED_MODEL,
por defecto `nomic-embed-text`) y poder buscar hallazgos históricos
similares vía PostgreSQL + pgvector.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Any, List, Optional

from . import utils

# Config por defecto: Ollama local, sin API keys ni cuotas.
# Se usa 127.0.0.1 en vez de "localhost" a propósito: en muchos sistemas
# Linux (Debian/Kali incluidos) "localhost" puede resolver primero a la
# dirección IPv6 "::1", y si Ollama solo escucha en la IPv4 de loopback
# (127.0.0.1, que es su comportamiento por defecto), la conexión falla con
# "Failed to connect to Ollama" aunque el servicio esté perfectamente
# arrancado y accesible. 127.0.0.1 es inequívoco y evita ese problema.
DEFAULT_OLLAMA_URL = "http://127.0.0.1:11434"
DEFAULT_CHAT_MODEL = "llama3.1"
DEFAULT_EMBED_MODEL = "nomic-embed-text"

# Timeout del cliente HTTP hacia Ollama, en segundos. Modelos grandes
# (varios GB) pueden tardar bastante en cargarse en memoria en la
# primera petición, sobre todo sin GPU dedicada; 180s da margen sin
# colgar el escaneo indefinidamente si Ollama de verdad no responde.
OLLAMA_CLIENT_TIMEOUT_SECONDS = 180

OLLAMA_URL_ENV_VAR = "OLLAMA_URL"
OLLAMA_CHAT_MODEL_ENV_VAR = "OLLAMA_CHAT_MODEL"
OLLAMA_EMBED_MODEL_ENV_VAR = "OLLAMA_EMBED_MODEL"
# Modelo de reserva si el principal no está descargado localmente
# (p. ej. si solo tienes 'llama3.2' pero no 'llama3.1').
OLLAMA_FALLBACK_MODEL_ENV_VAR = "OLLAMA_FALLBACK_MODEL"

SYSTEM_PROMPT = (
    "Eres un Consultor Principal de Ciberseguridad (CISO as a Service) "
    "especializado en el ecosistema Shopify. Tu trabajo es transformar "
    "datos técnicos de un escaneo pasivo y externo en un Informe Ejecutivo "
    "de Riesgo, útil tanto para un equipo técnico como para la dirección "
    "de la tienda. Nunca inventas hallazgos que no estén respaldados por "
    "los datos recibidos; si un dato es ambiguo, lo señalas como tal. "
    "Respondes EXCLUSIVAMENTE con un objeto JSON válido, sin texto antes "
    "ni después, sin backticks ni bloques de código Markdown."
)

EXECUTIVE_REPORT_PROMPT = """
Analiza los siguientes datos técnicos, obtenidos de un escaneo EXTERNO y
PASIVO (sin acceso al backend, sin fuerza bruta, sin explotación activa)
sobre una tienda Shopify:

{data_context}
{similar_findings_context}
Genera un INFORME EJECUTIVO DE RIESGO con estas secciones:

1. "executive_summary": 3-5 frases dirigidas a la dirección del negocio,
   sin jerga técnica, explicando el nivel de exposición general y el
   impacto potencial en el negocio (reputación, fraude, pérdida de datos
   de clientes, etc.). Si se incluye una comparación con un escaneo
   anterior ("previous_scan_comparison" en los datos), menciona brevemente
   la evolución (mejoró/empeoró) en el resumen.
2. "overall_risk_level": uno de "CRÍTICO", "ALTO", "MEDIO", "BAJO".
3. "findings": lista de hallazgos correlacionados (ignora ruido/falsos
   positivos, no repitas hallazgos idénticos). Para cada uno:
   - "title": nombre corto del problema.
   - "severity": "Crítica", "Alta", "Media" o "Baja".
   - "business_impact": qué significa esto para el negocio en términos
     concretos (no técnicos).
   - "technical_explanation": por qué es un riesgo, en términos técnicos.
   - "remediation_steps": lista de pasos concretos y ordenados.
   - "code_snippet": snippet EXACTO de código o configuración cuando
     aplique (Liquid, JSON de theme.liquid, cabecera HTTP, configuración
     del Admin de Shopify, etc.). Usa cadena vacía "" si no aplica.
4. "quick_wins": lista corta (máx. 3) de acciones de alto impacto y bajo
   esfuerzo que el equipo debería priorizar esta semana.

No sugieras herramientas de pago innecesarias si hay una solución nativa
de Shopify o de configuración de servidor/DNS.

Responde ÚNICAMENTE con el JSON del informe, siguiendo exactamente este
esquema, sin texto adicional antes o después, sin backticks ni bloques de
código Markdown:

{{
  "executive_summary": "string",
  "overall_risk_level": "CRÍTICO|ALTO|MEDIO|BAJO",
  "findings": [
    {{
      "title": "string",
      "severity": "Crítica|Alta|Media|Baja",
      "business_impact": "string",
      "technical_explanation": "string",
      "remediation_steps": ["string", "..."],
      "code_snippet": "string"
    }}
  ],
  "quick_wins": ["string", "..."]
}}
"""


class AIAnalyzerError(Exception):
    """Error genérico y controlado del módulo de análisis con IA."""


@dataclass(frozen=True)
class AIConfig:
    """Configuración de conexión a Ollama (local, sin API key)."""

    base_url: str = DEFAULT_OLLAMA_URL
    chat_model: str = DEFAULT_CHAT_MODEL
    embed_model: str = DEFAULT_EMBED_MODEL
    fallback_model: Optional[str] = None

    def model_chain(self) -> List[str]:
        chain = [self.chat_model]
        if self.fallback_model and self.fallback_model != self.chat_model:
            chain.append(self.fallback_model)
        return chain


def _load_config(model: Optional[str] = None) -> AIConfig:
    base_url = os.environ.get(OLLAMA_URL_ENV_VAR, DEFAULT_OLLAMA_URL)
    chat_model = model or os.environ.get(OLLAMA_CHAT_MODEL_ENV_VAR) or DEFAULT_CHAT_MODEL
    embed_model = os.environ.get(OLLAMA_EMBED_MODEL_ENV_VAR) or DEFAULT_EMBED_MODEL
    fallback_model = os.environ.get(OLLAMA_FALLBACK_MODEL_ENV_VAR) or None
    return AIConfig(
        base_url=base_url, chat_model=chat_model, embed_model=embed_model, fallback_model=fallback_model
    )


def _get_client(config: AIConfig) -> Any:
    """Crea el cliente oficial de la librería `ollama`. Import perezoso: no
    es una dependencia obligatoria del núcleo de escaneo."""
    try:
        import ollama
    except ImportError as exc:  # pragma: no cover - depende del entorno
        raise AIAnalyzerError(
            "El paquete 'ollama' no está instalado. Ejecuta "
            "'pip install -r requirements.txt' e inténtalo de nuevo."
        ) from exc

    # Timeout generoso: por defecto la librería 'ollama' hereda el timeout
    # corto de httpx (~5s), insuficiente para la PRIMERA petición cuando
    # el modelo (varios GB) todavía no está cargado en memoria. Sin esto,
    # se obtiene el mismo mensaje "Failed to connect to Ollama..." que un
    # fallo de conexión real, aunque Ollama esté perfectamente disponible.
    return ollama.Client(
        host=config.base_url,
        timeout=float(os.environ.get("OLLAMA_TIMEOUT_SECONDS", OLLAMA_CLIENT_TIMEOUT_SECONDS)),
    )


def _list_installed_chat_models(client: Any, embed_model: str) -> List[str]:
    """Consulta a Ollama qué modelos hay descargados localmente (equivalente
    a `ollama list`), para poder cambiar automáticamente a uno de ellos si
    el modelo configurado no está instalado. Excluye el modelo de embeddings
    (no sirve para chat) y nunca lanza: si algo falla, devuelve lista vacía.
    """
    try:
        response = client.list()
        raw_models = response.get("models") if isinstance(response, dict) else getattr(response, "models", [])
        names = []
        for m in raw_models or []:
            name = m.get("name") or m.get("model") if isinstance(m, dict) else getattr(m, "model", None)
            if name and embed_model not in name:
                names.append(name)
        return names
    except Exception:  # noqa: BLE001 - esto es un "mejor esfuerzo", nunca crítico
        return []


def _report_schema() -> dict:
    """Esquema JSON del Informe Ejecutivo (Pydantic si está disponible, o
    un esquema JSON equivalente escrito a mano como respaldo)."""
    try:
        from pydantic import BaseModel

        class Finding(BaseModel):
            title: str
            severity: str
            business_impact: str
            technical_explanation: str
            remediation_steps: List[str]
            code_snippet: str

        class ExecutiveReport(BaseModel):
            executive_summary: str
            overall_risk_level: str
            findings: List[Finding]
            quick_wins: List[str]

        return ExecutiveReport.model_json_schema()
    except ImportError:  # pragma: no cover - respaldo si falta pydantic
        return {
            "type": "object",
            "properties": {
                "executive_summary": {"type": "string"},
                "overall_risk_level": {"type": "string"},
                "findings": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "title": {"type": "string"},
                            "severity": {"type": "string"},
                            "business_impact": {"type": "string"},
                            "technical_explanation": {"type": "string"},
                            "remediation_steps": {"type": "array", "items": {"type": "string"}},
                            "code_snippet": {"type": "string"},
                        },
                        "required": ["title", "severity"],
                    },
                },
                "quick_wins": {"type": "array", "items": {"type": "string"}},
            },
            "required": ["executive_summary", "overall_risk_level", "findings"],
        }


def _clean_model_json(raw_content: Optional[str]) -> str:
    """Limpia envoltorios habituales que algunos modelos locales añaden
    pese a la instrucción de responder solo JSON: bloques de código
    Markdown (```json ... ``` o ``` ... ```) y espacios en blanco
    alrededor. Sin esto, un JSON por lo demás válido falla al parsear
    solo por los backticks que lo rodean.
    """
    if not raw_content:
        return raw_content or ""
    text = raw_content.strip()
    if text.startswith("```"):
        text = text.split("\n", 1)[1] if "\n" in text else text[3:]
        if text.rstrip().endswith("```"):
            text = text.rstrip()[:-3]
    return text.strip()


def _friendly_error_message(exc: Exception, config: AIConfig, model: str) -> str:
    """Traduce errores comunes de Ollama a un mensaje accionable."""
    text = str(exc).lower()
    if "connection" in text or "refused" in text or "timed out" in text or "timeout" in text:
        return (
            f"No se pudo conectar con Ollama en {config.base_url}. Verifica que Ollama esté "
            "en marcha: abre Ollama Desktop, o ejecuta 'ollama serve' en una terminal. "
            f"Si Ollama corre en otra máquina/contenedor, configura {OLLAMA_URL_ENV_VAR} en tu .env."
        )
    if "not found" in text or "404" in text or "no such model" in text:
        return (
            f"El modelo '{model}' no está descargado en Ollama. Descárgalo con "
            f"'ollama pull {model}', o configura {OLLAMA_CHAT_MODEL_ENV_VAR} con un modelo "
            "que ya tengas instalado (revisa 'ollama list')."
        )
    return f"Error al consultar Ollama: {exc}"


def get_embedding(text: str, model: Optional[str] = None) -> Optional[List[float]]:
    """Genera un embedding con el modelo de Ollama configurado (por defecto
    nomic-embed-text). Devuelve None si Ollama/el modelo no está disponible,
    para que las funciones que lo usan (vector_db.py) puedan degradar con
    elegancia en vez de fallar. Ver get_embedding_verbose() si necesitas
    además el motivo exacto del fallo."""
    embedding, _reason = get_embedding_verbose(text, model)
    return embedding


def get_embedding_verbose(text: str, model: Optional[str] = None) -> tuple[Optional[List[float]], Optional[str]]:
    """Como get_embedding(), pero además devuelve el motivo del fallo (o
    None si tuvo éxito) como segundo valor, para que quien llama pueda
    mostrar un mensaje accionable (p. ej. en la interfaz web) sin tener
    que rebuscar en los logs del servidor/contenedor.

    Ollama tiene DOS APIs de embeddings: la antigua `/api/embeddings`
    (método `client.embeddings(model=, prompt=)`, respuesta
    `{"embedding": [...]}`) está deprecada en favor de la nueva
    `/api/embed` (método `client.embed(model=, input=)`, respuesta
    `{"embeddings": [[...]]}`, en plural porque admite lote). Se prueba
    primero la API nueva y, si la librería instalada no la tiene o falla,
    se cae automáticamente a la antigua — para no depender de qué versión
    exacta de la librería `ollama` tenga instalada cada usuario.
    """
    config = _load_config()
    embed_model = model or config.embed_model

    try:
        client = _get_client(config)
    except AIAnalyzerError as exc:
        utils.warning(str(exc))
        return None, str(exc)

    last_error: Optional[Exception] = None

    # 1) API actual: client.embed(model=, input=) -> {"embeddings": [[...]]}
    try:
        response = client.embed(model=embed_model, input=text)
        embeddings = response.get("embeddings") if isinstance(response, dict) else getattr(response, "embeddings", None)
        if embeddings:
            return list(embeddings[0]), None
        last_error = AIAnalyzerError("client.embed() no devolvió ningún vector")
    except AttributeError as exc:
        # Versión de la librería 'ollama' sin client.embed(): prueba la API legacy.
        last_error = exc
    except Exception as exc:  # noqa: BLE001
        last_error = exc

    # 2) Respaldo: API legacy client.embeddings(model=, prompt=) -> {"embedding": [...]}
    try:
        response = client.embeddings(model=embed_model, prompt=text)
        embedding = response.get("embedding") if isinstance(response, dict) else getattr(response, "embedding", None)
        if embedding:
            return list(embedding), None
        last_error = AIAnalyzerError("client.embeddings() no devolvió ningún vector")
    except Exception as exc:  # noqa: BLE001
        last_error = exc

    reason = str(last_error) if last_error else "motivo desconocido"
    # "model not found"/404 es, con diferencia, la causa más habitual en
    # despliegues Docker: el modelo de chat (llama3.1) se descargó bien
    # pero el de embeddings (nomic-embed-text) no llegó a completarse en
    # el volumen de Ollama del contenedor (son dos 'ollama pull' distintos
    # en ollama-init, y uno puede fallar sin que el otro se entere).
    lower_reason = reason.lower()
    if "not found" in lower_reason or "404" in lower_reason or "no such model" in lower_reason:
        reason = (
            f"el modelo de embeddings '{embed_model}' no está disponible en Ollama "
            f"({reason}). Si usas el docker-compose, compruébalo con: "
            f"'docker exec shopiscan_ollama ollama list' (OJO: es un volumen distinto "
            f"al de tu Ollama local, aunque 'ollama list' en tu máquina sí lo muestre). "
            f"Si falta, descárgalo con: 'docker exec shopiscan_ollama ollama pull {embed_model}'."
        )

    utils.warning(f"No se pudo generar el embedding con Ollama ({embed_model}): {reason}")
    return None, reason


def generate_executive_report(
    scan_data: dict,
    model: Optional[str] = None,
    similar_findings: Optional[List[dict]] = None,
) -> Optional[dict]:
    """Envía los resultados del escaneo a Ollama y devuelve el Informe
    Ejecutivo de Riesgo estructurado.

    `similar_findings` es opcional: hallazgos históricos similares
    recuperados de PostgreSQL+pgvector (ver vector_db.py), que se añaden
    como contexto adicional al prompt si están disponibles (patrón
    recurrente entre tiendas, RAG-lite).

    Devuelve None si el análisis falla por cualquier motivo: la
    herramienta debe seguir siendo útil sin este módulo (escaneo técnico
    puro), nunca depender de Ollama para funcionar.
    """
    utils.section("Análisis con Inteligencia Artificial (Ollama, 100% local)")

    config = _load_config(model)

    try:
        client = _get_client(config)
    except AIAnalyzerError as exc:
        utils.warning(str(exc))
        utils.warning("Saltando el análisis con IA. El escaneo técnico sigue siendo válido.")
        return None

    data_context = json.dumps(scan_data, indent=2, ensure_ascii=False)

    similar_context = ""
    if similar_findings:
        lines = [
            f"  - {f.get('title')} (severidad {f.get('severity')}, similitud {f.get('similarity', 0):.2f})"
            for f in similar_findings
        ]
        similar_context = (
            "\nHallazgos históricos similares vistos en otros escaneos (contexto de "
            "patrones recurrentes, vía búsqueda vectorial en PostgreSQL+pgvector):\n"
            + "\n".join(lines)
            + "\n"
        )

    prompt = EXECUTIVE_REPORT_PROMPT.format(data_context=data_context, similar_findings_context=similar_context)
    schema = _report_schema()

    model_chain = config.model_chain()
    last_error: Optional[Exception] = None
    auto_discovery_attempted = False
    chain_index = 0

    while chain_index < len(model_chain):
        current_model = model_chain[chain_index]
        if chain_index == 0:
            utils.info(f"Modelo: {current_model} (Ollama en {config.base_url})")
        else:
            utils.warning(f"Probando con el modelo de respaldo: {current_model}")

        utils.info(f"Generando Informe Ejecutivo de Riesgo con {current_model}...")

        for response_format in (schema, "json"):
            try:
                response = client.chat(
                    model=current_model,
                    messages=[
                        {"role": "system", "content": SYSTEM_PROMPT},
                        {"role": "user", "content": prompt},
                    ],
                    format=response_format,
                    options={
                        "temperature": 0.2,
                        # Sin esto, algunos modelos locales cortan la
                        # respuesta a medio JSON (sobre todo con muchos
                        # hallazgos), lo que produce "JSON inválido" no
                        # porque el modelo se equivoque, sino porque la
                        # respuesta se trunca antes de cerrar todas las
                        # llaves/corchetes. 4096 da margen de sobra para
                        # un informe completo.
                        "num_predict": 4096,
                    },
                )
                raw_content = response["message"]["content"] if isinstance(response, dict) else response.message.content
                report = json.loads(_clean_model_json(raw_content))
                report["_model_used"] = current_model
                utils.success(f"Informe Ejecutivo de Riesgo generado correctamente con {current_model}.")
                return report
            except json.JSONDecodeError:
                utils.error("La IA no devolvió un JSON válido. Reintenta o revisa el modelo usado.")
                continue  # prueba el siguiente response_format (json "suelto") antes de rendirse
            except Exception as exc:  # noqa: BLE001 - errores de red/API son variados y no fatales
                last_error = exc
                is_schema_related = "format" in str(exc).lower() or "schema" in str(exc).lower()
                if response_format != "json" and is_schema_related:
                    # Algunos modelos/versiones de Ollama no soportan un JSON
                    # Schema completo en `format`: reintenta con el modo
                    # "json" simple (sin schema) antes de cambiar de modelo.
                    continue
                break  # error no relacionado con el formato: no insistas con este modelo

        chain_index += 1

        # Si se acabó la cadena configurada y el último error indica que el
        # modelo no está instalado, busca UNA vez qué modelos SÍ hay
        # disponibles localmente (equivalente a 'ollama list') y pruébalos
        # automáticamente antes de rendirte del todo. Así, si el usuario ya
        # tiene cualquier otro modelo descargado, ShopiScan lo usa sin que
        # haga falta configurar nada a mano.
        if chain_index >= len(model_chain) and not auto_discovery_attempted and last_error is not None:
            auto_discovery_attempted = True
            text = str(last_error).lower()
            if "not found" in text or "404" in text or "no such model" in text:
                utils.warning("El modelo configurado no está instalado; buscando otros modelos disponibles en Ollama...")
                discovered = _list_installed_chat_models(client, config.embed_model)
                new_models = [m for m in discovered if m not in model_chain]
                if new_models:
                    utils.info(f"Modelos instalados encontrados, se probarán automáticamente: {', '.join(new_models)}")
                    model_chain.extend(new_models)
                else:
                    utils.warning(
                        "No se encontró ningún modelo de chat instalado en Ollama. "
                        "Descarga uno con 'ollama pull <modelo>' (p. ej. 'ollama pull llama3.2')."
                    )

    if last_error is not None:
        utils.error(_friendly_error_message(last_error, config, model_chain[-1]))
    return None


def print_executive_report(report: dict) -> None:
    """Imprime en consola, con formato y color, el Informe Ejecutivo de Riesgo."""
    from colorama import Fore, Style

    from .utils import _ORANGE

    risk = report.get("overall_risk_level", "DESCONOCIDO")
    risk_color = {
        "CRÍTICO": Fore.RED,
        "ALTO": _ORANGE,
        "MEDIO": Fore.YELLOW,
        "BAJO": Fore.GREEN,
    }.get(risk, Fore.WHITE)

    utils.section("INFORME EJECUTIVO DE RIESGO (IA)")
    print(f"Riesgo general: {risk_color}{risk}{Style.RESET_ALL}")

    summary = report.get("executive_summary")
    if summary:
        print(f"\n{Fore.CYAN}Resumen ejecutivo:{Style.RESET_ALL}\n{summary}")

    quick_wins = report.get("quick_wins", [])
    if quick_wins:
        print(f"\n{Fore.CYAN}Quick wins (prioridad esta semana):{Style.RESET_ALL}")
        for i, item in enumerate(quick_wins, 1):
            print(f"  {i}. {item}")

    findings = report.get("findings", [])
    if not findings:
        utils.info("La IA no reportó hallazgos adicionales.")
        return

    for finding in findings:
        severity = finding.get("severity", "N/A")
        color = utils.severity_color(severity)
        print(f"\n{color}[{severity}] {finding.get('title', 'Hallazgo')}{Style.RESET_ALL}")
        print(f"  > Impacto de negocio: {finding.get('business_impact', '-')}")
        print(f"  > Explicación técnica: {finding.get('technical_explanation', '-')}")

        steps = finding.get("remediation_steps") or []
        if steps:
            print(f"  > {Fore.YELLOW}Remediación:{Style.RESET_ALL}")
            for i, step in enumerate(steps, 1):
                print(f"      {i}. {step}")

        snippet = finding.get("code_snippet")
        if snippet:
            print(f"  > {Fore.YELLOW}Snippet sugerido:{Style.RESET_ALL}")
            for line in snippet.splitlines():
                print(f"      {line}")
