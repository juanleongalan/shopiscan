FROM python:3.12-slim

# Evita prompts y mejora los logs de Python en contenedor
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# Instala primero las dependencias (mejor cacheo de capas)
COPY setup.py README.md ./
COPY src ./src

# Instala ShopiScan con los extras de IA, vector y servidor
RUN pip install --upgrade pip && pip install ".[full]"

# Sello de fecha/hora de esta compilación concreta. Se regenera SOLO
# cuando Docker realmente reconstruye esta capa (es decir, cuando el
# código en ./src cambió respecto a la imagen anterior) — si "docker
# compose up -d" reutiliza una imagen vieja sin --build, este valor se
# queda congelado en el momento de la última compilación real. Sirve
# para comprobar en GET /health si el contenedor corre código actualizado.
RUN date -u +"%Y-%m-%dT%H:%M:%SZ" > /app/.build_time

EXPOSE 8000

# Arranca el servidor HTTP (FastAPI + /metrics)
CMD ["shopiscan-server"]
