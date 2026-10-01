# Contribuir a ShopiScan

Gracias por el interés en contribuir. Esta guía es deliberadamente breve
— el objetivo es que puedas mandar tu primer *pull request* sin fricción.

## Antes de nada: uso ético

ShopiScan es una herramienta de auditoría pasiva para uso autorizado. Si
tu contribución añade una capacidad nueva (un escáner, una integración),
ténlo presente: se aceptan mejoras de detección pasiva y no intrusiva, no
funcionalidad de explotación activa, fuerza bruta o similar — eso se sale
del propósito y del planteamiento ético del proyecto.

## Puesta en marcha para desarrollo

```bash
git clone https://github.com/juanleongalan/shopiscan.git
cd shopiscan
python3 -m venv venv && source venv/bin/activate
pip install -e ".[full,dev]"
pytest tests/ -v
```

Todos los tests deben pasar antes de tu cambio y después de él. La suite
no hace peticiones de red reales (usa mocks), así que corre en segundos.

## Flujo de trabajo

1. Haz un fork del repositorio y crea una rama descriptiva
   (`fix/falso-positivo-xyz`, `feat/nuevo-scanner-abc`).
2. Si corriges un bug, añade primero una prueba que falle reproduciéndolo,
   y luego el fix que la hace pasar — así queda fijado como regresión.
   Varios de los bugs corregidos durante el desarrollo original de
   ShopiScan solo se detectaron escaneando tiendas reales, no con datos
   sintéticos; si tu fix viene de un caso real, un comentario breve
   explicando el escenario ayuda mucho a quien revise el cambio.
3. Sigue el estilo del código existente: tipado con type hints donde
   ya se usa, docstrings breves explicando el *porqué* de una decisión no
   obvia (no solo el *qué*), y nombres de test descriptivos
   (`test_<comportamiento>_<condición>`).
4. Actualiza el `README.md` si tu cambio afecta a una opción de la CLI,
   una variable de entorno, o el comportamiento documentado.
5. Abre el *pull request* con una descripción de qué cambia y por qué.

## Tipos de contribución especialmente bienvenidos

- **Nuevas firmas de "shadow apps"** (`shadow_apps_scanner.py`) — el
  catálogo se ha construido observando patrones reales; si detectas una
  app de Shopify que no está cubierta, es una contribución muy útil.
  Cuidado especial con los falsos positivos: una firma demasiado genérica
  (por ejemplo, un nombre de función de 2-3 caracteres) puede coincidir
  por azar con código minificado de cualquier sitio — revisa el caso de
  estudio del falso positivo de Zendesk documentado en la memoria del
  proyecto antes de añadir una firma nueva, y añade un test que cubra
  tanto el positivo real como el posible falso positivo.
- **Librerías JS adicionales** con CVEs conocidas (`libraries_scanner.py`).
- **Mejoras de seguridad para despliegue en internet** (autenticación,
  límite de tasa, protección SSRF) — ver la sección "Despliegue seguro y
  límites conocidos" del README para el contexto completo.
- **Correcciones de falsos positivos**, siempre con una prueba de
  regresión que demuestre el antes y el después.

## Qué NO es necesario preguntar antes de hacer

Typos, mejoras de documentación, tests adicionales para código ya
existente — adelante directamente con el *pull request*.

## Código de conducta

Sé respetuoso. Las discusiones técnicas pueden ser directas; las
personales, no.
