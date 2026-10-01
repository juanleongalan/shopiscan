# Política de seguridad

## Dos tipos de "seguridad" distintos

Este documento trata sobre **fallos de seguridad en el propio código de
ShopiScan** (por ejemplo, un bug que permitiera ejecutar código arbitrario,
una fuga de credenciales almacenadas, o una vulnerabilidad en cómo se
procesan las respuestas del objetivo escaneado).

No trata sobre **hallazgos que ShopiScan detecta** en una tienda Shopify
(cabeceras ausentes, cookies inseguras, etc.) — eso es el propósito normal
de la herramienta, documentado en el [README](README.md).

## Uso responsable (recordatorio)

ShopiScan es exclusivamente para auditorías autorizadas. Antes de reportar
nada relacionado con el comportamiento de la herramienta frente a un
objetivo real, asegúrate de que tenías autorización explícita para
escanearlo — ver el aviso legal y ético en el README.

## Cómo reportar una vulnerabilidad en ShopiScan

Si encuentras un problema de seguridad en el propio código (no un
hallazgo de una tienda escaneada), repórtalo de forma privada:

1. **No abras un issue público de GitHub** para vulnerabilidades no
   divulgadas todavía — eso expone el problema a cualquiera antes de que
   haya un parche disponible.
2. Usa la función **"Report a vulnerability"** de la pestaña *Security*
   del repositorio en GitHub (GitHub Security Advisories): genera un
   aviso privado visible solo para el mantenedor hasta que se resuelva.
3. Incluye, si es posible: una descripción del problema, pasos para
   reproducirlo, versión afectada, y el impacto potencial.

Se intentará responder en un plazo razonable y, cuando proceda, publicar
un aviso de seguridad (GitHub Security Advisory) y una nueva versión con
el fallo corregido antes de hacer público el detalle técnico.

## Qué se considera dentro de alcance

- Bugs en el motor de escaneo que puedan ser explotados por un **objetivo
  malicioso** contra el propio ShopiScan (por ejemplo, una respuesta HTTP
  diseñada para provocar un comportamiento inesperado, una inyección en el
  procesamiento de HTML/JS, o un path traversal al guardar informes).
- Fugas de credenciales: que un secreto detectado por `secrets_scanner.py`
  se registre sin enmascarar en algún formato de salida, log o base de
  datos.
- Vulnerabilidades en las dependencias directas del proyecto.

## Qué NO se considera un fallo de seguridad de ShopiScan

- Que la interfaz web o la API no tengan autenticación/rate limiting por
  defecto, o que el `docker-compose.yml` no esté endurecido para
  exposición pública a internet — esto es una **limitación conocida y
  documentada**, no un hallazgo nuevo (ver la sección "Despliegue seguro y
  límites conocidos" del README). Si quieres proponer una mejora en esta
  línea, es bienvenida como *pull request* o *issue* normal, no como
  reporte de seguridad privado.
- Comportamiento esperado al escanear un sitio sin autorización — eso es
  responsabilidad de quien ejecuta la herramienta, no un fallo del
  software.
