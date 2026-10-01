"""
notifications.py
------------------
Notificaciones (Slack / email) cuando el score de riesgo EMPEORA entre
escaneos de la misma tienda. Pensado sobre todo para el workflow de
GitHub Actions de escaneo periódico (scheduled-scan.yml), pero funciona
en cualquier ejecución que tenga --no-history desactivado (por defecto).

Ambos canales son opcionales y se activan solo si sus variables de
entorno están configuradas. Si no lo están, este módulo no hace nada: no
es una dependencia dura ni bloquea el escaneo si el envío falla.

Variables de entorno:
  SLACK_WEBHOOK_URL   URL de un "Incoming Webhook" de Slack.
  SMTP_HOST           Host del servidor SMTP (p. ej. smtp.gmail.com).
  SMTP_PORT           Puerto SMTP (por defecto 587, STARTTLS).
  SMTP_USER           Usuario SMTP (opcional según el proveedor).
  SMTP_PASS           Contraseña/App Password SMTP.
  NOTIFY_EMAIL_TO     Dirección de email destino de las alertas.
"""

from __future__ import annotations

import os
import smtplib
from email.mime.text import MIMEText
from typing import Any

import requests

from . import utils

SLACK_WEBHOOK_ENV_VAR = "SLACK_WEBHOOK_URL"
SMTP_HOST_ENV_VAR = "SMTP_HOST"
SMTP_PORT_ENV_VAR = "SMTP_PORT"
SMTP_USER_ENV_VAR = "SMTP_USER"
SMTP_PASS_ENV_VAR = "SMTP_PASS"
NOTIFY_EMAIL_TO_ENV_VAR = "NOTIFY_EMAIL_TO"

REQUEST_TIMEOUT = 10


def _as_dict(comparison: Any) -> dict:
    return comparison.to_dict() if hasattr(comparison, "to_dict") else comparison


def _build_message(url: str, comparison: Any) -> tuple[str, str]:
    """Devuelve (subject, body_texto_plano) para la alerta de regresión."""
    c = _as_dict(comparison)
    delta = c.get("score_delta", 0)
    subject = f"⚠️ ShopiScan: el riesgo de {url} empeoró (+{delta} puntos)"
    lines = [
        f"El score de riesgo de {url} ha empeorado entre escaneos.",
        "",
        f"Score anterior: {c.get('previous_score', 0)}/100 ({c.get('previous_label', '')})",
        f"Score actual:   {c.get('current_score', 0)}/100 ({c.get('current_label', '')})",
        f"Variación:      +{delta} puntos",
    ]
    new_findings = c.get("new_findings", [])
    if new_findings:
        lines.append("")
        lines.append("Hallazgos nuevos:")
        lines.extend(f"  - {f}" for f in new_findings)
    return subject, "\n".join(lines)


def is_configured() -> bool:
    """True si al menos un canal (Slack o email) tiene configuración."""
    has_slack = bool(os.environ.get(SLACK_WEBHOOK_ENV_VAR))
    has_email = bool(os.environ.get(NOTIFY_EMAIL_TO_ENV_VAR) and os.environ.get(SMTP_HOST_ENV_VAR))
    return has_slack or has_email


def notify_score_regression(url: str, comparison: Any, threshold: int = 0) -> None:
    """Envía notificaciones (Slack y/o email) si el score empeoró más de
    `threshold` puntos desde el escaneo anterior.

    No hace nada si ningún canal está configurado, o si el score no
    empeoró lo suficiente. Los fallos de envío se registran como avisos,
    nunca interrumpen el escaneo.
    """
    if comparison is None or not is_configured():
        return

    c = _as_dict(comparison)
    delta = c.get("score_delta", 0)
    if delta <= threshold:
        return

    subject, body = _build_message(url, comparison)

    slack_webhook = os.environ.get(SLACK_WEBHOOK_ENV_VAR)
    if slack_webhook:
        _send_slack(slack_webhook, f"*{subject}*\n```{body}```")

    email_to = os.environ.get(NOTIFY_EMAIL_TO_ENV_VAR)
    if email_to and os.environ.get(SMTP_HOST_ENV_VAR):
        _send_email(email_to, subject, body)


def _send_slack(webhook_url: str, text: str) -> None:
    try:
        resp = requests.post(webhook_url, json={"text": text}, timeout=REQUEST_TIMEOUT)
        if resp.status_code >= 300:
            utils.warning(f"Slack devolvió {resp.status_code} al enviar la notificación.")
        else:
            utils.success("Notificación de Slack enviada (el riesgo ha empeorado).")
    except requests.exceptions.RequestException as exc:
        utils.warning(f"No se pudo enviar la notificación a Slack: {exc}")


def _send_email(to_addr: str, subject: str, body: str) -> None:
    host = os.environ.get(SMTP_HOST_ENV_VAR, "")
    try:
        port = int(os.environ.get(SMTP_PORT_ENV_VAR, "587"))
    except ValueError:
        port = 587
    user = os.environ.get(SMTP_USER_ENV_VAR)
    password = os.environ.get(SMTP_PASS_ENV_VAR)

    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = user or "shopiscan@localhost"
    msg["To"] = to_addr

    try:
        with smtplib.SMTP(host, port, timeout=REQUEST_TIMEOUT) as server:
            server.starttls()
            if user and password:
                server.login(user, password)
            server.sendmail(msg["From"], [to_addr], msg.as_string())
        utils.success(f"Notificación por email enviada a {to_addr} (el riesgo ha empeorado).")
    except (smtplib.SMTPException, OSError) as exc:
        utils.warning(f"No se pudo enviar la notificación por email: {exc}")
