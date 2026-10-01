"""
Pruebas del módulo notifications (alertas Slack/email cuando el score
empeora). No se hace ninguna petición de red real: requests.post y
smtplib.SMTP se mockean.
"""

from unittest.mock import MagicMock, patch

from shopiscan import notifications


class _FakeComparison:
    def __init__(self, delta):
        self._delta = delta

    def to_dict(self):
        return {
            "score_delta": self._delta,
            "previous_score": 10,
            "current_score": 10 + self._delta,
            "previous_label": "BAJO",
            "current_label": "MEDIO",
            "new_findings": ["Nuevo hallazgo"],
            "resolved_findings": [],
        }


class TestIsConfigured:
    def test_false_when_nothing_set(self, monkeypatch):
        monkeypatch.delenv("SLACK_WEBHOOK_URL", raising=False)
        monkeypatch.delenv("NOTIFY_EMAIL_TO", raising=False)
        monkeypatch.delenv("SMTP_HOST", raising=False)
        assert notifications.is_configured() is False

    def test_true_when_slack_set(self, monkeypatch):
        monkeypatch.setenv("SLACK_WEBHOOK_URL", "https://hooks.slack.com/x")
        assert notifications.is_configured() is True


class TestNotifyScoreRegression:
    def test_noop_without_configuration(self, monkeypatch):
        monkeypatch.delenv("SLACK_WEBHOOK_URL", raising=False)
        monkeypatch.delenv("NOTIFY_EMAIL_TO", raising=False)
        with patch("shopiscan.notifications.requests.post") as mock_post:
            notifications.notify_score_regression("https://tienda.com", _FakeComparison(20))
            mock_post.assert_not_called()

    def test_noop_when_score_improved(self, monkeypatch):
        monkeypatch.setenv("SLACK_WEBHOOK_URL", "https://hooks.slack.com/x")
        with patch("shopiscan.notifications.requests.post") as mock_post:
            notifications.notify_score_regression("https://tienda.com", _FakeComparison(-10))
            mock_post.assert_not_called()

    def test_sends_slack_when_score_worsens(self, monkeypatch):
        monkeypatch.setenv("SLACK_WEBHOOK_URL", "https://hooks.slack.com/x")
        fake_response = MagicMock(status_code=200)
        with patch("shopiscan.notifications.requests.post", return_value=fake_response) as mock_post:
            notifications.notify_score_regression("https://tienda.com", _FakeComparison(15))
            mock_post.assert_called_once()
            args, kwargs = mock_post.call_args
            assert "hooks.slack.com" in args[0]
            assert "empeoró" in kwargs["json"]["text"]

    def test_respects_threshold(self, monkeypatch):
        monkeypatch.setenv("SLACK_WEBHOOK_URL", "https://hooks.slack.com/x")
        with patch("shopiscan.notifications.requests.post") as mock_post:
            notifications.notify_score_regression("https://tienda.com", _FakeComparison(5), threshold=10)
            mock_post.assert_not_called()

    def test_sends_email_when_configured(self, monkeypatch):
        monkeypatch.setenv("NOTIFY_EMAIL_TO", "alguien@ejemplo.com")
        monkeypatch.setenv("SMTP_HOST", "smtp.ejemplo.com")
        monkeypatch.setenv("SMTP_PORT", "587")
        fake_smtp = MagicMock()
        with patch("shopiscan.notifications.smtplib.SMTP") as mock_smtp_cls:
            mock_smtp_cls.return_value.__enter__.return_value = fake_smtp
            notifications.notify_score_regression("https://tienda.com", _FakeComparison(15))
            fake_smtp.sendmail.assert_called_once()
