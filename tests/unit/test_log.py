from civicshield.log import REDACTED, redact_processor


def test_redacts_sensitive_keys_and_values() -> None:
    event = {
        "event": "login",
        "password": "hunter2",
        "headers": {"Authorization": "Bearer abc", "Accept": "text/html"},
        "detail": "found civicshield-verification=abc123 in TXT",
    }
    out = redact_processor(None, "info", event)
    assert out["password"] == REDACTED
    assert out["headers"]["Authorization"] == REDACTED
    assert out["headers"]["Accept"] == "text/html"
    assert "abc123" not in out["detail"]
