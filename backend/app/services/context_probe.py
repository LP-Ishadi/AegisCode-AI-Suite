from app.services.redaction import redact


def preview(value: str) -> str:
    return redact(value)
# Test commit to start a new scan.
