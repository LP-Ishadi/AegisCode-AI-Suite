"""Best-effort redaction before model egress and finding persistence."""

import re

PATTERNS = [
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S),
    re.compile(
        r"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|sk-[A-Za-z0-9_-]{20,}|AKIA[A-Z0-9]{16})\b"
    ),
    re.compile(
        r"(?i)(?:api[_-]?key|secret|password|access[_-]?token|auth[_-]?token)\s*[:=]\s*['\"][^'\"\n]{8,}['\"]"
    ),
    re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b"),
]


def redact(text: str) -> str:
    for pattern in PATTERNS:
        text = pattern.sub(lambda m: "[REDACTED]" + "\n" * m.group().count("\n"), text)
    return text


def contains_secret(text: str) -> bool:
    return bool(re.search(r"-----BEGIN [A-Z ]*PRIVATE KEY-----", text)) or any(
        pattern.search(text) for pattern in PATTERNS
    )

# Test marker for import graph and manual review workflow verification.
