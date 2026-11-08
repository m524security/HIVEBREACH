"""ECC input/output sanitisation: strip secrets, sanitise paths, validate args."""

from __future__ import annotations

import logging
import os
import re
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

SECRET_PATTERNS: list[re.Pattern] = [
    re.compile(r"(?i)(?:api[_-]?key|apikey|token|secret|password|passwd|credential)\s*[=:]\s*['\"]?[A-Za-z0-9_\-\.]{16,}['\"]?"),
    re.compile(r"(?i)(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}"),
    re.compile(r"(?i)sk-[A-Za-z0-9]{32,}"),
    re.compile(r"(?i)AKIA[0-9A-Z]{16}"),
    re.compile(r"(?i)-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"),
    re.compile(r"(?i)-----BEGIN CERTIFICATE-----"),
]

REDACTION_TEXT = "[REDACTED]"


class Sanitizer:
    """Strip secrets from logs, sanitise file paths, and validate command arguments."""

    @staticmethod
    def strip_secrets(text: str) -> str:
        result = text
        for pattern in SECRET_PATTERNS:
            result = pattern.sub(lambda m: re.sub(r"[A-Za-z0-9_\-\.]{8,}", REDACTION_TEXT, m.group(0)), result)
        return result

    @staticmethod
    def sanitise_path(path: str, base_dir: str | Path | None = None) -> str:
        resolved = Path(path).resolve()
        if base_dir:
            base = Path(base_dir).resolve()
            try:
                resolved.relative_to(base)
            except ValueError:
                logger.warning("Path '%s' is outside base directory '%s'", path, base_dir)
                return str(base)
        return str(resolved)

    @staticmethod
    def validate_command_args(args: list[str]) -> list[dict[str, Any]]:
        issues: list[dict[str, Any]] = []
        for i, arg in enumerate(args):
            # Flag potential injection characters
            if re.search(r'[;&|`$(){}]', arg):
                issues.append({
                    "index": i,
                    "arg": arg[:100],
                    "issue": "Potential shell injection characters detected",
                })
            # Flag environment variable expansion
            if re.search(r'(?<!\$)\$\{?\w+\}?', arg):
                issues.append({
                    "index": i,
                    "arg": arg[:100],
                    "issue": "Environment variable expansion in argument",
                })
            # Flag path traversal
            if arg.startswith("..") or "/../" in arg.replace("\\", "/"):
                issues.append({
                    "index": i,
                    "arg": arg[:100],
                    "issue": "Path traversal attempt",
                })
        return issues

    @staticmethod
    def sanitize_for_log(data: dict[str, Any], sensitive_keys: list[str] | None = None) -> dict[str, Any]:
        sensitive = sensitive_keys or ["password", "token", "secret", "api_key", "api-key", "apikey", "credential"]
        result = dict(data)
        for key in result:
            if any(s in key.lower() for s in sensitive):
                result[key] = REDACTION_TEXT
            elif isinstance(result[key], dict):
                result[key] = Sanitizer.sanitize_for_log(result[key], sensitive)
            elif isinstance(result[key], str):
                result[key] = Sanitizer.strip_secrets(result[key])
        return result

    @staticmethod
    def validate_environment() -> dict[str, Any]:
        issues: list[dict[str, Any]] = []
        env_vars = dict(os.environ)

        for key, value in env_vars.items():
            if any(s in key.lower() for s in ["key", "token", "secret", "password"]):
                if value and len(value) > 8:
                    issues.append({"key": key, "issue": "Sensitive environment variable is set"})

        return {"total_env_vars": len(env_vars), "sensitive_vars_found": len(issues), "issues": issues}
