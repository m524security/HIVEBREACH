"""Post-scan lifecycle hooks."""

from hooks.post_scan.findings_logger import findings_logger_hook

__all__ = ["findings_logger_hook"]
