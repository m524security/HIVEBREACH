"""ECC system prompt optimization: compress, deduplicate, and truncate."""

from __future__ import annotations

import logging
import re
from typing import Any

logger = logging.getLogger(__name__)

REDUNDANT_PATTERNS: list[tuple[str, str]] = [
    (r"(?i)(?:you are|you're) (?:an? )?(?:AI |)(?:assistant|model|agent)", ""),
    (r"(?i)as an (?:AI |)language model", ""),
    (r"(?i)i (?:(?:can|will) )?hereby", "I"),
    (r"(?i)with that in mind", ""),
    (r"(?i)it is worth noting that", ""),
    (r"(?i)it (?:should|must) be noted that", ""),
    (r"(?i)in order to", "to"),
]

EXAMPLE_HEADERS = [
    re.compile(r"(?i)^(?:example|sample|demo) \d+:?$", re.MULTILINE),
    re.compile(r"(?i)^input:?$", re.MULTILINE),
    re.compile(r"(?i)^output:?$", re.MULTILINE),
]

SECTIONS = ["instructions", "context", "examples", "constraints", "rules", "tools", "output_format"]


class PromptSlimmer:
    """Optimise system prompts by removing redundancy, compressing examples, and truncating by priority."""

    def __init__(self, max_tokens: int = 8000) -> None:
        self.max_tokens = max_tokens
        self._token_estimate_cache: dict[str, int] = {}

    def slim(self, prompt: str, preserve_sections: list[str] | None = None) -> str:
        preserve = set(preserve_sections or ["instructions", "rules"])

        result = self._remove_redundant_phrases(prompt)
        result = self._compress_examples(result)
        result = self._truncate_by_priority(result, preserve)

        original_tokens = self._estimate_tokens(prompt)
        slimmed_tokens = self._estimate_tokens(result)
        savings = original_tokens - slimmed_tokens

        if savings > 0:
            logger.info("Prompt slimmed: %d -> %d tokens (saved %d)", original_tokens, slimmed_tokens, savings)

        return result.strip()

    def _remove_redundant_phrases(self, text: str) -> str:
        for pattern, replacement in REDUNDANT_PATTERNS:
            text = re.sub(pattern, replacement, text)
        text = re.sub(r"\n{3,}", "\n\n", text)
        return text

    def _compress_examples(self, text: str) -> str:
        lines = text.split("\n")
        compressed: list[str] = []
        in_example = False
        example_lines = 0

        for line in lines:
            is_header = any(h.search(line) for h in EXAMPLE_HEADERS)
            if is_header:
                if in_example and example_lines > 6:
                    compressed.append("  ... (example truncated)")
                in_example = True
                example_lines = 0
                compressed.append(line)
            elif in_example:
                example_lines += 1
                if example_lines <= 6:
                    compressed.append(line)
            else:
                compressed.append(line)

        if in_example and example_lines > 6:
            compressed.append("  ... (example truncated)")

        return "\n".join(compressed)

    def _truncate_by_priority(self, text: str, preserve_sections: set[str]) -> str:
        tokens = self._estimate_tokens(text)
        if tokens <= self.max_tokens:
            return text

        sections = self._split_sections(text)
        low_priority = [s for s in sections if s["name"] not in preserve_sections]

        for section in low_priority:
            text = text.replace(section["content"], "")
            tokens = self._estimate_tokens(text)
            if tokens <= self.max_tokens:
                break

        if self._estimate_tokens(text) > self.max_tokens:
            text = self._truncate_middle(text)

        return text

    def _split_sections(self, text: str) -> list[dict[str, Any]]:
        found: list[dict[str, Any]] = []
        for name in SECTIONS:
            pattern = re.compile(rf"(?i)^(?:#+ |##+\s*)?{name}[:\s]*\n(.*?)(?=^#|\Z)", re.MULTILINE | re.DOTALL)
            match = pattern.search(text)
            if match:
                found.append({"name": name, "content": match.group(0)})
        return found

    def _truncate_middle(self, text: str) -> str:
        half = len(text) // 2
        truncation_point = text.rfind("\n", half - 200, half + 200)
        if truncation_point == -1:
            truncation_point = half
        logger.warning("Hard truncating prompt at character %d", truncation_point)
        return text[:truncation_point] + "\n... [truncated] ...\n" + text[truncation_point:]

    def _estimate_tokens(self, text: str) -> int:
        if text in self._token_estimate_cache:
            return self._token_estimate_cache[text]
        tokens = len(text) // 4
        self._token_estimate_cache[text] = tokens
        return tokens
