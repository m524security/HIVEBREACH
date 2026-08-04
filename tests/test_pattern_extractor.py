from __future__ import annotations

import json
import re
from dataclasses import dataclass, field

import pytest
from typing import Any, Dict, List, Optional


@dataclass
class FindingPattern:
    name: str
    severity: str
    confidence: float
    description: str
    evidence: Dict[str, Any] = field(default_factory=dict)


class PatternExtractor:
    def __init__(self):
        self._patterns: List[FindingPattern] = []

    def extract_from_logs(self, log_content: str) -> List[FindingPattern]:
        patterns: List[FindingPattern] = []
        lines = log_content.strip().split("\n")
        for line in lines:
            line = line.strip()
            if not line:
                continue
            try:
                parsed = json.loads(line)
                if isinstance(parsed, dict) and "finding" in parsed:
                    f = parsed["finding"]
                    patterns.append(FindingPattern(
                        name=f.get("name", "Unknown"),
                        severity=f.get("severity", "info"),
                        confidence=f.get("confidence", 0.0),
                        description=f.get("description", ""),
                        evidence=f.get("evidence", {}),
                    ))
            except (json.JSONDecodeError, TypeError):
                finding = self._parse_plain_text(line)
                if finding:
                    patterns.append(finding)
        return patterns

    def _parse_plain_text(self, line: str) -> Optional[FindingPattern]:
        severity_pattern = r"\[(CRITICAL|HIGH|MEDIUM|LOW|INFO)\]"
        sev_match = re.search(severity_pattern, line, re.IGNORECASE)
        severity = sev_match.group(1).lower() if sev_match else "info"

        name_match = re.search(r"(?:Finding|Vulnerability|Issue)[:\s]+(.+?)(?:\[|$)", line, re.IGNORECASE)
        name = name_match.group(1).strip() if name_match else line[:60]

        if sev_match or name_match:
            return FindingPattern(
                name=name,
                severity=severity,
                confidence=0.5,
                description=line,
                evidence={"raw": line},
            )
        return None

    def extract_json_findings(self, text: str) -> List[FindingPattern]:
        patterns: List[FindingPattern] = []
        json_blocks = re.findall(r'```(?:json)?\s*([\s\S]*?)```', text)
        for block in json_blocks:
            try:
                data = json.loads(block)
                if isinstance(data, list):
                    for item in data:
                        patterns.append(self._dict_to_pattern(item))
                elif isinstance(data, dict):
                    patterns.append(self._dict_to_pattern(data))
            except json.JSONDecodeError:
                pass
        return patterns

    def _dict_to_pattern(self, d: Dict[str, Any]) -> FindingPattern:
        return FindingPattern(
            name=d.get("title", d.get("name", "Unknown")),
            severity=d.get("severity", "info"),
            confidence=d.get("confidence", 0.5),
            description=d.get("description", ""),
            evidence=d.get("evidence", {}),
        )


@pytest.fixture
def extractor():
    return PatternExtractor()


class TestPatternExtractor:
    def test_pattern_extraction_from_logs(self, extractor):
        log = json.dumps({
            "finding": {
                "name": "Open SSH Port",
                "severity": "high",
                "confidence": 0.95,
                "description": "Port 22 is open on target",
                "evidence": {"port": 22},
            }
        })
        patterns = extractor.extract_from_logs(log)
        assert len(patterns) == 1
        assert patterns[0].name == "Open SSH Port"
        assert patterns[0].severity == "high"
        assert patterns[0].confidence == 0.95


class TestEmptyLogHandling:
    def test_empty_log_handling(self, extractor):
        patterns = extractor.extract_from_logs("")
        assert patterns == []

    def test_whitespace_only_log(self, extractor):
        patterns = extractor.extract_from_logs("   \n  \n  ")
        assert patterns == []

    def test_log_with_only_newlines(self, extractor):
        patterns = extractor.extract_from_logs("\n\n\n")
        assert patterns == []


class TestMultipleFindings:
    def test_multiple_finding_patterns(self, extractor):
        log = "\n".join([
            json.dumps({"finding": {"name": "SQLi", "severity": "critical", "confidence": 0.9}}),
            json.dumps({"finding": {"name": "XSS", "severity": "medium", "confidence": 0.7}}),
            json.dumps({"finding": {"name": "Open Port", "severity": "low", "confidence": 0.5}}),
        ])
        patterns = extractor.extract_from_logs(log)
        assert len(patterns) == 3
        assert patterns[0].name == "SQLi"
        assert patterns[1].name == "XSS"
        assert patterns[2].name == "Open Port"

    def test_extract_json_findings_from_code_blocks(self, extractor):
        text = (
            "Some analysis text...\n"
            "```json\n"
            '[{"title": "RCE", "severity": "critical", "confidence": 0.99}]\n'
            "```\n"
            "More text\n"
            "```json\n"
            '{"title": "LFI", "severity": "high", "confidence": 0.85}\n'
            "```\n"
        )
        patterns = extractor.extract_json_findings(text)
        assert len(patterns) == 2
        names = [p.name for p in patterns]
        assert "RCE" in names
        assert "LFI" in names

    def test_mixed_finding_and_non_finding_lines(self, extractor):
        log = "\n".join([
            "INFO: Starting scan on target",
            json.dumps({"finding": {"name": "XSS", "severity": "medium", "confidence": 0.75}}),
            "DEBUG: Connection established",
            json.dumps({"finding": {"name": "SQLi", "severity": "high", "confidence": 0.85}}),
            "ERROR: Timeout on port 8080",
        ])
        patterns = extractor.extract_from_logs(log)
        assert len(patterns) == 2


class TestPlainTextParsing:
    def test_plain_text_severity_parsing(self, extractor):
        line = "[CRITICAL] Finding: Remote Code Execution in Apache"
        patterns = extractor.extract_from_logs(line)
        assert len(patterns) == 1
        assert patterns[0].severity == "critical"

    def test_plain_text_without_severity(self, extractor):
        line = "Regular log line with no finding"
        patterns = extractor.extract_from_logs(line)
        assert len(patterns) == 0

    def test_plain_text_vulnerability_keyword(self, extractor):
        line = "Vulnerability: SQL Injection in login form [HIGH]"
        patterns = extractor.extract_from_logs(line)
        assert len(patterns) == 1


class TestInvalidJson:
    def test_invalid_json_line(self, extractor):
        log = "not json at all { broken"
        patterns = extractor.extract_from_logs(log)
        assert patterns == []

    def test_malformed_json_finding(self, extractor):
        log = json.dumps({"finding": {"name": "Good"}}) + "\n" + "{not json"
        patterns = extractor.extract_from_logs(log)
        assert len(patterns) == 1
        assert patterns[0].name == "Good"


class TestConfidence:
    def test_confidence_default_for_plain_text(self, extractor):
        line = "[HIGH] Finding: Something bad"
        patterns = extractor.extract_from_logs(line)
        assert patterns[0].confidence == 0.5
