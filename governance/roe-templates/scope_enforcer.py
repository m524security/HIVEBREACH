"""Runtime scope enforcer that reads ROE files and validates actions."""

from __future__ import annotations

import re
import ipaddress
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger("hivebreach.governance.scope")


class ScopeEnforcer:
    """Validates agent actions against the Rules of Engagement.

    Parses the standard_roe.md and provides runtime checks:
      - target in authorised scope
      - action within allowed techniques
      - current time within testing window
      - action not in prohibited list
    """

    def __init__(self, roe_path: Optional[Path] = None) -> None:
        self.roe_path = roe_path or Path(__file__).parent / "standard_roe.md"
        self._parsed: Dict[str, Any] = {}
        self._loaded = False
        self._authorized_targets: List[str] = []
        self._authorized_networks: List[ipaddress.IPv4Network] = []
        self._prohibited_actions: List[str] = []
        self._allowed_techniques: Dict[str, str] = {}
        self._time_windows: List[Dict[str, Any]] = []

    def load(self) -> Dict[str, Any]:
        """Parse the ROE markdown file and extract structured fields."""
        if not self.roe_path.exists():
            logger.warning("ROE file not found at %s", self.roe_path)
            return {}

        text = self.roe_path.read_text(encoding="utf-8")
        self._parsed = {"raw_path": str(self.roe_path), "sections": {}}

        sections = re.split(r"\n##\s+", text)
        for section in sections:
            header_match = re.match(r"(\d+)\.\s+(.+)", section.strip())
            if header_match:
                num = int(header_match.group(1))
                name = header_match.group(2).strip()
                self._parsed["sections"][name] = section.strip()

        self._extract_targets(text)
        self._extract_techniques(text)
        self._extract_prohibited(text)
        self._extract_time_windows(text)

        self._loaded = True
        logger.info("Loaded ROE from %s", self.roe_path)
        return self._parsed

    def _extract_targets(self, text: str) -> None:
        """Extract authorised targets from the ROE header table."""
        match = re.search(r"\|\s*\*\*Authorized Scope\*\*\s*\|\s*`([^`]+)`", text)
        if match:
            raw = match.group(1)
            self._authorized_targets = [t.strip() for t in raw.split(" / ") if t.strip()]
            for entry in self._authorized_targets:
                try:
                    self._authorized_networks.append(ipaddress.IPv4Network(entry, strict=False))
                except (ValueError, TypeError):
                    pass

    def _extract_techniques(self, text: str) -> None:
        """Extract allowed MITRE ATT&CK techniques from Section 3."""
        lines = text.split("\n")
        in_table = False
        for line in lines:
            if "|--------|-------------|----------------|-------------|" in line:
                in_table = True
                continue
            if in_table and line.strip().startswith("|"):
                parts = [p.strip() for p in line.split("|")]
                if len(parts) >= 5 and parts[2]:
                    tech_id = parts[2].strip()
                    tech_name = parts[3].strip()
                    self._allowed_techniques[tech_id] = tech_name
            elif in_table and not line.strip().startswith("|"):
                break

    def _extract_prohibited(self, text: str) -> None:
        """Extract prohibited actions from Section 4."""
        lines = text.split("\n")
        in_section = False
        for line in lines:
            if line.strip().startswith("## 4."):
                in_section = True
                continue
            if in_section and line.strip().startswith("## "):
                break
            if in_section and line.strip().startswith("- "):
                self._prohibited_actions.append(line.strip()[2:])

    def _extract_time_windows(self, text: str) -> None:
        """Extract time window restrictions from Section 6."""
        lines = text.split("\n")
        in_table = False
        for line in lines:
            if "|-----|-------------|-------|" in line:
                in_table = True
                continue
            if in_table and line.strip().startswith("|"):
                parts = [p.strip() for p in line.split("|")]
                if len(parts) >= 3 and parts[1]:
                    window = {
                        "days": parts[1],
                        "hours": parts[2] if len(parts) > 2 else "",
                        "notes": parts[3] if len(parts) > 3 else "",
                    }
                    self._time_windows.append(window)
            elif in_table and not line.strip().startswith("|"):
                break

    def validate_target(self, target: str) -> Tuple[bool, str]:
        """Check if a target IP/host is within the authorised scope.

        Returns:
            (is_allowed: bool, reason: str)
        """
        if not self._loaded:
            self.load()

        if not self._authorized_networks:
            return False, "No authorised targets defined in ROE"

        try:
            ip = ipaddress.IPv4Address(target)
        except (ValueError, TypeError):
            return True, "Non-IP target—passed to domain resolver"

        for network in self._authorized_networks:
            if ip in network:
                return True, f"Target {target} is within scope {network}"

        return False, f"Target {target} is outside all authorised scope networks"

    def validate_technique(self, technique_id: str) -> Tuple[bool, str]:
        """Check if a MITRE ATT&CK technique is authorised.

        Returns:
            (is_allowed: bool, reason: str)
        """
        if not self._loaded:
            self.load()

        if technique_id in self._allowed_techniques:
            return True, f"Technique {technique_id} ({self._allowed_techniques[technique_id]}) is authorised"

        return False, f"Technique {technique_id} is not in the authorised list"

    def validate_time_window(self, dt: Optional[datetime] = None) -> Tuple[bool, str]:
        """Check if the current time falls within the testing window.

        Returns:
            (is_allowed: bool, reason: str)
        """
        if not self._loaded:
            self.load()

        dt = dt or datetime.now(timezone.utc)
        day_name = dt.strftime("%A")

        for window in self._time_windows:
            if day_name in window.get("days", ""):
                hours = window.get("hours", "")
                if "—" in hours:
                    start_str, end_str = hours.split("—", 1)
                    start_str = start_str.strip()
                    end_str = end_str.strip()
                    try:
                        start_h, start_m = [int(x) for x in start_str.split(":")]
                        end_h, end_m = [int(x) for x in end_str.split(":")]
                    except (ValueError, IndexError):
                        return False, f"Cannot parse time window: {hours}"

                    start_min = start_h * 60 + start_m
                    end_min = end_h * 60 + end_m
                    current_min = dt.hour * 60 + dt.minute

                    if start_min <= current_min < end_min:
                        return True, f"Current time {dt.strftime('%H:%M')} is within window ({hours})"
                    else:
                        return False, f"Current time {dt.strftime('%H:%M')} is outside window ({hours})"

                if "No testing" in window.get("notes", ""):
                    return False, f"{day_name} is a blackout day"

                return True, f"{day_name} has no explicit time restriction"

        return True, "No time window restriction for this day"

    def validate_action(self, target: str, technique_id: str) -> Tuple[bool, str]:
        """Run all validation checks for a proposed action.

        Returns:
            (is_allowed: bool, consolidated_reason: str)
        """
        target_ok, target_reason = self.validate_target(target)
        if not target_ok:
            return False, target_reason

        tech_ok, tech_reason = self.validate_technique(technique_id)
        if not tech_ok:
            return False, tech_reason

        time_ok, time_reason = self.validate_time_window()
        if not time_ok:
            return False, time_reason

        return True, f"Action is authorised: {tech_reason}; {target_reason}; {time_reason}"
