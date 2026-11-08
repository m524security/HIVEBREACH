"""Load and query the compliance framework mapping."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

logger = logging.getLogger("hivebreach.governance.compliance")


class ComplianceMapper:
    """Maps security testing findings to compliance framework controls.

    Loads the framework_map.yaml and provides query methods
    for SOC2, PCI-DSS, ISO 27001, and NIST 800-53 controls.
    """

    def __init__(self, map_path: Optional[Path] = None) -> None:
        self.map_path = map_path or Path(__file__).parent / "framework-map.yaml"
        self._raw: Dict[str, Any] = {}
        self._frameworks: Dict[str, Any] = {}
        self._loaded = False

    def load_map(self) -> Dict[str, Any]:
        """Load the compliance map from YAML and return the full dict."""
        if not self.map_path.exists():
            logger.warning("Compliance map not found at %s", self.map_path)
            return {}

        with open(self.map_path, "r", encoding="utf-8") as f:
            self._raw = yaml.safe_load(f)

        frameworks = self._raw.get("framework_map", {}).copy()
        frameworks.pop("version", None)
        frameworks.pop("last_updated", None)
        frameworks.pop("finding_type_mapping", None)
        self._frameworks = frameworks
        self._loaded = True

        logger.info(
            "Loaded compliance map: %d frameworks, version %s",
            len(self._frameworks),
            self._raw.get("framework_map", {}).get("version", "unknown"),
        )
        return self._raw

    def get_controls_for_framework(self, name: str) -> List[Dict[str, Any]]:
        """Return all control entries for a named framework.

        Args:
            name: Framework key (soc2, pci_dss, iso_27001, nist_800_53).

        Returns:
            List of {control_id, description, finding_types} dicts.
        """
        if not self._loaded:
            self.load_map()

        framework = self._frameworks.get(name)
        if framework is None:
            return []

        controls: List[Dict[str, Any]] = []
        container = framework.get("controls") or framework.get("requirements") or {}
        for ctrl_id, ctrl_data in container.items():
            controls.append({
                "control_id": ctrl_id,
                "description": ctrl_data.get("description", ""),
                "finding_types": ctrl_data.get("finding_types", []),
            })

        return controls

    def get_coverage_summary(self) -> Dict[str, Any]:
        """Return per-framework coverage summary.

        Returns:
            {framework_name: {total_controls, covered_control_ids, ...}}
        """
        if not self._loaded:
            self.load_map()

        summary: Dict[str, Any] = {}
        all_findings = self._raw.get("framework_map", {}).get("finding_type_mapping", {})

        for fw_name, fw_data in self._frameworks.items():
            container = fw_data.get("controls") or fw_data.get("requirements") or {}
            ctrl_ids = list(container.keys())
            display = fw_data.get("display_name", fw_name)

            mapped_in_reverse = set()
            for finding_type, mappings in all_findings.items():
                if fw_name in mappings:
                    mapped_in_reverse.update(mappings[fw_name])

            summary[fw_name] = {
                "display_name": display,
                "total_controls": len(ctrl_ids),
                "control_ids": ctrl_ids,
                "controls_with_reverse_mapping": sorted(mapped_in_reverse),
            }

        return summary

    def get_gaps(self) -> List[Dict[str, str]]:
        """Return controls that have no finding_type mapping (uncovered).

        A gap is a control defined in the forward map that does not appear
        in the reverse *finding_type_mapping* section.
        """
        if not self._loaded:
            self.load_map()

        gaps: List[Dict[str, str]] = []
        all_findings = self._raw.get("framework_map", {}).get("finding_type_mapping", {})

        mapped_controls: Dict[str, set] = {}
        for finding_type, mappings in all_findings.items():
            for fw_name, ctrl_list in mappings.items():
                if fw_name not in mapped_controls:
                    mapped_controls[fw_name] = set()
                mapped_controls[fw_name].update(ctrl_list)

        for fw_name, fw_data in self._frameworks.items():
            container = fw_data.get("controls") or fw_data.get("requirements") or {}
            for ctrl_id, ctrl_data in container.items():
                covered = ctrl_id in mapped_controls.get(fw_name, set())
                if not covered:
                    gaps.append({
                        "framework": fw_name,
                        "control_id": ctrl_id,
                        "description": ctrl_data.get("description", ""),
                    })

        return gaps
