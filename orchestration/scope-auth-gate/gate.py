"""
scope-auth-gate — Deterministic Scope and Authorization Gate

HiveBreach's single non-negotiable security gate. This module uses NO LLM
calls — it is purely deterministic logic that validates every action against
the Rules of Engagement before any agent executes a delegated task.

If a target, action, or technique is out of scope, the kill-switch engages
and the action is blocked with a detailed rejection message.
"""

from __future__ import annotations

import os
import re
import ipaddress
import fnmatch
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

import yaml

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class ScopeCheckResult(Enum):
    IN_SCOPE = "in_scope"
    OUT_OF_SCOPE = "out_of_scope"
    UNKNOWN = "unknown"
    KILL_SWITCH_ENGAGED = "kill_switch_engaged"


class ActionType(Enum):
    RECON = "recon"
    SCAN = "scan"
    FINGERPRINT = "fingerprint"
    EXPLOIT = "exploit"
    POST_EXPLOIT = "post_exploit"
    CREDENTIAL_ATTACK = "credential_attack"
    SOCIAL_ENGINEERING = "social_engineering"
    WIRELESS = "wireless"
    DENIAL_OF_SERVICE = "denial_of_service"
    PHYSICAL = "physical"
    REPORTING = "reporting"
    CLEANUP = "cleanup"


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class RoEDocument:
    """Parsed Rules of Engagement document."""

    title: str = ""
    client_name: str = ""
    engagement_id: str = ""
    effective_date: Optional[datetime] = None
    expiration_date: Optional[datetime] = None
    authorized_domains: List[str] = field(default_factory=list)
    authorized_ip_ranges: List[str] = field(default_factory=list)
    authorized_repos: List[str] = field(default_factory=list)
    authorized_cloud_accounts: List[str] = field(default_factory=list)
    excluded_domains: List[str] = field(default_factory=list)
    excluded_ip_ranges: List[str] = field(default_factory=list)
    excluded_paths: List[str] = field(default_factory=list)
    authorized_techniques: List[str] = field(default_factory=list)
    prohibited_techniques: List[str] = field(default_factory=list)
    authorized_action_types: List[ActionType] = field(default_factory=list)
    prohibited_action_types: List[ActionType] = field(default_factory=list)
    allowed_ports: List[int] = field(default_factory=list)
    prohibited_ports: List[int] = field(default_factory=list)
    max_severity: str = "critical"
    time_budget_hours: Optional[float] = None
    concurrent_connections_max: Optional[int] = None
    requires_explicit_approval: List[str] = field(default_factory=list)
    special_conditions: List[str] = field(default_factory=list)
    raw_yaml: str = ""

    @classmethod
    def from_yaml(cls, path: str) -> "RoEDocument":
        """Parse a YAML RoE file into an RoEDocument."""
        raw = Path(path).read_text(encoding="utf-8")
        data = yaml.safe_load(raw)
        doc = cls(raw_yaml=raw)

        doc.title = data.get("title", "")
        doc.client_name = data.get("client_name", "")
        doc.engagement_id = data.get("engagement_id", "")

        effective = data.get("effective_date")
        if effective:
            doc.effective_date = datetime.fromisoformat(effective)
        expiration = data.get("expiration_date")
        if expiration:
            doc.expiration_date = datetime.fromisoformat(expiration)

        scope = data.get("scope", {})
        doc.authorized_domains = scope.get("authorized_domains", [])
        doc.authorized_ip_ranges = scope.get("authorized_ip_ranges", [])
        doc.authorized_repos = scope.get("authorized_repos", [])
        doc.authorized_cloud_accounts = scope.get("authorized_cloud_accounts", [])
        doc.excluded_domains = scope.get("excluded_domains", [])
        doc.excluded_ip_ranges = scope.get("excluded_ip_ranges", [])
        doc.excluded_paths = scope.get("excluded_paths", [])

        rules = data.get("rules", {})
        doc.authorized_techniques = rules.get("authorized_techniques", [])
        doc.prohibited_techniques = rules.get("prohibited_techniques", [])
        doc.allowed_ports = rules.get("allowed_ports", [])
        doc.prohibited_ports = rules.get("prohibited_ports", [])
        doc.max_severity = rules.get("max_severity", "critical")
        doc.time_budget_hours = rules.get("time_budget_hours")
        doc.concurrent_connections_max = rules.get("concurrent_connections_max")

        auth_types = rules.get("authorized_action_types", [])
        doc.authorized_action_types = [ActionType(at) for at in auth_types if at]
        prohibited_types = rules.get("prohibited_action_types", [])
        doc.prohibited_action_types = [ActionType(pt) for pt in prohibited_types if pt]

        doc.requires_explicit_approval = rules.get("requires_explicit_approval", [])
        doc.special_conditions = rules.get("special_conditions", [])

        return doc


@dataclass
class ScopeCheckReport:
    """Result of a scope check decision."""

    result: ScopeCheckResult
    target: str
    action_type: ActionType
    reason: str = ""
    matched_rule: str = ""
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def is_allowed(self) -> bool:
        return self.result == ScopeCheckResult.IN_SCOPE


@dataclass
class AuthHeader:
    """Authorization header to inject into requests."""
    name: str = ""
    value: str = ""
    type: str = ""  # "bearer", "basic", "api-key", "custom"


# ---------------------------------------------------------------------------
# ScopeEnforcer
# ---------------------------------------------------------------------------

class ScopeEnforcer:
    """
    Deterministic scope enforcer. No LLM calls — all rules are parsed
    from the RoE document and checked against parsed target data.

    This is HiveBreach's single non-negotiable hard gate.
    """

    def __init__(self, roe_path: Optional[str] = None):
        self.roe: Optional[RoEDocument] = None
        self._kill_switched: bool = False
        self._kill_switch_reason: str = ""
        self._authorization_headers: List[AuthHeader] = []
        self._violations: List[ScopeCheckReport] = []
        self._in_scope_cache: Dict[str, ScopeCheckResult] = {}
        self._ip_networks: List[Tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, bool]] = []
        self._excluded_ip_networks: List[Tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, bool]] = []

        if roe_path:
            self.load_roe(roe_path)

    # ------------------------------------------------------------------
    # RoE loading
    # ------------------------------------------------------------------

    def load_roe(self, path: str) -> None:
        """Load and parse a Rules of Engagement YAML file."""
        self.roe = RoEDocument.from_yaml(path)
        self._precompute_networks()
        self._load_auth_headers()
        logger.info(
            "RoE loaded: %s — %d domains, %d IP ranges, expires %s",
            self.roe.title,
            len(self.roe.authorized_domains),
            len(self.roe.authorized_ip_ranges),
            self.roe.expiration_date.isoformat() if self.roe.expiration_date else "N/A",
        )

    def _precompute_networks(self) -> None:
        """Pre-parse IP networks for fast lookup."""
        self._ip_networks = []
        for cidr in (self.roe.authorized_ip_ranges if self.roe else []):
            try:
                net = ipaddress.ip_network(cidr, strict=False)
                self._ip_networks.append((net, True))
            except ValueError:
                logger.warning("Invalid CIDR in authorized ranges: %s", cidr)

        self._excluded_ip_networks = []
        for cidr in (self.roe.excluded_ip_ranges if self.roe else []):
            try:
                net = ipaddress.ip_network(cidr, strict=False)
                self._excluded_ip_networks.append((net, True))
            except ValueError:
                logger.warning("Invalid CIDR in excluded ranges: %s", cidr)

    def _load_auth_headers(self) -> None:
        """Load authorization headers from RoE document."""
        if not self.roe:
            return
        headers_cfg = getattr(self.roe, 'raw_yaml', '')
        if not headers_cfg:
            return
        try:
            data = yaml.safe_load(headers_cfg)
            auth = data.get("authorization", {}) if data else {}
            for hdr in auth.get("headers", []):
                self._authorization_headers.append(AuthHeader(
                    name=hdr.get("name", ""),
                    value=hdr.get("value", ""),
                    type=hdr.get("type", "custom"),
                ))
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Target parsing helpers
    # ------------------------------------------------------------------

    @staticmethod
    def parse_target(target: str) -> Dict[str, Any]:
        """Parse a target string into domain, IP, path, repo components."""
        result: Dict[str, Any] = {
            "original": target,
            "domain": None,
            "ip": None,
            "path": None,
            "repo": None,
            "scheme": None,
        }

        target = target.strip()

        # Try as URL
        if "://" in target or target.startswith("//"):
            if not "://" in target:
                target = "https:" + target
            parsed = urlparse(target)
            result["scheme"] = parsed.scheme
            result["domain"] = parsed.hostname or parsed.netloc
            result["path"] = parsed.path or None
            if result["domain"] and ":" in result["domain"]:
                result["domain"] = result["domain"].split(":")[0]
        else:
            # Try as plain domain
            domain_pattern = re.compile(
                r'^([a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
            )
            if domain_pattern.match(target):
                result["domain"] = target
            else:
                # Try as IP
                try:
                    ipaddress.ip_address(target)
                    result["ip"] = target
                except ValueError:
                    result["domain"] = target

        return result

    @staticmethod
    def get_domain_pattern(domain: str) -> str:
        """Convert a domain to a fnmatch-compatible pattern for glob matching."""
        if domain.startswith("*."):
            return domain
        return domain

    # ------------------------------------------------------------------
    # Scope checks
    # ------------------------------------------------------------------

    def check_target(self, target: str) -> Tuple[bool, str]:
        """
        Check if a target is within scope.

        Returns (is_in_scope: bool, reason: str).
        """
        cache_key = target.lower()
        if cache_key in self._in_scope_cache:
            cached = self._in_scope_cache[cache_key]
            if cached == ScopeCheckResult.IN_SCOPE:
                return (True, "cached in-scope")
            if cached == ScopeCheckResult.KILL_SWITCH_ENGAGED:
                if not self._kill_switched:
                    del self._in_scope_cache[cache_key]
                else:
                    return (False, self._kill_switch_reason or "kill switch engaged")
            return (False, "cached out-of-scope")

        if self._kill_switched:
            self._in_scope_cache[cache_key] = ScopeCheckResult.KILL_SWITCH_ENGAGED
            return (False, self._kill_switch_reason)

        if not self.roe:
            return (False, "No Rules of Engagement loaded")

        parsed = self.parse_target(target)
        domain = parsed.get("domain")
        ip_addr = parsed.get("ip")
        path = parsed.get("path")

        # Check expiration
        if self.roe.expiration_date:
            now = datetime.now(timezone.utc)
            exp = self.roe.expiration_date.replace(tzinfo=timezone.utc) \
                if self.roe.expiration_date.tzinfo is None else self.roe.expiration_date
            if now > exp:
                self._in_scope_cache[cache_key] = ScopeCheckResult.OUT_OF_SCOPE
                return (False, f"Engagement expired on {self.roe.expiration_date.isoformat()}")

        # Check excluded domains first
        if domain:
            for excl in self.roe.excluded_domains:
                if fnmatch.fnmatch(domain, excl):
                    self._in_scope_cache[cache_key] = ScopeCheckResult.OUT_OF_SCOPE
                    return (False, f"Domain {domain} is in excluded list (matched: {excl})")

        # Check excluded IP ranges
        if ip_addr:
            try:
                ip = ipaddress.ip_address(ip_addr)
                for net, _ in self._excluded_ip_networks:
                    if ip in net:
                        self._in_scope_cache[cache_key] = ScopeCheckResult.OUT_OF_SCOPE
                        return (False, f"IP {ip_addr} is in excluded range {net}")
            except ValueError:
                pass

        # Check excluded paths
        if path:
            for excl_path in self.roe.excluded_paths:
                if path.startswith(excl_path) or fnmatch.fnmatch(path, excl_path):
                    self._in_scope_cache[cache_key] = ScopeCheckResult.OUT_OF_SCOPE
                    return (False, f"Path {path} is in excluded list (matched: {excl_path})")

        # Check authorized domains
        if domain:
            for auth_domain in self.roe.authorized_domains:
                if fnmatch.fnmatch(domain, auth_domain):
                    self._in_scope_cache[cache_key] = ScopeCheckResult.IN_SCOPE
                    return (True, f"Domain {domain} matches authorized domain {auth_domain}")

        # Check authorized IP ranges
        if ip_addr:
            try:
                ip = ipaddress.ip_address(ip_addr)
                for net, _ in self._ip_networks:
                    if ip in net:
                        self._in_scope_cache[cache_key] = ScopeCheckResult.IN_SCOPE
                        return (True, f"IP {ip_addr} is in authorized range {net}")
            except ValueError:
                pass

        # Check authorized repos
        repo = parsed.get("repo")
        if repo:
            for auth_repo in self.roe.authorized_repos:
                if fnmatch.fnmatch(repo, auth_repo):
                    self._in_scope_cache[cache_key] = ScopeCheckResult.IN_SCOPE
                    return (True, f"Repo {repo} matches authorized repo {auth_repo}")

        self._in_scope_cache[cache_key] = ScopeCheckResult.OUT_OF_SCOPE
        return (False, f"Target {target} is not in any authorized scope definition")

    def check_action(
        self,
        action_type: ActionType,
        technique_id: Optional[str] = None,
    ) -> Tuple[bool, str]:
        """
        Check if an action type or MITRE technique is within scope.

        Returns (is_allowed: bool, reason: str).
        """
        if not self.roe:
            return (False, "No Rules of Engagement loaded")

        if self._kill_switched:
            return (False, self._kill_switch_reason)

        # Check prohibited action types
        if action_type in self.roe.prohibited_action_types:
            return (False, f"Action type {action_type.value} is prohibited")

        # If authorized list is non-empty, action must be in it
        if self.roe.authorized_action_types:
            if action_type not in self.roe.authorized_action_types:
                return (False, f"Action type {action_type.value} is not in authorized list")

        # Check techniques
        if technique_id:
            if self.roe.prohibited_techniques:
                for pt in self.roe.prohibited_techniques:
                    if fnmatch.fnmatch(technique_id.upper(), pt.upper()):
                        return (False, f"Technique {technique_id} is prohibited (matched: {pt})")
            if technique_id in self.roe.requires_explicit_approval:
                return (False, f"Technique {technique_id} requires explicit approval")

        return (True, "Action is within scope")

    def check_port(self, port: int) -> Tuple[bool, str]:
        """Check if a port is within the allowed range."""
        if not self.roe:
            return (True, "No RoE loaded — port check skipped")

        if self.roe.prohibited_ports and port in self.roe.prohibited_ports:
            return (False, f"Port {port} is prohibited")

        if self.roe.allowed_ports and port not in self.roe.allowed_ports:
            return (False, f"Port {port} is not in allowed list")

        return (True, f"Port {port} is allowed")

    def check_time_budget(self, elapsed_hours: float) -> Tuple[bool, str]:
        """Check if the engagement time budget has been exceeded."""
        if not self.roe or self.roe.time_budget_hours is None:
            return (True, "No time budget set")
        if elapsed_hours > self.roe.time_budget_hours:
            return (False, f"Time budget of {self.roe.time_budget_hours}h exceeded ({elapsed_hours:.1f}h elapsed)")
        remaining = self.roe.time_budget_hours - elapsed_hours
        return (True, f"{remaining:.1f}h remaining in budget")

    def check_connection_limit(self, current_connections: int) -> Tuple[bool, str]:
        """Check if the concurrent connection limit has been reached."""
        if not self.roe or self.roe.concurrent_connections_max is None:
            return (True, "No connection limit set")
        if current_connections >= self.roe.concurrent_connections_max:
            return (False, f"Connection limit of {self.roe.concurrent_connections_max} reached")
        return (True, f"{self.roe.concurrent_connections_max - current_connections} connections available")

    # ------------------------------------------------------------------
    # Kill switch
    # ------------------------------------------------------------------

    def engage_kill_switch(self, reason: str) -> None:
        """Engage the kill switch — all subsequent actions are blocked."""
        self._kill_switched = True
        self._kill_switch_reason = reason
        self._in_scope_cache.clear()
        logger.critical("KILL SWITCH ENGAGED: %s", reason)

    def disengage_kill_switch(self) -> None:
        """Disengage the kill switch and clear cached scope decisions."""
        self._kill_switched = False
        self._kill_switch_reason = ""
        self._in_scope_cache.clear()
        logger.info("Kill switch disengaged")

    @property
    def is_kill_switched(self) -> bool:
        return self._kill_switched

    # ------------------------------------------------------------------
    # Authorization headers
    # ------------------------------------------------------------------

    def get_authorization_headers(self) -> List[AuthHeader]:
        """Get authorization headers to inject into requests."""
        return self._authorization_headers.copy()

    def inject_auth_header(self, name: str = "Authorization", value: str = "",
                           header_type: str = "custom") -> None:
        """Add an authorization header."""
        self._authorization_headers.append(AuthHeader(
            name=name, value=value, type=header_type,
        ))

    def get_auth_header_dict(self) -> Dict[str, str]:
        """Get auth headers as a dict for HTTP requests."""
        return {h.name: h.value for h in self._authorization_headers if h.name and h.value}

    # ------------------------------------------------------------------
    # Full authorization check
    # ------------------------------------------------------------------

    def authorize(
        self,
        target: str,
        action_type: ActionType,
        technique_id: Optional[str] = None,
        port: Optional[int] = None,
        elapsed_hours: float = 0.0,
        current_connections: int = 0,
    ) -> ScopeCheckReport:
        """
        Full authorization check. Runs ALL checks and returns the
        most restrictive result.

        This is the primary entry point for the orchestration layer.
        """
        report = ScopeCheckReport(
            result=ScopeCheckResult.IN_SCOPE,
            target=target,
            action_type=action_type,
        )

        # 1. Target scope check
        target_ok, target_reason = self.check_target(target)
        if not target_ok:
            if self._kill_switched:
                report.result = ScopeCheckResult.KILL_SWITCH_ENGAGED
            else:
                report.result = ScopeCheckResult.OUT_OF_SCOPE
            report.reason = target_reason
            report.matched_rule = "target_scope"
            self._violations.append(report)
            return report

        # 2. Action type check
        action_ok, action_reason = self.check_action(action_type, technique_id)
        if not action_ok:
            report.result = ScopeCheckResult.OUT_OF_SCOPE
            report.reason = action_reason
            report.matched_rule = "action_type"
            self._violations.append(report)
            return report

        # 3. Port check
        if port is not None:
            port_ok, port_reason = self.check_port(port)
            if not port_ok:
                report.result = ScopeCheckResult.OUT_OF_SCOPE
                report.reason = port_reason
                report.matched_rule = "port"
                self._violations.append(report)
                return report

        # 4. Kill switch check
        if self._kill_switched:
            report.result = ScopeCheckResult.KILL_SWITCH_ENGAGED
            report.reason = self._kill_switch_reason
            report.matched_rule = "kill_switch"
            return report

        # 5. Time budget
        budget_ok, budget_reason = self.check_time_budget(elapsed_hours)
        if not budget_ok:
            report.result = ScopeCheckResult.OUT_OF_SCOPE
            report.reason = budget_reason
            report.matched_rule = "time_budget"
            self._violations.append(report)
            return report

        # 6. Connection limit
        conn_ok, conn_reason = self.check_connection_limit(current_connections)
        if not conn_ok:
            report.result = ScopeCheckResult.OUT_OF_SCOPE
            report.reason = conn_reason
            report.matched_rule = "connection_limit"
            self._violations.append(report)
            return report

        report.reason = "All scope checks passed"
        return report

    def get_violations(self, clear: bool = False) -> List[ScopeCheckReport]:
        """Get all scope violations recorded so far."""
        result = self._violations.copy()
        if clear:
            self._violations.clear()
        return result

    def reset(self) -> None:
        """Reset the enforcer state (clear cache, violations, kill switch)."""
        self._in_scope_cache.clear()
        self._violations.clear()
        self._kill_switched = False
        self._kill_switch_reason = ""
