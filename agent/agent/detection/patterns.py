
"""
Enhanced detection patterns for information disclosure.

This module provides comprehensive pattern detection for various types of
information disclosure, designed to be more sensitive than traditional
scanners while maintaining low false positive rates.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set
from enum import Enum


class DisclosureType(Enum):
    """Types of information disclosure."""
    STACK_TRACE = "stack_trace"
    FILE_PATH = "file_path"
    DB_ERROR = "db_error"
    DEBUG_INFO = "debug_info"
    VERSION_DISCLOSURE = "version_disclosure"
    FRAMEWORK_HINT = "framework_hint"
    INTERNAL_IP = "internal_ip"
    CONFIG_EXPOSURE = "config_exposure"
    VERBOSE_ERROR = "verbose_error"
    SOURCE_CODE = "source_code"
    LOG_EXPOSURE = "log_exposure"
    INTERNAL_STRUCTURE = "internal_structure"


class Severity(Enum):
    """Disclosure severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class DisclosureSignal:
    """Represents a detected information disclosure signal."""
    disclosure_type: DisclosureType
    severity: Severity
    confidence: float
    evidence: List[str] = field(default_factory=list)
    location: str = ""  # body, headers, etc.
    context: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": self.disclosure_type.value,
            "severity": self.severity.value,
            "confidence": self.confidence,
            "evidence": self.evidence,
            "location": self.location,
            "context": self.context,
        }


# ============================================================================
# ERROR PATTERN DETECTORS
# ============================================================================

class ErrorPatternDetector:
    """Detects error-related information disclosure."""
    
    # Stack trace patterns - more comprehensive
    STACK_TRACE_PATTERNS = [
        # Java/Common
        re.compile(r"\bat\s+[a-zA-Z0-9_.$]+\([A-Za-z0-9_.]+:\d+\)", re.I),
        re.compile(r"\bat\s+[a-zA-Z0-9_$]+\.[a-zA-Z0-9_$]+\([^)]+\)", re.I),
        # Python
        re.compile(r"Traceback \(most recent call last\):", re.I),
        re.compile(r'File "([^"]+)", line \d+, in ', re.I),
        re.compile(r"\b(?:\w+Error|\w+Exception):\s*.+", re.I),
        # .NET
        re.compile(r"at\s+System\.", re.I),
        re.compile(r"--- End of inner exception stack trace ---", re.I),
        # PHP
        re.compile(r"#\d+\s+(?:0x[0-9a-f]+\s+)?(.+?)(?:\(|$)", re.I),
        # Node.js
        re.compile(r"at\s+(?:Object\.)?[a-zA-Z0-9_$.]+\s+\((?:[^)]+)?\)", re.I),
        # Generic
        re.compile(r"\bFatal error\b", re.I),
        re.compile(r"\bStack trace:\b", re.I),
        re.compile(r"\bUnhandled Exception:\b", re.I),
    ]
    
    # File path patterns - enhanced
    FILE_PATH_PATTERNS = [
        # Unix paths
        re.compile(r"(?:^|/)(?:etc|var|usr|home|opt|tmp|root)(?:/[^/\s<>:\"'|?*]+)+", re.I),
        re.compile(r"(?:[A-Za-z]:\\(?:[^\\\r\n]+\\)+[^\\\r\n]*)"),
        # Application paths
        re.compile(r"/(?:app|application|src|lib|bin|public|private)/[^\s<>:\"'|?*]+", re.I),
        re.compile(r"/(?:www|web|html|htdocs)/[^\s<>:\"'|?*]+", re.I),
        # Config paths
        re.compile(r"/(?:config|conf|cfg|settings)/[^\s<>:\"'|?*]+", re.I),
    ]
    
    # Database error patterns - comprehensive
    DB_ERROR_PATTERNS = [
        # MySQL
        re.compile(r"SQL syntax.*MySQL", re.I),
        re.compile(r"MySqlException", re.I),
        re.compile(r"Warning.*mysql_", re.I),
        re.compile(r"Table '[^']+' doesn't exist", re.I),
        re.compile(r"Duplicate entry '[^']+' for key", re.I),
        # PostgreSQL
        re.compile(r"PostgreSQL.*ERROR", re.I),
        re.compile(r"PG::[A-Za-z]+", re.I),
        re.compile(r"org\.postgresql\.", re.I),
        # Oracle
        re.compile(r"ORA-\d{5}", re.I),
        re.compile(r"Oracle error", re.I),
        # SQL Server
        re.compile(r"Microsoft OLE DB Provider for SQL Server", re.I),
        re.compile(r"SQLServerException", re.I),
        re.compile(r"Unclosed quotation mark", re.I),
        # SQLite
        re.compile(r"SQLite/JDBCDriver", re.I),
        re.compile(r"sqlite3\.", re.I),
        # Generic
        re.compile(r"(?:SQL|ODBC|JDBC).*error", re.I),
        re.compile(r"database.*error", re.I),
        re.compile(r"connection.*failed", re.I),
    ]
    
    # Verbose error indicators
    VERBOSE_ERROR_PATTERNS = [
        re.compile(r"\bdevelopment mode\b", re.I),
        re.compile(r"\bverbose error\b", re.I),
        re.compile(r"\bexception report\b", re.I),
        re.compile(r"\bdebug (?:mode|page|toolbar)\b", re.I),
        re.compile(r"\brunning in debug\b", re.I),
        re.compile(r"\bdetailed error\b", re.I),
        re.compile(r"\bfull stack trace\b", re.I),
        re.compile(r"whitelabel error page", re.I),
    ]
    
    def __init__(self, allow_2xx: bool = True):
        """
        Initialize detector.
        
        Args:
            allow_2xx: Whether to detect errors in 2xx responses
        """
        self.allow_2xx = allow_2xx
    
    def detect(self, body: str, status_code: int) -> List[DisclosureSignal]:
        """Detect error-related disclosures in response."""
        signals = []
        
        if not body:
            return signals
        
        # Stack traces - always detect regardless of status
        stack_traces = self._find_stack_traces(body)
        if stack_traces:
            signals.append(DisclosureSignal(
                disclosure_type=DisclosureType.STACK_TRACE,
                severity=Severity.MEDIUM,
                confidence=0.95,
                evidence=stack_traces[:5],
                location="body",
                context={"status_code": status_code}
            ))
        
        # File paths - detect in any response
        file_paths = self._find_file_paths(body)
        if file_paths:
            signals.append(DisclosureSignal(
                disclosure_type=DisclosureType.FILE_PATH,
                severity=Severity.MEDIUM,
                confidence=0.90,
                evidence=file_paths[:5],
                location="body",
                context={"status_code": status_code}
            ))
        
        # DB errors - detect in any response
        db_errors = self._find_db_errors(body)
        if db_errors:
            signals.append(DisclosureSignal(
                disclosure_type=DisclosureType.DB_ERROR,
                severity=Severity.HIGH,
                confidence=0.92,
                evidence=db_errors[:5],
                location="body",
                context={"status_code": status_code}
            ))
        
        # Verbose errors
        verbose_errors = self._find_verbose_errors(body)
        if verbose_errors:
            signals.append(DisclosureSignal(
                disclosure_type=DisclosureType.DEBUG_INFO,
                severity=Severity.LOW,
                confidence=0.85,
                evidence=verbose_errors[:3],
                location="body",
                context={"status_code": status_code}
            ))
        
        return signals
    
    def _find_stack_traces(self, body: str) -> List[str]:
        """Find stack trace patterns in body."""
        results = []
        for pattern in self.STACK_TRACE_PATTERNS:
            for match in pattern.finditer(body):
                trace = match.group(0).strip()
                if trace and len(trace) > 20:
                    results.append(trace[:200])
        return list(dict.fromkeys(results))  # Preserve order, remove dupes
    
    def _find_file_paths(self, body: str) -> List[str]:
        """Find file path patterns in body."""
        results = []
        for pattern in self.FILE_PATH_PATTERNS:
            for match in pattern.finditer(body):
                path = match.group(0).strip()
                if path and len(path) > 10:
                    results.append(path[:200])
        return list(dict.fromkeys(results))
    
    def _find_db_errors(self, body: str) -> List[str]:
        """Find database error patterns in body."""
        results = []
        for pattern in self.DB_ERROR_PATTERNS:
            for match in pattern.finditer(body):
                error = match.group(0).strip()
                if not error:
                    continue
                # Short markers such as ORA-00001 are meaningful only when
                # carried with nearby SQL/driver context; preserve that
                # context instead of dropping the match as "too short".
                start = max(0, match.start() - 120)
                end = min(len(body), match.end() + 200)
                context = body[start:end].strip()
                candidate = context if len(error) <= 10 else error
                if candidate and len(candidate) > 10:
                    results.append(candidate[:300])
        return list(dict.fromkeys(results))
    
    def _find_verbose_errors(self, body: str) -> List[str]:
        """Find verbose error indicators in body."""
        results = []
        for pattern in self.VERBOSE_ERROR_PATTERNS:
            for match in pattern.finditer(body):
                error = match.group(0).strip()
                if error:
                    results.append(error[:100])
        return list(dict.fromkeys(results))


# ============================================================================
# SYSTEM INFO DETECTORS
# ============================================================================

class SystemInfoDetector:
    """Detects system/infrastructure information disclosure."""
    
    # Version disclosure patterns
    VERSION_PATTERNS = [
        # Server headers in body
        re.compile(r"\b(?:apache|nginx|iis|caddy|envoy)/\d[\w.\-]*\b", re.I),
        re.compile(r"\b(?:tomcat|jetty|jboss|wildfly|weblogic|websphere|glassfish)/\d[\w.\-]*\b", re.I),
        re.compile(r"\b(?:gunicorn|uwsgi|werkzeug|uvicorn|hypercorn)/\d[\w.\-]*\b", re.I),
        # Framework versions
        re.compile(r"\b(?:django[ /]\d|flask[ /]\d|spring boot[ /]\d|laravel[ /]\d)", re.I),
        re.compile(r"\b(?:express[ /]\d|koa[ /]\d|next\.js[ /]\d|nuxt[ /]\d)", re.I),
        re.compile(r"\b(?:php[ /]\d|asp\.net(?: core)?[ /]\d)", re.I),
    ]
    
    # Framework hints
    FRAMEWORK_PATTERNS = [
        re.compile(r"\bSpring\b", re.I),
        re.compile(r"\bDjango\b", re.I),
        re.compile(r"\bFlask\b|\bWerkzeug\b", re.I),
        re.compile(r"\bExpress\b", re.I),
        re.compile(r"\bRuby on Rails\b", re.I),
        re.compile(r"\bLaravel\b", re.I),
        re.compile(r"\bASP\.NET\b", re.I),
        re.compile(r"\bNext\.js\b|\bNuxt\b", re.I),
        re.compile(r"\bVue\b", re.I),
        re.compile(r"\bReact\b", re.I),
        re.compile(r"\bAngular\b", re.I),
    ]
    
    # Internal IP patterns
    INTERNAL_IP_PATTERNS = [
        re.compile(r"\b10(?:\.\d{1,3}){3}\b"),
        re.compile(r"\b192\.168(?:\.\d{1,3}){2}\b"),
        re.compile(r"\b172\.(?:1[6-9]|2\d|3[0-1])(?:\.\d{1,3}){2}\b"),
    ]
    
    # Source code disclosure patterns
    SOURCE_CODE_PATTERNS = [
        re.compile(r"<\?php\s", re.I),
        re.compile(r"<\?=\s*", re.I),
        re.compile(r"<%@\s*page\s", re.I),
        re.compile(r"<%@\s*taglib\s", re.I),
        re.compile(r"#!/usr/bin/(?:python|perl|ruby|node)", re.I),
        re.compile(r"package\s+[a-zA-Z_][a-zA-Z0-9_.]*;", re.I),
        re.compile(r"import\s+(?:React|Vue|Angular)", re.I),
    ]
    
    def detect(self, body: str, headers: Dict[str, str]) -> List[DisclosureSignal]:
        """Detect system info disclosures."""
        signals = []
        
        # Version disclosure
        versions = self._find_versions(body)
        if versions:
            signals.append(DisclosureSignal(
                disclosure_type=DisclosureType.VERSION_DISCLOSURE,
                severity=Severity.LOW,
                confidence=0.88,
                evidence=versions[:5],
                location="body",
                context={}
            ))
        
        # Framework hints
        frameworks = self._find_frameworks(body)
        if frameworks:
            signals.append(DisclosureSignal(
                disclosure_type=DisclosureType.FRAMEWORK_HINT,
                severity=Severity.LOW,
                confidence=0.82,
                evidence=frameworks[:5],
                location="body",
                context={}
            ))
        
        # Internal IPs
        internal_ips = self._find_internal_ips(body)
        if internal_ips:
            signals.append(DisclosureSignal(
                disclosure_type=DisclosureType.INTERNAL_IP,
                severity=Severity.MEDIUM,
                confidence=0.90,
                evidence=internal_ips[:3],
                location="body",
                context={}
            ))
        
        # Source code
        source_code = self._find_source_code(body)
        if source_code:
            signals.append(DisclosureSignal(
                disclosure_type=DisclosureType.SOURCE_CODE,
                severity=Severity.HIGH,
                confidence=0.95,
                evidence=source_code[:3],
                location="body",
                context={}
            ))
        
        # Header-based disclosure
        header_disclosure = self._detect_header_disclosure(headers)
        if header_disclosure:
            signals.append(header_disclosure)
        
        return signals
    
    def _find_versions(self, body: str) -> List[str]:
        results = []
        for pattern in self.VERSION_PATTERNS:
            for match in pattern.finditer(body):
                version = match.group(0).strip()
                if version:
                    results.append(version)
        return list(dict.fromkeys(results))
    
    def _find_frameworks(self, body: str) -> List[str]:
        results = []
        for pattern in self.FRAMEWORK_PATTERNS:
            for match in pattern.finditer(body):
                framework = match.group(0).strip()
                if framework:
                    results.append(framework)
        return list(dict.fromkeys(results))
    
    def _find_internal_ips(self, body: str) -> List[str]:
        results = []
        for pattern in self.INTERNAL_IP_PATTERNS:
            for match in pattern.finditer(body):
                ip = match.group(0).strip()
                if ip and not ip.startswith("127."):
                    results.append(ip)
        return list(dict.fromkeys(results))
    
    def _find_source_code(self, body: str) -> List[str]:
        results = []
        for pattern in self.SOURCE_CODE_PATTERNS:
            if pattern.search(body):
                results.append(pattern.pattern[:50])
        return results
    
    def _detect_header_disclosure(self, headers: Dict[str, str]) -> Optional[DisclosureSignal]:
        """Detect information in headers."""
        evidence = []
        
        for key, value in headers.items():
            key_lower = key.lower()
            if key_lower == "server" and value:
                evidence.append(f"Server: {value}")
            elif key_lower == "x-powered-by" and value:
                evidence.append(f"X-Powered-By: {value}")
            elif key_lower == "x-aspnet-version" and value:
                evidence.append(f"X-AspNet-Version: {value}")
        
        if evidence:
            return DisclosureSignal(
                disclosure_type=DisclosureType.VERSION_DISCLOSURE,
                severity=Severity.INFO,
                confidence=0.95,
                evidence=evidence,
                location="headers",
                context={}
            )
        return None


# ============================================================================
# CONFIG EXPOSURE DETECTORS
# ============================================================================

class ConfigExposureDetector:
    """Detects configuration and sensitive data exposure."""
    
    # Sensitive config keys
    SENSITIVE_KEYS = {
        "password", "passwd", "pwd", "secret", "token", "api_key", "apikey",
        "access_key", "private_key", "client_secret", "auth_token",
        "db_password", "db_pass", "database_password", "mysql_password",
        "db_host", "db_user", "db_name", "db_port", "database_host",
        "aws_access_key", "aws_secret", "aws_secret_key",
        "redis_password", "redis_pass", "jwt_secret",
    }
    
    # Config file patterns in URL
    CONFIG_URL_PATTERNS = [
        r"\.env",
        r"\.yaml",
        r"\.yml",
        r"\.json",
        r"\.xml",
        r"\.ini",
        r"\.conf",
        r"\.cfg",
        r"\.properties",
        r"config",
        r"appsettings",
        r"application\.yml",
        r"application\.properties",
    ]
    
    # Config markers in body
    CONFIG_MARKERS = [
        "db_password", "mysql_password", "database", "db_host", "db_user",
        "secret", "api_key", "access_key", "private_key", "connection_string",
        "aws_access_key", "aws_secret", "redis", "postgres", "mysql",
    ]
    
    def detect(self, body: str, url: str) -> List[DisclosureSignal]:
        """Detect configuration exposure."""
        signals = []
        
        # Check URL for config file patterns
        url_lower = url.lower()
        for pattern in self.CONFIG_URL_PATTERNS:
            if re.search(pattern, url_lower):
                signals.append(DisclosureSignal(
                    disclosure_type=DisclosureType.CONFIG_EXPOSURE,
                    severity=Severity.HIGH,
                    confidence=0.85,
                    evidence=[f"Config-like URL: {url}"],
                    location="url",
                    context={"url_pattern": pattern}
                ))
                break
        
        # Check body for config markers
        markers = self._find_config_markers(body)
        if markers:
            signals.append(DisclosureSignal(
                disclosure_type=DisclosureType.CONFIG_EXPOSURE,
                severity=Severity.MEDIUM,
                confidence=0.80,
                evidence=markers[:10],
                location="body",
                context={}
            ))
        
        # Extract actual config values
        config_values = self._extract_config_values(body)
        if config_values:
            signals.append(DisclosureSignal(
                disclosure_type=DisclosureType.CONFIG_EXPOSURE,
                severity=Severity.HIGH,
                confidence=0.90,
                evidence=config_values[:5],
                location="body",
                context={"sensitive_keys_found": len(config_values)}
            ))
        
        return signals
    
    def _find_config_markers(self, body: str) -> List[str]:
        body_lower = body.lower()
        markers = []
        for marker in self.CONFIG_MARKERS:
            if marker in body_lower:
                markers.append(marker)
        return markers
    
    def _extract_config_values(self, body: str) -> List[str]:
        """Extract potential sensitive config values."""
        results = []
        
        # Key=value patterns
        kv_pattern = re.compile(
            r"(?i)\b([a-zA-Z_][a-zA-Z0-9_]*)\s*[=:]\s*['\"]?([^'\"\n]{4,})['\"]?",
            re.MULTILINE
        )
        
        for match in kv_pattern.finditer(body):
            key = match.group(1).strip().lower()
            value = match.group(2).strip()
            
            # Check if key is sensitive
            if any(sensitive in key for sensitive in self.SENSITIVE_KEYS):
                # Mask the value
                if len(value) > 4:
                    masked = value[:2] + "*" * (len(value) - 4) + value[-2:]
                else:
                    masked = "****"
                results.append(f"{key}={masked}")
        
        return results


# ============================================================================
# CONVENIENCE FUNCTIONS
# ============================================================================

def extract_error_signals(body: str, status_code: int) -> List[DisclosureSignal]:
    """Convenience function to extract error signals."""
    detector = ErrorPatternDetector()
    return detector.detect(body, status_code)


def extract_system_info_signals(body: str, headers: Dict[str, str]) -> List[DisclosureSignal]:
    """Convenience function to extract system info signals."""
    detector = SystemInfoDetector()
    return detector.detect(body, headers)


def extract_config_signals(body: str, url: str) -> List[DisclosureSignal]:
    """Convenience function to extract config exposure signals."""
    detector = ConfigExposureDetector()
    return detector.detect(body, url)
