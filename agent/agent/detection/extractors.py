"""
Signal extraction utilities for information disclosure detection.

This module provides high-level functions to extract disclosure signals
from HTTP responses, combining multiple detection strategies.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

from agent.detection.patterns import (
    DisclosureSignal,
    DisclosureType,
    Severity,
    ErrorPatternDetector,
    SystemInfoDetector,
    ConfigExposureDetector,
)


def extract_all_signals(
    body: str,
    headers: Dict[str, str],
    url: str,
    status_code: int,
) -> List[DisclosureSignal]:
    """
    Extract all disclosure signals from an HTTP response.
    
    This is the main entry point for comprehensive signal detection.
    
    Args:
        body: Response body text
        headers: Response headers
        url: Requested URL
        status_code: HTTP status code
        
    Returns:
        List of DisclosureSignal objects
    """
    signals = []
    
    # Error pattern detection
    error_detector = ErrorPatternDetector()
    signals.extend(error_detector.detect(body, status_code))
    
    # System info detection
    system_detector = SystemInfoDetector()
    signals.extend(system_detector.detect(body, headers))
    
    # Config exposure detection
    config_detector = ConfigExposureDetector()
    signals.extend(config_detector.detect(body, url))
    
    return signals


def has_critical_disclosure(signals: List[DisclosureSignal]) -> bool:
    """Check if any signal indicates critical disclosure."""
    critical_types = {
        DisclosureType.STACK_TRACE,
        DisclosureType.DB_ERROR,
        DisclosureType.SOURCE_CODE,
        DisclosureType.CONFIG_EXPOSURE,
    }
    return any(s.disclosure_type in critical_types for s in signals)


def get_highest_severity(signals: List[DisclosureSignal]) -> Severity:
    """Get the highest severity from a list of signals."""
    if not signals:
        return Severity.INFO
    
    severity_order = {
        Severity.CRITICAL: 5,
        Severity.HIGH: 4,
        Severity.MEDIUM: 3,
        Severity.LOW: 2,
        Severity.INFO: 1,
    }
    
    return max(signals, key=lambda s: severity_order.get(s.severity, 0)).severity


def signals_to_finding_format(signals: List[DisclosureSignal]) -> Dict[str, Any]:
    """Convert signals to a format suitable for finding generation."""
    if not signals:
        return {"has_disclosure": False, "signals": []}
    
    return {
        "has_disclosure": True,
        "has_critical": has_critical_disclosure(signals),
        "highest_severity": get_highest_severity(signals).value,
        "signal_count": len(signals),
        "signals": [s.to_dict() for s in signals],
        "signal_types": list(set(s.disclosure_type.value for s in signals)),
    }


# Legacy compatibility functions
def extract_error_signals(body: str, status_code: int) -> List[DisclosureSignal]:
    """Legacy function for error signal extraction."""
    detector = ErrorPatternDetector()
    return detector.detect(body, status_code)


def extract_system_info_signals(body: str, headers: Dict[str, str]) -> List[DisclosureSignal]:
    """Legacy function for system info signal extraction."""
    detector = SystemInfoDetector()
    return detector.detect(body, headers)


def extract_config_signals(body: str, url: str) -> List[DisclosureSignal]:
    """Legacy function for config signal extraction."""
    detector = ConfigExposureDetector()
    return detector.detect(body, url)

