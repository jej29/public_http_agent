"""
Detection module for information disclosure patterns.

This module provides enhanced detection for various types of information disclosure:
- Error disclosure (stack traces, file paths, DB errors)
- System info disclosure (versions, frameworks, internal IPs)
- Configuration exposure
- Verbose error messages
- Debug information
"""

from agent.detection.patterns import (
    ErrorPatternDetector,
    SystemInfoDetector,
    ConfigExposureDetector,
)
from agent.detection.extractors import (
    extract_error_signals,
    extract_system_info_signals,
    extract_config_signals,
)

__all__ = [
    "ErrorPatternDetector",
    "SystemInfoDetector", 
    "ConfigExposureDetector",
    "extract_error_signals",
    "extract_system_info_signals",
    "extract_config_signals",
]