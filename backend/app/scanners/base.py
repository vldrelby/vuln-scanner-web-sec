"""
Base scanner class defining the interface for all scanners.
"""

from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional
from datetime import datetime

from app.database import Severity
from app.models import VulnerabilityResponse


class ScanResult:
    """Normalized scan result."""
    def __init__(
        self,
        vulnerabilities: List[VulnerabilityResponse],
        metadata: Optional[Dict[str, Any]] = None,
        error: Optional[str] = None
    ):
        self.vulnerabilities = vulnerabilities
        self.metadata = metadata or {}
        self.error = error
        self.success = error is None


class BaseScanner(ABC):
    """Base class for all scanners."""
    
    def __init__(self, config: Any):
        """
        Initialize scanner with configuration.
        
        Args:
            config: Scanner configuration object
        """
        self.config = config
        self.scanner_type = self.__class__.__name__.replace("Scanner", "").lower()
    
    @abstractmethod
    async def scan(self, target_url: str, options: Optional[Dict[str, Any]] = None) -> ScanResult:
        """
        Perform scan on target URL.
        
        Args:
            target_url: Target URL to scan
            options: Optional scan-specific options
        
        Returns:
            ScanResult with vulnerabilities and metadata
        """
        pass
    
    def normalize_severity(self, severity: str) -> Severity:
        """
        Normalize severity string to Severity enum.
        
        Args:
            severity: Severity string (case-insensitive)
        
        Returns:
            Normalized Severity enum value
        """
        severity_lower = severity.lower()
        severity_map = {
            "critical": Severity.CRITICAL,
            "high": Severity.HIGH,
            "medium": Severity.MEDIUM,
            "low": Severity.LOW,
            "info": Severity.INFO,
        }
        return severity_map.get(severity_lower, Severity.INFO)
    
    def create_vulnerability(
        self,
        title: str,
        description: str,
        severity: Severity,
        affected_url: Optional[str] = None,
        cve: Optional[str] = None,
        recommendation: Optional[str] = None,
        evidence: Optional[Dict[str, Any]] = None
    ) -> VulnerabilityResponse:
        """
        Create a normalized vulnerability response.
        
        Args:
            title: Vulnerability title
            description: Detailed description
            severity: Severity level
            affected_url: Affected URL or endpoint
            cve: CVE identifier if available
            recommendation: Remediation recommendation
            evidence: Additional evidence data
        
        Returns:
            VulnerabilityResponse object
        """
        return VulnerabilityResponse(
            id=0,  # Will be set by database
            title=title,
            description=description,
            severity=severity,
            scanner_type=self.scanner_type,
            affected_url=affected_url,
            cve=cve,
            recommendation=recommendation,
            evidence=evidence,
            discovered_at=datetime.utcnow()
        )

