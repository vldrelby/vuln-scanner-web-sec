"""
Pydantic models for API requests and responses.
"""

from datetime import datetime
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, HttpUrl, Field

from app.database import ScanStatus, Severity


# Request Models
class ScanRequest(BaseModel):
    """Request model for creating a new scan."""
    target_url: str = Field(..., description="Target URL to scan")
    scan_type: str = Field(..., description="Type of scan: nmap, nuclei, or custom")
    options: Optional[Dict[str, Any]] = Field(default=None, description="Additional scan options")


# Response Models
class VulnerabilityResponse(BaseModel):
    """Vulnerability response model."""
    id: int
    title: str
    description: str
    severity: Severity
    scanner_type: str
    affected_url: Optional[str] = None
    cve: Optional[str] = None
    recommendation: Optional[str] = None
    evidence: Optional[Dict[str, Any]] = None
    discovered_at: datetime
    
    class Config:
        from_attributes = True


class ScanResponse(BaseModel):
    """Scan response model."""
    id: int
    target_url: str
    scan_type: str
    status: ScanStatus
    created_at: datetime
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    error_message: Optional[str] = None
    scan_metadata: Optional[Dict[str, Any]] = None
    vulnerabilities: List[VulnerabilityResponse] = Field(default_factory=list)
    
    class Config:
        from_attributes = True


class ScanListResponse(BaseModel):
    """List of scans response model."""
    scans: List[ScanResponse]
    total: int


class HealthResponse(BaseModel):
    """Health check response model."""
    status: str
    version: str
    database: str

