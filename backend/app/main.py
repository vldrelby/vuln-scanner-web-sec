"""
FastAPI application main entry point.
Provides REST API endpoints for vulnerability scanning.
"""

import asyncio
from contextlib import asynccontextmanager
from typing import List
from fastapi import FastAPI, HTTPException, Depends, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from loguru import logger
import sys

from app.config import settings, load_config
from app.database import init_db, get_db, Scan, Vulnerability, ScanStatus
from app.models import (
    ScanRequest, ScanResponse, ScanListResponse,
    VulnerabilityResponse, HealthResponse
)
from app.scanners import NmapScanner, NucleiScanner, CustomScanner


# Configure logging
def setup_logging():
    """Configure loguru logger."""
    logger.remove()  # Remove default handler
    logger.add(
        sys.stdout,
        format="<green>{time:YYYY-MM-DD HH:mm:ss}</green> | <level>{level: <8}</level> | <cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> - <level>{message}</level>",
        level=settings.logging.level
    )
    logger.add(
        settings.logging.file,
        rotation=settings.logging.rotation,
        retention=settings.logging.retention,
        level=settings.logging.level,
        format="{time:YYYY-MM-DD HH:mm:ss} | {level: <8} | {name}:{function}:{line} - {message}"
    )


setup_logging()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager."""
    # Startup
    logger.info("Initializing database...")
    await init_db()
    logger.info("Database initialized")
    yield
    # Shutdown
    logger.info("Shutting down...")


# Create FastAPI app
app = FastAPI(
    title="Web Vulnerability Scanner API",
    description="Comprehensive security scanning tool for web applications",
    version="1.0.0",
    lifespan=lifespan
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure appropriately for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Initialize scanners
nmap_scanner = NmapScanner()
nuclei_scanner = NucleiScanner()
custom_scanner = CustomScanner()


async def run_scan_task(scan_id: int, target_url: str, scan_type: str, options: dict):
    """
    Background task to run vulnerability scan.
    
    Args:
        scan_id: Scan database ID
        target_url: Target URL to scan
        scan_type: Type of scan (nmap, nuclei, custom)
        options: Scan options
    """
    from app.database import AsyncSessionLocal
    from datetime import datetime
    
    async with AsyncSessionLocal() as db:
        try:
            # Update scan status to running
            result = await db.execute(select(Scan).where(Scan.id == scan_id))
            scan = result.scalar_one()
            scan.status = ScanStatus.RUNNING
            scan.started_at = datetime.utcnow()
            await db.commit()
            
            logger.info(f"Starting {scan_type} scan on {target_url} (scan_id: {scan_id})")
            
            vulnerabilities = []
            
            # Run appropriate scanner
            if scan_type == "nmap":
                logger.info("Running Nmap scanner...")
                nmap_result = await nmap_scanner.scan(target_url, options)
                if nmap_result.success:
                    vulnerabilities.extend(nmap_result.vulnerabilities)
                else:
                    logger.warning(f"Nmap scan failed: {nmap_result.error}")
            
            elif scan_type == "nuclei":
                logger.info("Running Nuclei scanner...")
                
                # Define callback to save vulnerabilities in real-time
                async def save_vulnerability_realtime(vuln_data):
                    """Save vulnerability to database as soon as it's found."""
                    try:
                        # Refresh db session to avoid stale state
                        await db.refresh(scan)
                        
                        # Convert VulnerabilityResponse to database model
                        vuln = Vulnerability(
                            scan_id=scan_id,
                            title=vuln_data.title,
                            description=vuln_data.description,
                            severity=vuln_data.severity,
                            scanner_type=vuln_data.scanner_type,
                            affected_url=vuln_data.affected_url,
                            cve=vuln_data.cve,
                            recommendation=vuln_data.recommendation,
                            evidence=vuln_data.evidence
                        )
                        db.add(vuln)
                        await db.commit()
                        logger.info(f"Saved vulnerability in real-time: {vuln_data.title}")
                    except Exception as e:
                        logger.error(f"Error saving vulnerability in real-time: {e}")
                        await db.rollback()
                
                # Run nuclei scan with real-time callback
                nuclei_result = await nuclei_scanner.scan(
                    target_url, 
                    options,
                    on_vulnerability_found=save_vulnerability_realtime
                )
                
                if nuclei_result.success:
                    vulnerabilities.extend(nuclei_result.vulnerabilities)
                else:
                    logger.warning(f"Nuclei scan failed: {nuclei_result.error}")
            
            elif scan_type == "custom":
                logger.info("Running custom scanner...")
                custom_result = await custom_scanner.scan(target_url, options)
                if custom_result.success:
                    vulnerabilities.extend(custom_result.vulnerabilities)
                else:
                    logger.warning(f"Custom scan failed: {custom_result.error}")
            
            # Save vulnerabilities to database
            for vuln_data in vulnerabilities:
                # Convert VulnerabilityResponse to database model
                vuln = Vulnerability(
                    scan_id=scan_id,
                    title=vuln_data.title,
                    description=vuln_data.description,
                    severity=vuln_data.severity,
                    scanner_type=vuln_data.scanner_type,
                    affected_url=vuln_data.affected_url,
                    cve=vuln_data.cve,
                    recommendation=vuln_data.recommendation,
                    evidence=vuln_data.evidence
                )
                db.add(vuln)
            
            # Update scan status to completed
            scan.status = ScanStatus.COMPLETED
            scan.completed_at = datetime.utcnow()
            await db.commit()
            
            logger.info(f"Scan {scan_id} completed: found {len(vulnerabilities)} vulnerabilities")
        
        except Exception as e:
            logger.exception(f"Error running scan {scan_id}: {e}")
            # Update scan status to failed
            try:
                result = await db.execute(select(Scan).where(Scan.id == scan_id))
                scan = result.scalar_one()
                scan.status = ScanStatus.FAILED
                scan.error_message = str(e)
                await db.commit()
            except Exception as db_error:
                logger.error(f"Error updating scan status: {db_error}")


@app.get("/", response_model=HealthResponse)
async def root():
    """Root endpoint - health check."""
    return HealthResponse(
        status="healthy",
        version="1.0.0",
        database="connected"
    )


@app.get("/health", response_model=HealthResponse)
async def health():
    """Health check endpoint."""
    return HealthResponse(
        status="healthy",
        version="1.0.0",
        database="connected"
    )


@app.post("/api/scans", response_model=ScanResponse, status_code=201)
async def create_scan(
    scan_request: ScanRequest,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db)
):
    """
    Create a new vulnerability scan.
    
    Args:
        scan_request: Scan request with target URL and scan type
        background_tasks: FastAPI background tasks
        db: Database session
    
    Returns:
        Created scan response
    """
    # Validate scan type
    valid_scan_types = ["nmap", "nuclei", "custom"]
    if scan_request.scan_type not in valid_scan_types:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid scan_type. Must be one of: {', '.join(valid_scan_types)}"
        )
    
    # Create scan record
    scan = Scan(
        target_url=scan_request.target_url,
        scan_type=scan_request.scan_type,
        status=ScanStatus.PENDING,
        scan_metadata=scan_request.options
    )
    db.add(scan)
    await db.commit()
    await db.refresh(scan)
    
    # Start background scan task
    background_tasks.add_task(
        run_scan_task,
        scan.id,
        scan_request.target_url,
        scan_request.scan_type,
        scan_request.options or {}
    )
    
    logger.info(f"Created scan {scan.id} for {scan_request.target_url}")
    
    return ScanResponse(
        id=scan.id,
        target_url=scan.target_url,
        scan_type=scan.scan_type,
        status=scan.status,
        created_at=scan.created_at,
        started_at=scan.started_at,
        completed_at=scan.completed_at,
        error_message=scan.error_message,
        scan_metadata=scan.scan_metadata,
        vulnerabilities=[]
    )


@app.get("/api/scans", response_model=ScanListResponse)
async def list_scans(
    skip: int = 0,
    limit: int = 100,
    db: AsyncSession = Depends(get_db)
):
    """
    List all scans.
    
    Args:
        skip: Number of records to skip
        limit: Maximum number of records to return
        db: Database session
    
    Returns:
        List of scans
    """
    # Get total count
    count_result = await db.execute(select(Scan))
    total = len(count_result.scalars().all())
    
    # Get scans
    result = await db.execute(
        select(Scan)
        .order_by(Scan.created_at.desc())
        .offset(skip)
        .limit(limit)
    )
    scans = result.scalars().all()
    
    # Get vulnerabilities for each scan
    scan_responses = []
    for scan in scans:
        vuln_result = await db.execute(
            select(Vulnerability).where(Vulnerability.scan_id == scan.id)
        )
        vulnerabilities = [
            VulnerabilityResponse(
                id=v.id,
                title=v.title,
                description=v.description,
                severity=v.severity,
                scanner_type=v.scanner_type,
                affected_url=v.affected_url,
                cve=v.cve,
                recommendation=v.recommendation,
                evidence=v.evidence,
                discovered_at=v.discovered_at
            )
            for v in vuln_result.scalars().all()
        ]
        
        scan_responses.append(ScanResponse(
            id=scan.id,
            target_url=scan.target_url,
            scan_type=scan.scan_type,
            status=scan.status,
            created_at=scan.created_at,
            started_at=scan.started_at,
            completed_at=scan.completed_at,
            error_message=scan.error_message,
            scan_metadata=scan.scan_metadata,
            vulnerabilities=vulnerabilities
        ))
    
    return ScanListResponse(scans=scan_responses, total=total)


@app.get("/api/scans/{scan_id}", response_model=ScanResponse)
async def get_scan(
    scan_id: int,
    db: AsyncSession = Depends(get_db)
):
    """
    Get scan by ID with vulnerabilities.
    
    Args:
        scan_id: Scan ID
        db: Database session
    
    Returns:
        Scan response with vulnerabilities
    """
    # Get scan
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalar_one_or_none()
    
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    # Get vulnerabilities
    vuln_result = await db.execute(
        select(Vulnerability).where(Vulnerability.scan_id == scan_id)
    )
    vulnerabilities = [
        VulnerabilityResponse(
            id=v.id,
            title=v.title,
            description=v.description,
            severity=v.severity,
            scanner_type=v.scanner_type,
            affected_url=v.affected_url,
            cve=v.cve,
            recommendation=v.recommendation,
            evidence=v.evidence,
            discovered_at=v.discovered_at
        )
        for v in vuln_result.scalars().all()
    ]
    
    return ScanResponse(
        id=scan.id,
        target_url=scan.target_url,
        scan_type=scan.scan_type,
        status=scan.status,
        created_at=scan.created_at,
        started_at=scan.started_at,
        completed_at=scan.completed_at,
        error_message=scan.error_message,
        scan_metadata=scan.scan_metadata,
        vulnerabilities=vulnerabilities
    )


@app.get("/api/scans/{scan_id}/vulnerabilities", response_model=List[VulnerabilityResponse])
async def get_scan_vulnerabilities(
    scan_id: int,
    severity: str = None,
    db: AsyncSession = Depends(get_db)
):
    """
    Get vulnerabilities for a scan, optionally filtered by severity.
    
    Args:
        scan_id: Scan ID
        severity: Optional severity filter (critical, high, medium, low, info)
        db: Database session
    
    Returns:
        List of vulnerabilities
    """
    # Verify scan exists
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalar_one_or_none()
    
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    # Build query
    query = select(Vulnerability).where(Vulnerability.scan_id == scan_id)
    
    if severity:
        from app.database import Severity
        try:
            severity_enum = Severity(severity.lower())
            query = query.where(Vulnerability.severity == severity_enum)
        except ValueError:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid severity. Must be one of: critical, high, medium, low, info"
            )
    
    vuln_result = await db.execute(query)
    vulnerabilities = [
        VulnerabilityResponse(
            id=v.id,
            title=v.title,
            description=v.description,
            severity=v.severity,
            scanner_type=v.scanner_type,
            affected_url=v.affected_url,
            cve=v.cve,
            recommendation=v.recommendation,
            evidence=v.evidence,
            discovered_at=v.discovered_at
        )
        for v in vuln_result.scalars().all()
    ]
    
    return vulnerabilities


@app.delete("/api/scans/{scan_id}", status_code=204)
async def delete_scan(
    scan_id: int,
    db: AsyncSession = Depends(get_db)
):
    """
    Delete a scan and its vulnerabilities.
    
    Args:
        scan_id: Scan ID
        db: Database session
    """
    # Get scan
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalar_one_or_none()
    
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    # Delete vulnerabilities first
    vuln_result = await db.execute(
        select(Vulnerability).where(Vulnerability.scan_id == scan_id)
    )
    for vuln in vuln_result.scalars().all():
        await db.delete(vuln)
    
    # Delete scan
    await db.delete(scan)
    await db.commit()
    
    logger.info(f"Deleted scan {scan_id}")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "app.main:app",
        host=settings.api_host,
        port=settings.api_port,
        reload=settings.api_reload
    )

