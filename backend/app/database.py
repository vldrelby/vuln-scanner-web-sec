"""
Database models and connection management.
Uses SQLAlchemy with async SQLite.
"""

from datetime import datetime
from typing import Optional, List
from sqlalchemy import Column, Integer, String, Text, DateTime, JSON, Enum as SQLEnum
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy.orm import declarative_base
import enum

from app.config import settings

Base = declarative_base()


class ScanStatus(str, enum.Enum):
    """Scan status enumeration."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class Severity(str, enum.Enum):
    """Vulnerability severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Scan(Base):
    """Scan record model."""
    __tablename__ = "scans"
    
    id = Column(Integer, primary_key=True, index=True)
    target_url = Column(String, nullable=False, index=True)
    scan_type = Column(String, nullable=False)  # nmap, nuclei, custom
    status = Column(SQLEnum(ScanStatus), default=ScanStatus.PENDING, index=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    error_message = Column(Text, nullable=True)
    scan_metadata = Column(JSON, nullable=True)  # Additional scan metadata


class Vulnerability(Base):
    """Vulnerability record model."""
    __tablename__ = "vulnerabilities"
    
    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, nullable=False, index=True)
    title = Column(String, nullable=False)
    description = Column(Text, nullable=False)
    severity = Column(SQLEnum(Severity), nullable=False, index=True)
    scanner_type = Column(String, nullable=False)  # nmap, nuclei, custom
    affected_url = Column(String, nullable=True)
    cve = Column(String, nullable=True, index=True)
    recommendation = Column(Text, nullable=True)
    evidence = Column(JSON, nullable=True)  # Additional evidence data
    discovered_at = Column(DateTime, default=datetime.utcnow)


# Database engine and session
# SQLite with async support
database_url = f"sqlite+aiosqlite:///{settings.database.path}"
engine = create_async_engine(
    database_url,
    echo=False,
    future=True
)

AsyncSessionLocal = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False
)


async def init_db():
    """Initialize database tables."""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def get_db() -> AsyncSession:
    """Get database session."""
    async with AsyncSessionLocal() as session:
        try:
            yield session
        finally:
            await session.close()

