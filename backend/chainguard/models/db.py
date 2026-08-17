"""Persistence for completed scans.

SQLite via SQLAlchemy, chosen so a demo can never fail because a database service
is not running.

**Storage shape:** each scan is one row carrying queryable summary columns plus
the full result as JSON. The alternative — fully normalised tables for packages,
signals, vulnerabilities and call paths — was considered and rejected: the result
is a deeply nested document that is always read whole, the schema is still moving,
and four extra tables would buy nothing that the summary columns do not already
provide for listing and filtering. The JSON column keeps the API able to return a
complete historical result without a five-way join.
"""

from __future__ import annotations

import json
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any, Iterator, Optional

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Float,
    Integer,
    String,
    Text,
    create_engine,
    desc,
)
from sqlalchemy.orm import Session, declarative_base, sessionmaker

from chainguard.config import get_settings
from chainguard.logging_setup import get_logger

logger = get_logger(__name__)

Base = declarative_base()


class ScanRecord(Base):
    """One completed (or running) scan."""

    __tablename__ = "scans"

    id = Column(String(32), primary_key=True)
    target = Column(String(255), nullable=False, default="")
    ecosystem = Column(String(32), nullable=False, default="")
    status = Column(String(32), nullable=False, default="running")
    created_at = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    duration_seconds = Column(Float, nullable=False, default=0.0)

    # Summary columns, duplicated out of the JSON so listings and filters do not
    # have to parse every stored document.
    total_packages = Column(Integer, nullable=False, default=0)
    malicious_packages = Column(Integer, nullable=False, default=0)
    suspicious_packages = Column(Integer, nullable=False, default=0)
    total_vulnerabilities = Column(Integer, nullable=False, default=0)
    reachable_vulnerabilities = Column(Integer, nullable=False, default=0)
    unreachable_vulnerabilities = Column(Integer, nullable=False, default=0)
    reachability_available = Column(Boolean, nullable=False, default=False)
    model_source = Column(String(32), nullable=False, default="rules-baseline")

    result_json = Column(Text, nullable=False, default="{}")

    def to_summary(self) -> dict[str, Any]:
        """Lightweight representation for list endpoints."""
        # SQLite has no timezone-aware column type, so the UTC timestamp comes
        # back naive. Serialising it without an offset makes the browser read
        # UTC as local time — scans then display hours off, which looks like
        # broken history rather than a formatting bug. Re-attach UTC on the way
        # out so the client converts correctly.
        created = self.created_at
        if created is not None and created.tzinfo is None:
            created = created.replace(tzinfo=timezone.utc)

        return {
            "scan_id": self.id,
            "target": self.target,
            "ecosystem": self.ecosystem,
            "status": self.status,
            "created_at": created.isoformat() if created else None,
            "duration_seconds": round(self.duration_seconds or 0.0, 2),
            "total_packages": self.total_packages,
            "malicious_packages": self.malicious_packages,
            "suspicious_packages": self.suspicious_packages,
            "total_vulnerabilities": self.total_vulnerabilities,
            "reachable_vulnerabilities": self.reachable_vulnerabilities,
            "unreachable_vulnerabilities": self.unreachable_vulnerabilities,
            "reachability_available": self.reachability_available,
            "model_source": self.model_source,
        }

    def to_result(self) -> dict[str, Any]:
        try:
            return json.loads(self.result_json or "{}")
        except json.JSONDecodeError:
            logger.warning("Stored result for scan %s is not valid JSON", self.id)
            return {}


_engine = None
_SessionFactory: Optional[sessionmaker] = None


def get_engine():
    global _engine
    if _engine is None:
        url = get_settings().database_url
        # check_same_thread=False: FastAPI runs sync DB work in a threadpool, so a
        # connection can legitimately be used from a different thread.
        connect_args = {"check_same_thread": False} if url.startswith("sqlite") else {}
        _engine = create_engine(url, connect_args=connect_args, future=True)
    return _engine


def init_db() -> None:
    """Create tables if they do not exist."""
    Base.metadata.create_all(get_engine())


@contextmanager
def session_scope() -> Iterator[Session]:
    """A transactional session."""
    global _SessionFactory
    if _SessionFactory is None:
        _SessionFactory = sessionmaker(bind=get_engine(), expire_on_commit=False, future=True)

    session = _SessionFactory()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def save_scan(result: Any) -> None:
    """Insert or update the stored record for a scan result."""
    payload = result.model_dump(mode="json") if hasattr(result, "model_dump") else dict(result)
    summary = payload.get("summary") or {}

    with session_scope() as session:
        record = session.get(ScanRecord, payload["scan_id"])
        if record is None:
            record = ScanRecord(id=payload["scan_id"])
            session.add(record)

        record.target = str(payload.get("target", ""))[:255]
        record.ecosystem = str(payload.get("ecosystem", ""))[:32]
        record.status = str(payload.get("status", "completed"))[:32]
        record.duration_seconds = float(payload.get("duration_seconds", 0.0))
        record.total_packages = int(summary.get("total_packages", 0))
        record.malicious_packages = int(summary.get("malicious_packages", 0))
        record.suspicious_packages = int(summary.get("suspicious_packages", 0))
        record.total_vulnerabilities = int(summary.get("total_vulnerabilities", 0))
        record.reachable_vulnerabilities = int(summary.get("reachable_vulnerabilities", 0))
        record.unreachable_vulnerabilities = int(summary.get("unreachable_vulnerabilities", 0))
        record.reachability_available = bool(payload.get("reachability_available", False))
        record.model_source = str(payload.get("model_source", "rules-baseline"))[:32]
        record.result_json = json.dumps(payload)


def load_scan(scan_id: str) -> Optional[dict[str, Any]]:
    with session_scope() as session:
        record = session.get(ScanRecord, scan_id)
        return record.to_result() if record else None


def list_scans(limit: int = 50) -> list[dict[str, Any]]:
    with session_scope() as session:
        records = (
            session.query(ScanRecord)
            .order_by(desc(ScanRecord.created_at))
            .limit(limit)
            .all()
        )
        return [r.to_summary() for r in records]


def delete_scan(scan_id: str) -> bool:
    with session_scope() as session:
        record = session.get(ScanRecord, scan_id)
        if record is None:
            return False
        session.delete(record)
        return True
