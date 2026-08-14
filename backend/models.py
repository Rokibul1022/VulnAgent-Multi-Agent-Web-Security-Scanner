from datetime import datetime, timezone
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


class ScanMode(str, Enum):
    LIGHT = "light"
    FULL = "full"


class Finding(BaseModel):
    finding_id: str = ""
    source_tool: str
    title: str
    severity: str  # info/low/medium/high/critical
    category: str = "Other"
    description: str
    location: str  # URL, param, or header name
    raw_evidence: str = ""
    hint: str = ""
    cwe: Optional[str] = None


class ScanRequest(BaseModel):
    url: str
    authorization_confirmed: bool = False
    scan_mode: ScanMode = ScanMode.LIGHT


class ScanJob(BaseModel):
    job_id: str
    url: str
    scan_mode: ScanMode
    authorization_confirmed: bool
    created_at: str = Field(default_factory=utcnow)
    status: str = "queued"  # queued/running/completed/failed
    stages: dict = {}
    feed: list = []
    report: Optional[dict] = None


class Report(BaseModel):
    job_id: str
    url: str
    scan_mode: ScanMode
    scanned_at: str
    summary: dict = {}
    findings: list[Finding] = []
    screenshots: list[dict] = []
    executive_summary: str = ""
    top_risks: list[dict] = []