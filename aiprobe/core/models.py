"""Data models for test results, findings, and configuration."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class TestStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    PASSED = "passed"
    FAILED = "failed"
    ERROR = "error"
    SKIPPED = "skipped"


class AttackCategory(str, Enum):
    # RAG
    KNOWLEDGE_POISONING = "knowledge_poisoning"
    RETRIEVAL_MANIPULATION = "retrieval_manipulation"
    INDIRECT_INJECTION = "indirect_injection"
    CITATION_HALLUCINATION = "citation_hallucination"
    CONTEXT_OVERFLOW = "context_overflow"
    # Agent
    UNAUTHORIZED_TOOL_USE = "unauthorized_tool_use"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    TOOL_CHAIN_ABUSE = "tool_chain_abuse"
    AGENT_HIJACKING = "agent_hijacking"
    SCOPE_CREEP = "scope_creep"
    # Multi-modal
    IMAGE_INJECTION = "image_injection"
    CROSS_MODAL_EXPLOIT = "cross_modal_exploit"
    STEGANOGRAPHIC_ATTACK = "steganographic_attack"
    OCR_BYPASS = "ocr_bypass"


class Finding(BaseModel):
    """A single security finding from a test."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4())[:8])
    category: AttackCategory
    severity: Severity
    title: str
    description: str
    attack_payload: str = ""
    model_response: str = ""
    evidence: str = ""
    remediation: str = ""
    owasp_mapping: str = ""
    risk_score: float = 0.0  # 0-100
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> dict[str, Any]:
        d = self.model_dump()
        d["timestamp"] = self.timestamp.isoformat()
        d["category"] = self.category.value
        d["severity"] = self.severity.value
        return d


class TestCase(BaseModel):
    """A single test case within a module."""

    id: str
    name: str
    description: str
    category: AttackCategory
    payloads: list[str] = []
    status: TestStatus = TestStatus.PENDING
    findings: list[Finding] = []


class TestResult(BaseModel):
    """Aggregated result for a test module."""

    module: str
    category: str  # rag | agent | multimodal
    total_tests: int = 0
    passed: int = 0
    failed: int = 0
    errors: int = 0
    skipped: int = 0
    findings: list[Finding] = []
    risk_score: float = 0.0
    duration_seconds: float = 0.0
    status: TestStatus = TestStatus.PENDING
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.CRITICAL)

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.HIGH)

    def to_dict(self) -> dict[str, Any]:
        d = self.model_dump()
        d["timestamp"] = self.timestamp.isoformat()
        d["status"] = self.status.value
        d["findings"] = [f.to_dict() for f in self.findings]
        d["critical_count"] = self.critical_count
        d["high_count"] = self.high_count
        return d


class ScanResult(BaseModel):
    """Top-level scan result aggregating all modules."""

    scan_id: str = Field(default_factory=lambda: f"AP-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}")
    target: str = ""
    provider: str = ""
    modules_run: list[str] = []
    results: list[TestResult] = []
    overall_risk_score: float = 0.0
    total_findings: int = 0
    critical_findings: int = 0
    high_findings: int = 0
    medium_findings: int = 0
    low_findings: int = 0
    duration_seconds: float = 0.0
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    def compute_aggregates(self):
        self.total_findings = sum(len(r.findings) for r in self.results)
        self.critical_findings = sum(r.critical_count for r in self.results)
        self.high_findings = sum(r.high_count for r in self.results)
        self.medium_findings = sum(
            1 for r in self.results for f in r.findings if f.severity == Severity.MEDIUM
        )
        self.low_findings = sum(
            1 for r in self.results for f in r.findings if f.severity == Severity.LOW
        )
        if self.results:
            self.overall_risk_score = sum(r.risk_score for r in self.results) / len(self.results)

    def to_dict(self) -> dict[str, Any]:
        self.compute_aggregates()
        d = self.model_dump()
        d["timestamp"] = self.timestamp.isoformat()
        d["results"] = [r.to_dict() for r in self.results]
        return d
