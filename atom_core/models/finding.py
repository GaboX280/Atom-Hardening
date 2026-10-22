import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import ClassVar


@dataclass
class Finding:
    """Normalized result produced by an Atom security check."""

    VALID_STATUSES: ClassVar[set[str]] = {"PASS", "WARNING", "FAIL", "ERROR"}
    VALID_SEVERITIES: ClassVar[set[str]] = {
        "CRITICAL",
        "HIGH",
        "MEDIUM",
        "LOW",
        "INFO",
    }
    VALID_CONFIDENCE: ClassVar[set[str]] = {"HIGH", "MEDIUM", "LOW"}

    title: str
    status: str
    severity: str
    details: str = ""
    impact: str = ""
    recommendation: str = ""
    category: str = "General"
    module: str = "Unknown"
    reference: str = ""
    compliance: list[str] = field(default_factory=list)
    severity_score: int = 0
    confidence: str = "HIGH"
    finding_id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def __post_init__(self) -> None:
        self.status = self.status.upper().strip()
        self.severity = self.severity.upper().strip()
        self.confidence = self.confidence.upper().strip()

        if self.status not in self.VALID_STATUSES:
            raise ValueError(f"Invalid finding status: {self.status}")
        if self.severity not in self.VALID_SEVERITIES:
            raise ValueError(f"Invalid finding severity: {self.severity}")
        if self.confidence not in self.VALID_CONFIDENCE:
            raise ValueError(f"Invalid finding confidence: {self.confidence}")
        if self.severity_score < 0:
            raise ValueError("severity_score cannot be negative")

        self.compliance = list(self.compliance)

    def to_dict(self) -> dict:
        return asdict(self)

    def __str__(self) -> str:
        return (
            f"\n[{self.status}] {self.title}\n"
            f"--------------------------------\n"
            f"ID: {self.finding_id}\n"
            f"Severity: {self.severity}\n"
            f"Confidence: {self.confidence}\n"
            f"Category: {self.category}\n"
            f"Module: {self.module}\n"
            f"Details: {self.details}\n"
            f"Impact: {self.impact}\n"
            f"Recommendation: {self.recommendation}\n"
            f"Reference: {self.reference}\n"
            f"Timestamp: {self.timestamp}\n"
        )
