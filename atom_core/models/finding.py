import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone


@dataclass
class Finding:
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

    finding_id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])

    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self):
        return asdict(self)

    def __str__(self):

        return (
            f"\n[{self.status}] {self.title}\n"
            f"--------------------------------\n"
            f"ID: {self.finding_id}\n"
            f"Severity: {self.severity}\n"
            f"Category: {self.category}\n"
            f"Module: {self.module}\n"
            f"Details: {self.details}\n"
            f"Impact: {self.impact}\n"
            f"Recommendation: {self.recommendation}\n"
            f"Reference: {self.reference}\n"
            f"Timestamp: {self.timestamp}\n"
        )
