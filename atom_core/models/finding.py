from dataclasses import dataclass, asdict, field
import datetime
import uuid


@dataclass
class Finding:


    title: str

    status: str

    severity: str

    details: str = ""

    recommendation: str = ""

    category: str = "General"

    module: str = "Unknown"

    finding_id: str = field(
        default_factory=lambda:
            str(uuid.uuid4())[:8]
    )


    timestamp: str = field(
        default_factory=lambda:
            datetime.datetime.now().strftime(
                "%Y-%m-%d %H:%M:%S"
            )
    )


    def to_dict(self):

        return asdict(self)



    def __str__(self):

        return (
            f"\n[{self.status}] {self.title}\n"
            f"ID: {self.finding_id}\n"
            f"Severity: {self.severity}\n"
            f"Category: {self.category}\n"
            f"Module: {self.module}\n"
            f"Details: {self.details}\n"
            f"Recommendation: {self.recommendation}\n"
            f"Timestamp: {self.timestamp}\n"
        )