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

    reference: str = ""

    finding_id: str = field(
        default_factory=lambda:
            str(uuid.uuid4())[:8]
    )

    timestamp: str = field(
        default_factory=lambda:
            datetime.datetime.now(
                datetime.UTC
            ).isoformat()
    )