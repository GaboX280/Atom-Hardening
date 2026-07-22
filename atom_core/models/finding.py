from dataclasses import dataclass
from typing import Optional

@dataclass
class Finding:
    
    #Representa una vulnerabilidad o hallazgo de seguridad en un sistema o aplicación.
    
    title: str
    status: str
    severity: str
    recommendation: str
    details: Optional[str] = None