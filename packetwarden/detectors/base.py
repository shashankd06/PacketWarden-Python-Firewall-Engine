"""Base detector abstractions and Alert model."""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any


@dataclass(slots=True, frozen=True)
class Alert:
    """Security alert emitted by a detector."""

    detector_name: str
    severity: str  # 'LOW', 'MEDIUM', 'HIGH'
    source_ip: str
    start_time: float
    end_time: float
    evidence: dict[str, Any]
    description: str


class BaseDetector(ABC):
    """Abstract base class for streaming attack detectors."""

    @abstractmethod
    def process_packet(self, pkt: Any, conn: Any = None) -> list[Alert]:
        """Process packet and return list of new alerts triggered."""
        raise NotImplementedError
