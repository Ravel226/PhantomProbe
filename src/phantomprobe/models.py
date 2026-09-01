#!/usr/bin/env python3
"""
Core data models shared by every PhantomProbe engine.
"""

from dataclasses import dataclass
from enum import Enum
from typing import List




class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


@dataclass
class Finding:
    id: str
    title: str
    description: str
    severity: Severity
    category: str
    evidence: str
    remediation: str
    references: List[str]
    discovered_at: str
    target: str

