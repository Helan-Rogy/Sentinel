"""Pydantic schemas for every message that crosses a domain boundary."""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Literal, Optional

from pydantic import BaseModel, Field


def now() -> datetime:
    return datetime.now(timezone.utc)


def new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:10]}"


class RiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class FileOp(str, Enum):
    CREATE = "create"
    MODIFY = "modify"
    RENAME = "rename"
    DELETE = "delete"


class ActionKind(str, Enum):
    LOG = "log"
    ALERT = "alert"
    SUSPEND_PROCESS = "suspend_process"
    QUARANTINE_FILE = "quarantine_file"
    RUN_SANDBOX = "run_sandbox"


class ActionStatus(str, Enum):
    PROPOSED = "proposed"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXECUTED = "executed"
    FAILED = "failed"
    VERIFIED = "verified"


class IncidentStatus(str, Enum):
    OPEN = "open"
    AWAITING_APPROVAL = "awaiting_approval"
    CONTAINED = "contained"
    CLOSED = "closed"
    FALSE_POSITIVE = "false_positive"


# --- Raw observations -------------------------------------------------------

class FileEvent(BaseModel):
    id: str = Field(default_factory=lambda: new_id("evt"))
    ts: datetime = Field(default_factory=now)
    endpoint_id: str = "local"
    op: FileOp
    path: str
    new_path: Optional[str] = None
    pid: Optional[int] = None
    process_name: Optional[str] = None
    size: Optional[int] = None


class EntropyResult(BaseModel):
    path: str
    ts: datetime = Field(default_factory=now)
    shannon: float = Field(ge=0, le=8)
    chi_square: Optional[float] = None
    previous_shannon: Optional[float] = None
    delta: Optional[float] = None
    type_mismatch: bool = False
    detail: str = ""


class HoneyHit(BaseModel):
    path: str
    ts: datetime = Field(default_factory=now)
    op: FileOp
    pid: Optional[int] = None
    process_name: Optional[str] = None


class SandboxReport(BaseModel):
    sample_path: str
    ts: datetime = Field(default_factory=now)
    backend: str = "stub"
    completed: bool = True
    files_touched: int = 0
    files_encrypted_like: int = 0
    extensions_changed: list[str] = Field(default_factory=list)
    yara_matches: list[str] = Field(default_factory=list)
    notes: str = ""


# --- Assessment -------------------------------------------------------------

class Signal(BaseModel):
    """One piece of evidence contributing to a verdict."""
    name: str
    value: float
    weight: float = 1.0
    detail: str = ""


class RiskAssessment(BaseModel):
    ts: datetime = Field(default_factory=now)
    level: RiskLevel
    score: float = Field(ge=0, le=1)
    method: Literal["rules", "ml", "hybrid"] = "rules"
    signals: list[Signal] = Field(default_factory=list)
    uncertainty: list[str] = Field(default_factory=list)
    summary: str = ""


# --- Agent and response -----------------------------------------------------

class AgentStep(BaseModel):
    ts: datetime = Field(default_factory=now)
    kind: Literal["observe", "tool_call", "tool_result", "reasoning", "decision", "verify"]
    text: str
    data: dict[str, Any] = Field(default_factory=dict)


class ProposedAction(BaseModel):
    id: str = Field(default_factory=lambda: new_id("act"))
    ts: datetime = Field(default_factory=now)
    kind: ActionKind
    target: Optional[str] = None
    pid: Optional[int] = None
    rationale: str = ""
    requires_approval: bool = True
    status: ActionStatus = ActionStatus.PROPOSED


class ActionResult(BaseModel):
    action_id: str
    ts: datetime = Field(default_factory=now)
    success: bool
    detail: str = ""
    verified: Optional[bool] = None


class Incident(BaseModel):
    id: str = Field(default_factory=lambda: new_id("inc"))
    created: datetime = Field(default_factory=now)
    updated: datetime = Field(default_factory=now)
    endpoint_id: str = "local"
    title: str
    status: IncidentStatus = IncidentStatus.OPEN
    assessment: Optional[RiskAssessment] = None
    process_name: Optional[str] = None
    pid: Optional[int] = None
    affected_files: int = 0
    honey_hits: list[HoneyHit] = Field(default_factory=list)
    entropy: list[EntropyResult] = Field(default_factory=list)
    sandbox: Optional[SandboxReport] = None
    steps: list[AgentStep] = Field(default_factory=list)
    actions: list[ProposedAction] = Field(default_factory=list)
    results: list[ActionResult] = Field(default_factory=list)
