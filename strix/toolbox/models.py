"""Typed inputs and outputs for toolbox operations."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class Classification(StrEnum):
    PASSIVE = "PASSIVE"
    ACTIVE = "ACTIVE"
    DESTRUCTIVE = "DESTRUCTIVE"


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Confidence(StrEnum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class FindingLocation(BaseModel):
    file: str | None = None
    line: int | None = None
    end_line: int | None = None
    url: str | None = None
    extra: dict[str, Any] = Field(default_factory=dict)


class Finding(BaseModel):
    id: str
    severity: Severity
    title: str
    location: FindingLocation | None = None
    evidence: str = ""
    confidence: Confidence = Confidence.MEDIUM
    recommendation: str = ""
    raw_output: str = ""
    tool: str = ""
    tags: list[str] = Field(default_factory=list)


class CommandResult(BaseModel):
    success: bool
    exit_code: int | None = None
    stdout: str = ""
    stderr: str = ""
    timed_out: bool = False
    truncated: bool = False
    argv: list[str] = Field(default_factory=list)
    duration_ms: int = 0
    error: str | None = None


class ToolResult(BaseModel):
    success: bool
    classification: Classification
    error: str | None = None
    unavailable: bool = False
    warning: str | None = None
    data: dict[str, Any] = Field(default_factory=dict)

    def to_json_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json")


class TargetKind(StrEnum):
    HOST = "host"
    CIDR = "cidr"
    URL = "url"
    PATH = "path"


class AuthorizedTarget(BaseModel):
    id: str
    kind: TargetKind
    value: str
    implicit: bool = False
    note: str = ""
