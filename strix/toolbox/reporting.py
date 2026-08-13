"""Deterministic finding store (no LLM dedupe)."""

from __future__ import annotations

from threading import Lock
from typing import Any
from uuid import uuid4

from strix.toolbox.models import (
    Classification,
    Confidence,
    Finding,
    FindingLocation,
    Severity,
    ToolResult,
)


class FindingStore:
    def __init__(self) -> None:
        self._lock = Lock()
        self._items: dict[str, Finding] = {}

    def create(
        self,
        *,
        title: str,
        severity: str = "info",
        evidence: str = "",
        recommendation: str = "",
        confidence: str = "medium",
        file: str | None = None,
        line: int | None = None,
        url: str | None = None,
        raw_output: str = "",
        tool: str = "",
        tags: list[str] | None = None,
    ) -> Finding:
        finding = Finding(
            id=str(uuid4()),
            severity=Severity(severity.lower()),
            title=title,
            location=FindingLocation(file=file, line=line, url=url) if (file or url) else None,
            evidence=evidence,
            confidence=Confidence(confidence.lower()),
            recommendation=recommendation,
            raw_output=raw_output[:20_000],
            tool=tool,
            tags=tags or [],
        )
        with self._lock:
            self._items[finding.id] = finding
        return finding

    def list_findings(self) -> list[Finding]:
        with self._lock:
            return list(self._items.values())

    def get(self, finding_id: str) -> Finding | None:
        with self._lock:
            return self._items.get(finding_id)

    def clear(self) -> None:
        with self._lock:
            self._items.clear()


def create_finding_result(store: FindingStore, **kwargs: Any) -> ToolResult:
    try:
        finding = store.create(**kwargs)
    except Exception as exc:  # noqa: BLE001
        return ToolResult(success=False, classification=Classification.PASSIVE, error=str(exc))
    return ToolResult(
        success=True,
        classification=Classification.PASSIVE,
        data={"finding": finding.model_dump(mode="json")},
    )


def list_findings_result(store: FindingStore) -> ToolResult:
    return ToolResult(
        success=True,
        classification=Classification.PASSIVE,
        data={"findings": [item.model_dump(mode="json") for item in store.list_findings()]},
    )


def get_finding_result(store: FindingStore, finding_id: str) -> ToolResult:
    finding = store.get(finding_id)
    if finding is None:
        return ToolResult(
            success=False,
            classification=Classification.PASSIVE,
            error=f"finding not found: {finding_id}",
        )
    return ToolResult(
        success=True,
        classification=Classification.PASSIVE,
        data={"finding": finding.model_dump(mode="json")},
    )
