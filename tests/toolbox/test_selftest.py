"""Self-test report tests."""

from __future__ import annotations

from strix.toolbox.selftest import format_self_test, run_self_test


def test_self_test_does_not_require_llm() -> None:
    report = run_self_test()
    assert report["checks"]["LLM dependency"]["status"] == "NOT REQUIRED"
    assert report["checks"]["Runtime"]["ok"] is True
    text = format_self_test(report)
    assert "Strix Toolbox Self-Test" in text
    assert "LLM dependency: NOT REQUIRED" in text
    assert "Overall:" in text
