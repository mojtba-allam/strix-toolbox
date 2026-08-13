"""No-LLM Strix security toolbox.

This package is the Cursor MCP execution layer. It must not import
``strix.agents``, ``strix.interface.main``, or any LLM provider.
"""

from __future__ import annotations


__all__ = ["TOOLBOX_NAME"]

TOOLBOX_NAME = "strix-toolbox"
