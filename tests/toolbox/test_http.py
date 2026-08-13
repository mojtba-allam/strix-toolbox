"""HTTP tool tests against a local server."""

from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from strix.toolbox.http import http_request
from strix.toolbox.safety import TargetAllowlist


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        if self.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "https://example.com/out")
            self.end_headers()
            return
        body = b'{"ok": true}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:
        return


@pytest.fixture
def local_server() -> str:
    server = HTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address[:2]
    url = f"http://{host}:{port}/"
    yield url
    server.shutdown()


def test_http_localhost(local_server: str) -> None:
    allowlist = TargetAllowlist()
    result = http_request(allowlist=allowlist, url=local_server)
    assert result.success
    assert result.data["status"] == 200
    assert "ok" in result.data["body"]


def test_http_unauthorized_remote() -> None:
    allowlist = TargetAllowlist()
    result = http_request(allowlist=allowlist, url="https://example.com/")
    assert result.success is False
    assert "not authorized" in (result.error or "")


def test_http_missing_target() -> None:
    allowlist = TargetAllowlist()
    result = http_request(allowlist=allowlist, url="not-a-url")
    assert result.success is False


def test_http_redirect_to_unauthorized(local_server: str) -> None:
    allowlist = TargetAllowlist()
    result = http_request(allowlist=allowlist, url=local_server + "redirect")
    assert result.success is False
    assert (
        "not authorized" in (result.error or "").lower()
        or "redirect" in (result.error or "").lower()
    )
