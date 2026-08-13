"""Scanner output parsers."""

from __future__ import annotations

from strix.toolbox.parsers import parse_nmap_xml, parse_nuclei, parse_semgrep, parse_subfinder


def test_parse_nuclei_jsonl() -> None:
    raw = (
        '{"template-id":"sqli","info":{"name":"SQL Injection","severity":"high"},'
        '"matched-at":"http://127.0.0.1/item?id=1"}\n'
    )
    findings = parse_nuclei(raw)
    assert findings[0]["title"] == "SQL Injection"
    assert findings[0]["severity"] == "high"


def test_parse_semgrep() -> None:
    raw = """{"results":[{"check_id":"python.lang.security","path":"a.py","start":{"line":3},"extra":{"message":"sql","severity":"ERROR","lines":"cur.execute(q)"}}]}"""
    findings = parse_semgrep(raw)
    assert findings[0]["file"] == "a.py"
    assert findings[0]["line"] == 3


def test_parse_subfinder_lines() -> None:
    assert parse_subfinder("a.example.com\nb.example.com\n") == ["a.example.com", "b.example.com"]


def test_parse_nmap_xml() -> None:
    xml = """<?xml version="1.0"?>
    <nmaprun>
      <host>
        <status state="up"/>
        <address addr="127.0.0.1"/>
        <ports>
          <port protocol="tcp" portid="80"><state state="open"/><service name="http"/></port>
        </ports>
      </host>
    </nmaprun>
    """
    parsed = parse_nmap_xml(xml)
    assert parsed["hosts"][0]["address"] == "127.0.0.1"
    assert parsed["hosts"][0]["ports"][0]["port"] == "80"
