"""Parse scanner JSON/text into structured records."""

from __future__ import annotations

import json
import re
from typing import Any
from xml.etree import ElementTree


def parse_jsonl(text: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        try:
            payload = json.loads(stripped)
        except json.JSONDecodeError:
            continue
        if isinstance(payload, dict):
            rows.append(payload)
    return rows


def parse_json(text: str) -> Any:
    stripped = text.strip()
    if not stripped:
        return None
    try:
        return json.loads(stripped)
    except json.JSONDecodeError:
        return None


def parse_nuclei(stdout: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for row in parse_jsonl(stdout):
        info = row.get("info") if isinstance(row.get("info"), dict) else {}
        findings.append(
            {
                "title": info.get("name") or row.get("template-id") or "Nuclei finding",
                "severity": str(info.get("severity") or "info").lower(),
                "template_id": row.get("template-id"),
                "host": row.get("host") or row.get("matched-at"),
                "url": row.get("matched-at") or row.get("url"),
                "evidence": str(row.get("extracted-results") or row.get("matcher-name") or ""),
                "raw": row,
            }
        )
    return findings


def parse_semgrep(stdout: str) -> list[dict[str, Any]]:
    payload = parse_json(stdout)
    if not isinstance(payload, dict):
        return []
    findings: list[dict[str, Any]] = []
    for result in payload.get("results") or []:
        extra = result.get("extra") if isinstance(result.get("extra"), dict) else {}
        start = result.get("start") if isinstance(result.get("start"), dict) else {}
        findings.append(
            {
                "title": extra.get("message") or result.get("check_id") or "Semgrep finding",
                "severity": str(extra.get("severity") or "INFO").lower(),
                "file": result.get("path"),
                "line": start.get("line"),
                "check_id": result.get("check_id"),
                "evidence": extra.get("lines") or "",
                "raw": result,
            }
        )
    return findings


def parse_bandit(stdout: str) -> list[dict[str, Any]]:
    payload = parse_json(stdout)
    if not isinstance(payload, dict):
        return []
    findings: list[dict[str, Any]] = []
    for result in payload.get("results") or []:
        findings.append(
            {
                "title": result.get("issue_text") or result.get("test_id") or "Bandit finding",
                "severity": str(result.get("issue_severity") or "medium").lower(),
                "file": result.get("filename"),
                "line": result.get("line_number"),
                "confidence": str(result.get("issue_confidence") or "medium").lower(),
                "test_id": result.get("test_id"),
                "evidence": result.get("code") or "",
                "raw": result,
            }
        )
    return findings


def parse_gitleaks(stdout: str) -> list[dict[str, Any]]:
    payload = parse_json(stdout)
    rows: list[Any]
    if isinstance(payload, list):
        rows = payload
    elif isinstance(payload, dict):
        rows = [payload]
    else:
        rows = parse_jsonl(stdout)
    findings: list[dict[str, Any]] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        findings.append(
            {
                "title": row.get("RuleID") or row.get("Description") or "Secret",
                "severity": "high",
                "file": row.get("File") or row.get("file"),
                "line": row.get("StartLine") or row.get("line"),
                "evidence": row.get("Secret") or row.get("Match") or "",
                "raw": row,
            }
        )
    return findings


def parse_trufflehog(stdout: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for row in parse_jsonl(stdout):
        detector = row.get("DetectorName") or row.get("detector") or "secret"
        source = row.get("SourceMetadata") if isinstance(row.get("SourceMetadata"), dict) else {}
        data = source.get("Data") if isinstance(source.get("Data"), dict) else {}
        filesystem = data.get("Filesystem") if isinstance(data.get("Filesystem"), dict) else {}
        findings.append(
            {
                "title": str(detector),
                "severity": "high",
                "file": filesystem.get("file") or row.get("SourceName"),
                "line": filesystem.get("line"),
                "verified": row.get("Verified"),
                "raw": row,
            }
        )
    return findings


def parse_trivy(stdout: str) -> list[dict[str, Any]]:
    payload = parse_json(stdout)
    if not isinstance(payload, dict):
        return []
    findings: list[dict[str, Any]] = []
    for result in payload.get("Results") or []:
        target = result.get("Target")
        for vuln in result.get("Vulnerabilities") or []:
            findings.append(
                {
                    "title": vuln.get("Title") or vuln.get("VulnerabilityID") or "Trivy finding",
                    "severity": str(vuln.get("Severity") or "medium").lower(),
                    "file": target,
                    "package": vuln.get("PkgName"),
                    "installed": vuln.get("InstalledVersion"),
                    "fixed": vuln.get("FixedVersion"),
                    "id": vuln.get("VulnerabilityID"),
                    "raw": vuln,
                }
            )
        for secret in result.get("Secrets") or []:
            findings.append(
                {
                    "title": secret.get("Title") or secret.get("RuleID") or "Secret",
                    "severity": str(secret.get("Severity") or "high").lower(),
                    "file": target,
                    "line": (secret.get("StartLine") or None),
                    "raw": secret,
                }
            )
        for misconfig in result.get("Misconfigurations") or []:
            findings.append(
                {
                    "title": misconfig.get("Title") or misconfig.get("ID") or "Misconfiguration",
                    "severity": str(misconfig.get("Severity") or "medium").lower(),
                    "file": target,
                    "raw": misconfig,
                }
            )
    return findings


def parse_subfinder(stdout: str) -> list[str]:
    hosts: list[str] = []
    json_rows = parse_jsonl(stdout)
    if json_rows:
        for row in json_rows:
            host = row.get("host") or row.get("fqdn")
            if isinstance(host, str):
                hosts.append(host)
        return hosts
    for line in stdout.splitlines():
        host = line.strip()
        if host:
            hosts.append(host)
    return hosts


def parse_httpx(stdout: str) -> list[dict[str, Any]]:
    rows = parse_jsonl(stdout)
    if rows:
        return rows
    return [{"url": line.strip()} for line in stdout.splitlines() if line.strip()]


def parse_naabu(stdout: str) -> list[dict[str, Any]]:
    rows = parse_jsonl(stdout)
    if rows:
        return rows
    results: list[dict[str, Any]] = []
    for line in stdout.splitlines():
        if ":" in line:
            host, port = line.rsplit(":", 1)
            results.append({"host": host.strip(), "port": port.strip()})
    return results


def parse_katana(stdout: str) -> list[dict[str, Any]]:
    rows = parse_jsonl(stdout)
    if rows:
        return rows
    return [{"url": line.strip()} for line in stdout.splitlines() if line.strip()]


def parse_wafw00f(stdout: str) -> dict[str, Any]:
    payload = parse_json(stdout)
    if isinstance(payload, dict):
        return payload
    if isinstance(payload, list) and payload:
        first = payload[0]
        return first if isinstance(first, dict) else {"raw": payload}
    detected = "is behind" in stdout.lower() or "is protected by" in stdout.lower()
    match = re.search(r"is behind ([^\n]+)", stdout, flags=re.IGNORECASE)
    return {
        "detected": detected,
        "waf": match.group(1).strip() if match else None,
        "raw": stdout[:2000],
    }


def parse_ffuf(stdout: str) -> list[dict[str, Any]]:
    payload = parse_json(stdout)
    if isinstance(payload, dict):
        results = payload.get("results") or []
        return [row for row in results if isinstance(row, dict)]
    return parse_jsonl(stdout)


def parse_nmap_xml(stdout: str) -> dict[str, Any]:
    try:
        root = ElementTree.fromstring(stdout)  # noqa: S314
    except ElementTree.ParseError:
        return {"hosts": [], "raw": stdout[:2000]}
    hosts: list[dict[str, Any]] = []
    for host in root.findall("host"):
        address = host.find("address")
        status = host.find("status")
        ports: list[dict[str, Any]] = []
        ports_el = host.find("ports")
        if ports_el is not None:
            for port in ports_el.findall("port"):
                state = port.find("state")
                service = port.find("service")
                ports.append(
                    {
                        "port": port.get("portid"),
                        "protocol": port.get("protocol"),
                        "state": None if state is None else state.get("state"),
                        "service": None if service is None else service.get("name"),
                        "product": None if service is None else service.get("product"),
                    }
                )
        hosts.append(
            {
                "address": None if address is None else address.get("addr"),
                "status": None if status is None else status.get("state"),
                "ports": ports,
            }
        )
    return {"hosts": hosts}
