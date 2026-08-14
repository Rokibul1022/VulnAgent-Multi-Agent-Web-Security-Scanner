"""TLS scan agent: wraps testssl.sh --jsonfile output into Findings."""

import asyncio
import json
import os
import signal
import tempfile
from urllib.parse import urlparse

from models import Finding

TLS_TIMEOUT = 120

SEV_MAP = {"HIGH": "high", "MEDIUM": "medium", "LOW": "low", "WARN": "medium", "CRITICAL": "critical"}
SKIP_IDS = ("cipher-", "engine_problem")
KEEP_SEVS = {"HIGH", "MEDIUM", "LOW", "WARN", "CRITICAL"}


class TLSScanAgent:
    name = "scan_tls"

    def __init__(self, timeout: int = TLS_TIMEOUT):
        self.timeout = timeout

    async def run(self, context):
        cap = 30 if context.scan_mode == "light" else 240
        self.timeout = min(self.timeout, cap)
        host, port = _host_port(context.url)
        if not host:
            await context.emit_agent(self.name, "no host parsed, skipping")
            return

        await context.emit_agent(self.name, f"launching testssl.sh against {host}:{port}")

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tf:
            outfile = tf.name

        cmd = [
            "testssl.sh",
            "--quiet",
            "--fast",          # big speedup: skips deepest checks, keeps top findings
            "--ip=one",
            "--jsonfile", outfile,
            f"{host}:{port}",
        ]

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
                start_new_session=True,
            )
        except FileNotFoundError:
            await context.emit_agent(
                self.name, "testssl.sh not found — install with `brew install testssl`"
            )
            os.unlink(outfile)
            return

        try:
            await asyncio.wait_for(proc.wait(), timeout=self.timeout)
        except asyncio.TimeoutError:
            _kill_group(proc)
            await context.emit_agent(
                self.name, f"hit {self.timeout}s cap, keeping partial results"
            )

        findings = _parse_jsonfile(outfile, context, host, port)
        try:
            os.unlink(outfile)
        except OSError:
            pass

        context.findings.extend(findings)
        await context.emit_agent(
            self.name, f"testssl finished: {len(findings)} finding(s)"
        )


def _kill_group(proc):
    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        try:
            proc.kill()
        except ProcessLookupError:
            pass


def _parse_jsonfile(path, context, host, port) -> list[Finding]:
    try:
        text = open(path, encoding="utf-8", errors="replace").read()
    except OSError:
        return []
    entries = _parse_partial(text)
    findings = []
    seen = set()
    for e in entries:
        sev = e.get("severity", "")
        if sev not in KEEP_SEVS:
            continue
        fid = e.get("id", "")
        if any(fid.startswith(p) for p in SKIP_IDS):
            continue
        key = (fid, e.get("finding", ""))
        if key in seen:
            continue
        seen.add(key)
        findings.append(_to_finding(e, host, port))
    return findings


def _to_finding(e: dict, host: str, port: str) -> Finding:
    finding_text = str(e.get("finding") or "").strip()
    desc = finding_text
    if e.get("cve"):
        desc = f"{desc}\nCVEs: {e['cve']}".strip()
    return Finding(
        source_tool="testssl",
        title=_title(e.get("id", ""), finding_text),
        severity=SEV_MAP.get(e.get("severity", ""), "info"),
        category="Transport",
        description=desc,
        location=f"{host}:{port}",
        raw_evidence=f"{e.get('id')}: {finding_text}"[:500],
        cwe=e.get("cwe") or None,
    )


def _title(fid: str, finding_text: str) -> str:
    human = {
        "TLS1": "TLS 1.0 offered",
        "TLS1_1": "TLS 1.1 offered",
        "SWEET32": "SWEET32 — 64-bit block ciphers",
        "BREACH": "BREACH — HTTP compression",
        "BEAST": "BEAST — CBC ciphers",
        "LUCKY13": "LUCKY13 — CBC padding oracle",
        "cipherlist_3DES_IDEA": "Triple-DES / IDEA ciphers offered",
        "cipherlist_OBSOLETED": "Obsoleted CBC ciphers offered",
        "cipherlist_EXPORT": "Export-grade ciphers offered",
        "cipherlist_NULL": "NULL cipher suites offered",
        "cipherlist_AUTH": "Anonymous cipher suites offered",
        "cert_keyUsage": "Certificate keyUsage issue",
        "cert_chain_of_trust": "Broken chain of trust",
        "cert_expirationStatus": "Certificate expiration issue",
        "cert_signatureAlgorithm": "Weak certificate signature",
        "HSTS": "Missing HSTS header",
    }
    if fid in human:
        return human[fid]
    return fid.replace("_", " ").strip() or "TLS configuration issue"


def _parse_partial(text: str) -> list:
    """Salvage complete JSON objects from a (possibly truncated) JSON array."""
    text = text.strip()
    if text.startswith("["):
        text = text[1:]
    decoder = json.JSONDecoder()
    items = []
    while True:
        text = text.strip()
        if text.startswith(","):
            text = text[1:].strip()
        if not text:
            break
        try:
            obj, end = decoder.raw_decode(text)
        except json.JSONDecodeError:
            break
        items.append(obj)
        text = text[end:]
    return items


def _host_port(url: str) -> tuple[str | None, str | None]:
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    parsed = urlparse(url)
    host = parsed.hostname
    if not host:
        return None, None
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    return host, str(port)