"""Nuclei scan agent: wraps the nuclei CLI, normalizes JSONL into Findings."""

import asyncio
import json
import os
import tempfile
import time

from models import Finding

TEMPLATE_TIMEOUT = 300
HEARTBEAT_EVERY = 20


class NucleiScanAgent:
    name = "scan_nuclei"

    def __init__(self, timeout: int = TEMPLATE_TIMEOUT):
        self.timeout = timeout

    async def run(self, context):
        cap = 30 if context.scan_mode == "light" else 300
        self.timeout = min(self.timeout, cap)
        urls = _target_list(context)
        if not urls:
            await context.emit_agent(self.name, "no targets to scan")
            return

        await context.emit_agent(
            self.name, f"launching nuclei against {len(urls)} URL(s)"
        )

        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as tf:
            tf.write("\n".join(urls) + "\n")
            listfile = tf.name

        cmd = [
            "nuclei",
            "-l", listfile,
            "-j",          # JSONL on stdout
            "-silent",
            "-timeout", "10",
            "-exclude-tags", "ssl,tls,intrusive",  # TLS covered by testssl; intrusive too heavy
        ]
        if context.scan_mode == "light":
            cmd += ["-rl", "200", "-severity", "critical,high,medium"]
        else:
            cmd += ["-rl", "300"]

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
        except FileNotFoundError:
            await context.emit_agent(
                self.name, "nuclei not found — install with `brew install nuclei`"
            )
            os.unlink(listfile)
            return

        lines = []
        last_beat = time.monotonic()

        async def _collect():
            nonlocal last_beat
            count = 0
            async for raw in proc.stdout:
                lines.append(raw)
                count += 1
                now = time.monotonic()
                if now - last_beat >= HEARTBEAT_EVERY:
                    last_beat = now
                    await context.emit_agent(
                        self.name, f"running… {count} result(s) so far"
                    )

        try:
            await asyncio.wait_for(_collect(), timeout=self.timeout)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            await context.emit_agent(
                self.name, f"hit {self.timeout}s cap, keeping partial results"
            )

        findings = []
        for raw in lines:
            try:
                item = json.loads(raw)
            except (json.JSONDecodeError, ValueError):
                continue
            finding = _to_finding(item)
            if finding:
                findings.append(finding)

        context.findings.extend(findings)
        try:
            os.unlink(listfile)
        except OSError:
            pass
        await context.emit_agent(
            self.name, f"nuclei finished: {len(findings)} finding(s)"
        )


def _target_list(context) -> list[str]:
    urls = list(getattr(context, "targets", None) or [context.url])
    for page in (context.results.get("recon", {}) or {}).get("pages", []):
        u = page.get("url")
        if u and u not in urls:
            urls.append(u)
    cap = 25 if context.scan_mode == "full" else 1
    return urls[:cap]


def _to_finding(item: dict) -> Finding | None:
    info = item.get("info") or {}
    severity = str(info.get("severity", "info")).lower()
    if severity not in ("info", "low", "medium", "high", "critical"):
        severity = "info"

    cwes = (info.get("classification") or {}).get("cwe-id") or []
    description = info.get("description") or ""
    references = info.get("reference") or ""
    if references:
        description = f"{description}\nReference: {references}".strip()

    matched = item.get("matched-at") or item.get("host") or ""
    evidence = (
        item.get("matcher-name")
        or "\n".join(item.get("extractor-results") or [])
        or (item.get("matched-line") or "")
    )

    return Finding(
        source_tool="nuclei",
        title=info.get("name") or item.get("template-id", "nuclei finding"),
        severity=severity,
        category=_category(info.get("tags") or []),
        description=description or "Detected by nuclei template "
        f"'{item.get('template-id')}'.",
        location=matched or "",
        raw_evidence=evidence or "",
        cwe=cwes[0] if cwes else None,
    )


def _category(tags) -> str:
    t = {str(x).lower() for x in tags}
    if "cve" in t or "rce" in t or "sqli" in t or "xss" in t or "injection" in t:
        return "Web App / Injection"
    if "cors" in t:
        return "CORS"
    if "jwt" in t or "auth" in t:
        return "Auth/JWT"
    if "tls" in t or "ssl" in t or "certificate" in t:
        return "Transport"
    if "headers" in t or "csp" in t or "hsts" in t or "x-frame" in t:
        return "Headers"
    if "exposure" in t or "exposed" in t or "misconfig" in t or "default-login" in t:
        return "Content Exposure"
    if "tech" in t or "detect" in t or "fingerprint" in t or "scan" in t:
        return "Fingerprint"
    if "cve" in t:
        return "Vulnerability"
    return "Web App"