"""OWASP ZAP agent driven through its Docker REST API.

Runs a headless ZAP container (zaproxy/zap-stable), spiders the target and
either passively scans (light mode) or runs the full active scan (full mode),
then pulls alerts and normalizes them into Findings.

Gracefully skips when Docker is unavailable or the image has not been pulled —
the rest of the pipeline must never hang on ZAP.
"""

import asyncio
import json
import random
import re
import urllib.parse

import httpx

from agents._common import run_capture

ZAP_IMAGE = "zaproxy/zap-stable"
API_POLL = 3
SPIDER_TIMEOUT = 300
ASCAN_TIMEOUT = 900
STARTUP_TIMEOUT = 180
MAX_ALERTS = 30

RISK_MAP = {3: "high", 2: "medium", 1: "low", 0: "info"}
CATEGORY_RULES = [
    (re.compile(r"cross.?site.?scripting|reflected xss|stored xss|sql injection|command injection|path traversal", re.I),
     "Web App / Injection"),
    (re.compile(r"cors", re.I), "CORS"),
    (re.compile(r"auth|jwt|session", re.I), "Auth/JWT"),
    (re.compile(r"header", re.I), "Headers"),
]


class ZapScanAgent:
    name = "scan_zap"

    async def run(self, context):
        if not await _docker_ready():
            await context.emit_agent(
                self.name,
                "Docker unavailable — ZAP skipped (install docker/colima and "
                "`docker pull zaproxy/zap-stable`)",
            )
            context.results[self.name] = {"skipped": "docker unavailable"}
            return

        if not await _image_present():
            await context.emit_agent(
                self.name, "zaproxy/zap-stable image not pulled — run "
                "`docker pull zaproxy/zap-stable`. ZAP skipped."
            )
            context.results[self.name] = {"skipped": "image not pulled"}
            return

        await context.emit_agent(
            self.name, f"starting ZAP container ({ZAP_IMAGE})"
        )
        container = None
        base = "http://127.0.0.1"
        try:
            host_port = 18090 + random.randint(0, 2000)
            container, err = await _start_container(context, host_port)
            if not container:
                await context.emit_agent(self.name, f"ZAP container failed to start: {err}")
                return

            api = f"{base}:{host_port}"
            await _wait_ready(context, api)
            await _api(context, api, "core/action/newSession", {"name": "scan", "overwrite": "true"})

            await _api(context, api, "core/action/accessUrl", {"url": context.url})
            await _spider(context, api)
            await context.emit_agent(self.name, "spider done")

            if context.scan_mode == "full":
                await context.emit_agent(self.name, "running active scan (full mode)")
                await _active_scan(context, api)
                await context.emit_agent(self.name, "active scan done")

            findings = await _fetch_alerts(context, api)
            context.findings.extend(findings)
            context.results[self.name] = {"findings": len(findings)}
            await context.emit_agent(self.name, f"ZAP done: {len(findings)} finding(s)")
        except Exception as exc:  # noqa: BLE001
            await context.emit_agent(self.name, f"ZAP error: {exc}")
            context.results[self.name] = {"error": str(exc)}
        finally:
            if container:
                await _stop_container(container)


async def _docker_ready() -> bool:
    found, out, _, _ = await run_capture(["docker", "version", "--format", "{{.Server.Version}}"], timeout=20)
    return bool(found and out and out.strip())


async def _image_present() -> bool:
    found, _, _, rc = await run_capture(["docker", "image", "inspect", ZAP_IMAGE], timeout=20)
    return bool(found and rc == 0)


async def _start_container(context, host_port):
    name = f"vuln-zap-{context.job.job_id[:8]}"
    cmd = [
        "docker", "run", "-d", "--name", name,
        "-p", f"127.0.0.1:{host_port}:8090",
        ZAP_IMAGE,
        "zap.sh", "-daemon", "-host", "0.0.0.0", "-port", "8090",
        "-config", "api.disablekey=true",
        "-config", "api.addrs.addr.name=.*",
        "-config", "api.addrs.addr.regex=true",
    ]
    found, out, err, rc = await run_capture(cmd, timeout=120)
    if not found or rc != 0:
        return None, (err or b"").decode(errors="replace")[:300] or (out or b"").decode()[:300]
    return name, None


async def _stop_container(name):
    await run_capture(["docker", "rm", "-f", name], timeout=60)


async def _wait_ready(context, api):
    async with httpx.AsyncClient(timeout=5.0) as client:
        for _ in range(STARTUP_TIMEOUT // API_POLL):
            try:
                r = await client.get(f"{api}/JSON/core/view/version")
                if r.status_code == 200:
                    await context.emit_agent(self.name, "ZAP API ready")
                    return
            except httpx.HTTPError:
                pass
            await asyncio.sleep(API_POLL)
    raise RuntimeError("ZAP API did not become ready in time")


async def _api(context, api, path, params) -> dict | None:
    url = f"{api}/JSON/{path}"
    async with httpx.AsyncClient(timeout=60.0) as client:
        try:
            r = await client.post(url, data=params)
            if r.status_code == 200:
                return r.json()
        except httpx.HTTPError:
            pass
    return None


async def _spider(context, api):
    data = await _api(context, api, "spider/action/scan", {"url": context.url, "maxChildren": "10"})
    scan_id = (data or {}).get("scan") or "0"
    elapsed = 0
    async with httpx.AsyncClient(timeout=15.0) as client:
        while elapsed < SPIDER_TIMEOUT:
            try:
                r = await client.get(
                    f"{api}/JSON/spider/view/status", params={"scanId": scan_id}
                )
                status = (r.json().get("status") if r.status_code == 200 else "") or "0"
            except (httpx.HTTPError, json.JSONDecodeError):
                status = "0"
            await context.emit_agent(self.name, f"spider progress: {status}%")
            if status == "100":
                return
            await asyncio.sleep(API_POLL)
            elapsed += API_POLL
    await context.emit_agent(self.name, "spider timed out — continuing with scanned pages")


async def _active_scan(context, api):
    data = await _api(context, api, "ascan/action/scan", {"url": context.url, "recurse": "true"})
    scan_id = (data or {}).get("scan") or "0"
    elapsed = 0
    async with httpx.AsyncClient(timeout=15.0) as client:
        while elapsed < ASCAN_TIMEOUT:
            try:
                r = await client.get(
                    f"{api}/JSON/ascan/view/status", params={"scanId": scan_id}
                )
                status = (r.json().get("status") if r.status_code == 200 else "") or "0"
            except (httpx.HTTPError, json.JSONDecodeError):
                status = "0"
            await context.emit_agent(self.name, f"active scan progress: {status}%")
            if status == "100":
                return
            await asyncio.sleep(API_POLL)
            elapsed += API_POLL
    await context.emit_agent(self.name, "active scan timed out")


async def _fetch_alerts(context, api) -> list:
    params = {"baseurl": context.url, "start": "0", "count": str(MAX_ALERTS * 3)}
    async with httpx.AsyncClient(timeout=30.0) as client:
        try:
            r = await client.get(f"{api}/JSON/core/view/alerts", params=params)
            alerts = r.json() if r.status_code == 200 else []
        except (httpx.HTTPError, json.JSONDecodeError):
            return []

    findings = []
    seen = set()
    for a in alerts:
        risk = int(a.get("risk", 0) or 0)
        confidence = int(a.get("confidence", 0) or 0)
        if confidence <= 0:
            continue  # suspected false positive
        title = a.get("alert") or "ZAP alert"
        url = a.get("url") or context.url
        key = (title, url)
        if key in seen:
            continue
        seen.add(key)
        severity = RISK_MAP.get(risk, "info")
        findings.append(_finding(title, severity, url, a))
        if len(findings) >= MAX_ALERTS:
            break
    return findings


def _category(title: str) -> str:
    for rule, cat in CATEGORY_RULES:
        if rule.search(title):
            return cat
    return "Web App / Injection"


def _finding(title, severity, url, alert: dict):
    from models import Finding
    desc = alert.get("description") or title
    if alert.get("solution"):
        desc = f"{desc} Remediation direction: {alert['solution'][:400]}"
    evidence = alert.get("evidence") or ""
    cwe = alert.get("cweid")
    cwe = f"CWE-{cwe}" if cwe else None
    return Finding(
        source_tool="scan_zap",
        title=title,
        severity=severity,
        category=_category(title),
        description=desc[:800],
        location=url,
        raw_evidence=evidence[:400],
        hint="Address the underlying injection/configuration issue in the "
             "application (see OWASP category above); validate and encode input, "
             "and fix the referenced URL/parameter.",
        cwe=cwe,
    )