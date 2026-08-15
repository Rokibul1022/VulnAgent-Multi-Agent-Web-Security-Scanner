"""Scan orchestration.

Milestone 2: runs the real recon + header-check agents (pure Python) and
assembles a report. Triage is a deterministic dedupe pass until the LLM
triage agent lands (milestone 4).
"""

import asyncio
import time
from urllib.parse import urlparse

from agents.discovery_cms import CmsAgent
from agents.discovery_dirs import DirDiscoveryAgent
from agents.discovery_exposure import ExposureAgent
from agents.discovery_screenshot import ScreenshotAgent
from agents.recon import ReconAgent
from agents.scan_cors import CorsScanAgent
from agents.scan_headers import HeadersScanAgent
from agents.scan_jwt import JwtScanAgent
from agents.scan_nuclei import NucleiScanAgent
from agents.scan_open_redirect import OpenRedirectScanAgent
from agents.scan_secrets import SecretsScanAgent
from agents.scan_sqlmap import SqlmapScanAgent
from agents.scan_tls import TLSScanAgent
from agents.scan_zap import ZapScanAgent
from agents.surface_amass import AmassAgent
from agents.surface_dns import DnsAgent
from agents.surface_ports import PortsAgent
from agents.surface_subdomains import SubdomainsAgent
from agents.surface_waf import WafAgent
from agents.triage_llm import TriageAgent
from models import Finding, Report, ScanMode, utcnow
from storage.jobs import jobs

SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
SUBDOMAIN_CAP = 5


class ScanContext:
    def __init__(self, job, emit):
        self.job = job
        self.url = job.url
        self.scan_mode = job.scan_mode
        self.emit = emit
        self.results = {}
        self.findings: list[Finding] = []
        self.targets = [job.url]
        self.stage_errors: list[dict] = []
        self.failed_stages: set[str] = set()
        self.connection_issues: list[str] = []

    async def feed(self, event: str, data: dict) -> dict:
        entry = {"event": event, "data": data, "ts": utcnow()}
        self.job.feed.append(entry)
        await self.emit(event, data)
        return entry

    async def emit_agent(self, agent: str, line: str) -> None:
        await self.feed("agent_output", {"agent": agent, "line": f"[{agent}] {line}"})


async def run_scan(job, emit):
    context = ScanContext(job, emit)
    job.status = "running"

    agents = [
        (
            "surface", "Attack Surface",
            [SubdomainsAgent(), DnsAgent(), PortsAgent(), WafAgent(), AmassAgent()],
            True,
        ),
        ("recon", "Recon", [ReconAgent()], True),
        (
            "discovery", "Content Discovery",
            [ExposureAgent(), DirDiscoveryAgent(), CmsAgent(), ScreenshotAgent()],
            True,
        ),
        ("scans", "Scanning", [
            HeadersScanAgent(), NucleiScanAgent(), TLSScanAgent(),
            CorsScanAgent(), JwtScanAgent(), OpenRedirectScanAgent(),
            ZapScanAgent(), SecretsScanAgent(), SqlmapScanAgent(),
        ], True),
    ]

    # Light mode: get targets from the fast surface agents (subdomains/dns/waf)
    # first, then run the slow nmap scan in the background while recon,
    # discovery and the scan agents all run in parallel. Full mode keeps the
    # strict sequential DAG (each stage feeds the next).
    if job.scan_mode == ScanMode.LIGHT:
        await _run_stage(context, "surface", "Attack Surface",
                         [SubdomainsAgent(), DnsAgent(), WafAgent()], concurrent=True)
        context.targets = _compute_targets(context)
        nmap_task = asyncio.create_task(
            _run_stage(context, "ports", "Background Port Scan",
                       [PortsAgent()], concurrent=False)
        )
        scans_task = asyncio.create_task(
            _run_stage(context, *agents[-1])
        )
        recon_task = asyncio.create_task(
            _run_stage(context, *agents[1])
        )
        discovery_task = asyncio.create_task(
            _run_stage(context, *agents[2])
        )
        await asyncio.gather(nmap_task, scans_task, recon_task, discovery_task)
    else:
        for name, label, agent_list, concurrent in agents:
            await _run_stage(context, name, label, agent_list, concurrent=concurrent)
            if name == "surface":
                context.targets = _compute_targets(context)

    await _run_stage(context, "triage", "Triage", [_triage_pass, TriageAgent()], concurrent=False)
    await _run_stage(context, "report", "Report", [_build_report], concurrent=False)

    job.status = "completed"
    await context.feed("report_ready", {"job_id": job.job_id})


async def _run_stage(context, name, label, agent_list, concurrent=True):
    await context.feed("stage_start", {"stage": name, "label": label})
    t0 = time.monotonic()
    try:
        failures = 0

        async def _run_one(item):
            nonlocal failures
            agent_name = getattr(item, "name", name)
            t_start = time.monotonic()
            try:
                if hasattr(item, "run"):
                    await item.run(context)
                else:
                    await item(context)
                await context.emit_agent(
                    agent_name,
                    f"took {round(time.monotonic() - t_start, 1)}s",
                )
            except Exception as exc:  # noqa: BLE001 — one agent must never kill a stage
                failures += 1
                context.stage_errors.append(
                    {"stage": name, "agent": agent_name, "error": str(exc)}
                )
                await context.emit_agent(
                    agent_name,
                    f"error (skipped, continuing): {exc}",
                )

        if concurrent:
            await asyncio.gather(*(_run_one(a) for a in agent_list))
        else:
            for a in agent_list:
                await _run_one(a)
        if failures == len(agent_list):
            context.failed_stages.add(name)
            raise RuntimeError("all agents in this stage failed")
        await context.feed("stage_done", {"stage": name, "elapsed": round(time.monotonic() - t0, 1)})
    except Exception as exc:  # noqa: BLE001
        await context.feed("stage_failed", {"stage": name, "error": str(exc)})
        await context.emit_agent(name, f"stage failed: {exc}")


async def _triage_pass(context):
    """Deterministic dedupe + same-surface filter for now; LLM re-rank
    lands in milestone 4."""
    allowed = _allowed_hosts(context)
    seen = set()
    unique = []
    dropped = 0
    for f in context.findings:
        key = (f.source_tool, f.title, f.location)
        if key in seen:
            dropped += 1
            continue
        seen.add(key)
        if f.location:
            h = _host_of(f.location)
            if h and h not in allowed:
                dropped += 1
                continue
        unique.append(f)
    context.findings = unique
    await context.emit_agent(
        "triage", f"deduplicated/filtered {dropped} finding(s), {len(unique)} kept"
    )


def _compute_targets(context) -> list[str]:
    root = context.url
    targets = [root]
    root_host = _host_of(root)
    resolving = (context.results.get("surface_dns", {}) or {}).get("resolving", [])
    for h in resolving:
        if not h or h == root_host:
            continue
        if f"https://{h}" in targets:
            continue
        targets.append(f"https://{h}")
        if len(targets) - 1 >= SUBDOMAIN_CAP:
            break
    return targets


def _allowed_hosts(context) -> set[str]:
    allowed = {_host_of(context.url)}
    for h in (context.results.get("surface_subdomains", {}) or {}).get("subdomains", []):
        allowed.add(h.lower())
    return {a for a in allowed if a}


def _host_of(url: str) -> str | None:
    url = (url or "").strip()
    if url.startswith(("http://", "https://")):
        return (urlparse(url).hostname or "").lower()
    return url.split(":")[0].split("/")[0].strip().lower() or None


async def _build_report(context):
    findings = sorted(
        context.findings,
        key=lambda f: (SEVERITY_RANK.get(f.severity, 9), f.title),
    )
    for i, f in enumerate(findings, start=1):
        f.finding_id = f"f{i}"

    by_sev = {}
    by_category = {}
    categories = []
    for f in findings:
        by_sev[f.severity] = by_sev.get(f.severity, 0) + 1
        by_category[f.category] = by_category.get(f.category, 0) + 1
        if f.category not in categories:
            categories.append(f.category)

    warnings = list(context.connection_issues)
    for stage in sorted(context.failed_stages):
        warnings.append(f"the {stage} stage failed, so those checks could not run")
    err_counts: dict[str, int] = {}
    for e in context.stage_errors:
        err_counts[e["stage"]] = err_counts.get(e["stage"], 0) + 1
    for stage, n in sorted(err_counts.items()):
        if stage in context.failed_stages:
            continue
        warnings.append(f"{n} agent(s) in the {stage} stage errored and were skipped")

    report = Report(
        job_id=context.job.job_id,
        url=context.url,
        scan_mode=context.job.scan_mode,
        scanned_at=utcnow(),
        summary={
            "total": len(findings),
            "by_severity": by_sev,
            "by_category": by_category,
            "categories": categories,
            "risk_score": _risk_score(findings),
            "warnings": warnings,
        },
        findings=findings,
        executive_summary=_executive_summary(context, findings, by_sev, warnings),
        top_risks=_top_risks(findings),
        screenshots=[
            {"url": s.get("url", ""), "file": f"/screenshots/{context.job.job_id}/{s.get('file', '')}"}
            for s in (context.results.get("discovery_screenshot", {}) or {}).get("screenshots", [])
        ],
    )
    context.job.report = report.model_dump()
    await context.emit_agent("report", f"assembled report with {len(findings)} finding(s)")


SEV_WEIGHTS = {"critical": 10, "high": 7, "medium": 4, "low": 2, "info": 0.5}
SEV_LABELS = {"critical": "critical", "high": "high", "medium": "medium", "low": "low", "info": "informational"}


def _risk_score(findings) -> int:
    score = sum(SEV_WEIGHTS.get(f.severity, 0) for f in findings)
    return min(100, round(score))


def _top_risks(findings, n: int = 5) -> list[dict]:
    top = sorted(
        findings,
        key=lambda f: (SEVERITY_RANK.get(f.severity, 9), f.title),
    )[:n]
    return [
        {
            "severity": f.severity,
            "title": f.title,
            "location": f.location,
            "description": (f.description or "")[:200],
        }
        for f in top
    ]


def _executive_summary(context, findings, by_sev, warnings) -> str:
    mode = str(getattr(context.job, "scan_mode", "light")).split(".")[-1].lower()
    total = len(findings)
    if warnings:
        head = (
            f"VulnAgent scanned {context.url} in {mode} mode but part of the scan "
            f"failed ({len(warnings)} warning(s)) — {'; '.join(warnings)}. "
        )
        if total == 0:
            return (
                head + "No findings could be collected because the target could not be "
                "fully reached. This does not mean the site is clean — re-run the scan."
            )
        return head + f"Despite the failures, {total} issue(s) were still found below."
    if total == 0:
        return (
            f"VulnAgent scanned {context.url} in {mode} mode and did not "
            "detect any issues. No exploitable or hardening problems were observed. "
            "Consider running a full (active) scan for deeper coverage."
        )
    parts = []
    for sev in ("critical", "high", "medium", "low", "info"):
        n = by_sev.get(sev, 0)
        if n:
            parts.append(f"{n} {SEV_LABELS[sev]}")
    sev_line = ", ".join(parts) if parts else "no issues"
    head = (
        f"VulnAgent scanned {context.url} in {mode} mode and found "
        f"{total} potential issue(s): {sev_line}."
    )
    hi = by_sev.get("high", 0) + by_sev.get("critical", 0)
    if hi == 0 and by_sev.get("medium", 0) == 0:
        tail = "The findings are low-severity hardening or informational items — worth addressing, but not an emergency."
    elif hi == 0:
        tail = "No high or critical issues were confirmed; the medium-severity items below should be reviewed and fixed."
    else:
        tail = "High/critical issues were confirmed — these should be addressed before the site is exposed to real traffic."
    return f"{head} {tail} Fix the top risks below first, then re-scan to confirm."


async def scan_worker(job_id: str):
    """Background task wrapper."""
    job = jobs.get(job_id)
    if not job:
        return
    subscriber = subscribers.get(job_id)
    emit = subscriber.emit if subscriber else _null_emit

    try:
        await run_scan(job, emit)
    except Exception as exc:  # noqa: BLE001
        job.status = "failed"
        job.feed.append({"event": "scan_failed", "data": {"error": str(exc)}, "ts": utcnow()})


async def _null_emit(event, data):
    pass


class Subscriber:
    def __init__(self):
        self._queue = asyncio.Queue()

    async def emit(self, event: str, data: dict):
        await self._queue.put({"event": event, "data": data})

    async def next(self):
        return await self._queue.get()


subscribers: dict[str, Subscriber] = {}