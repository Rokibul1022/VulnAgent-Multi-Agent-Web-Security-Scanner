AGENT_NAME = "scan_secrets"

"""Committed-secret scanning (gitleaks + git-dumper).

Conditional on an exposed `.git` directory found by discovery_exposure.py.
Dumps the remote .git over HTTP with git-dumper, then runs gitleaks on the
dump. Skips entirely when no source is reachable — never invents a target."""

import asyncio
import json
import os
import shutil
import sys
import tempfile

from agents._common import run_capture

MAX_BASES = 5
MAX_FINDINGS_PER_BASE = 10
MAX_TOTAL = 25
DUMP_TIMEOUT = 240


class SecretsScanAgent:
    name = "scan_secrets"

    async def run(self, context):
        git_bases = (context.results.get("discovery_exposure", {}) or {}).get("git_urls", [])
        if not git_bases:
            await context.emit_agent(AGENT_NAME, "no exposed .git found — skipping")
            context.results[self.name] = {"skipped": "no git source"}
            return
        if not _tool_available():
            await context.emit_agent(
                self.name,
                "gitleaks or git-dumper missing — install `brew install gitleaks` "
                "and `pip install git-dumper`. Skipping.",
            )
            context.results[self.name] = {"skipped": "tools missing"}
            return

        await context.emit_agent(
            self.name, f"scanning {len(git_bases)} exposed git source(s) for secrets"
        )
        all_findings = []
        for base in git_bases[:MAX_BASES]:
            f = await _scan_base(context, base)
            all_findings.extend(f)
            for item in f:
                await context.emit_agent(AGENT_NAME, f"{item.severity}: {item.title} @ {item.location}")
            if len(all_findings) >= MAX_TOTAL:
                break

        context.findings.extend(all_findings)
        context.results[self.name] = {"bases": len(git_bases), "findings": len(all_findings)}
        await context.emit_agent(AGENT_NAME, f"secrets scan done: {len(all_findings)} finding(s)")


async def _scan_base(context, base) -> list:
    dumpdir = tempfile.mkdtemp(prefix="gitdump-")
    try:
        await _git_dump(context, base, dumpdir)
        repo = os.path.join(dumpdir, ".git")
        if not os.path.isdir(repo):
            await context.emit_agent(AGENT_NAME, f"git dump for {base} incomplete — skipping")
            return []
        return await _gitleaks(context, base, dumpdir)
    finally:
        shutil.rmtree(dumpdir, ignore_errors=True)


async def _git_dump(context, base, dumpdir):
    tool = _git_dumper_path()
    if not tool:
        return
    await context.emit_agent(AGENT_NAME, f"dumping .git from {base}")
    target = base.rstrip("/") + "/.git/"
    await run_capture([tool, target, dumpdir], timeout=DUMP_TIMEOUT)


def _git_dumper_path() -> str | None:
    candidates = [
        os.path.join(sys.prefix, "bin", "git-dumper"),
        "/usr/local/bin/git-dumper",
        "/opt/homebrew/bin/git-dumper",
    ]
    for c in candidates:
        if os.path.exists(c):
            return c
    return None


async def _gitleaks(context, base, dumpdir) -> list:
    report = os.path.join(dumpdir, "gitleaks.json")
    cmd = ["gitleaks", "dir", dumpdir, "--no-banner",
           "--report-format", "json", "--report-path", report]
    found, _, _, _ = await run_capture(cmd, timeout=180)
    if not found:
        await context.emit_agent(AGENT_NAME, "gitleaks not found")
        return []

    try:
        with open(report, "r", encoding="utf-8") as fh:
            alerts = json.load(fh)
    except (OSError, json.JSONDecodeError):
        return []
    if not isinstance(alerts, list):
        return []

    findings = []
    for a in alerts[:MAX_FINDINGS_PER_BASE]:
        rule = a.get("RuleID") or ""
        desc = a.get("Description") or rule or "secret"
        secret = (a.get("Secret") or "")[:60]
        file = a.get("File") or ""
        if file.startswith(dumpdir):
            file = file[len(dumpdir):].lstrip("/")
        findings.append(_finding(
            f"Committed secret: {desc}",
            base.rstrip("/"),
            f"file {file}:{a.get('StartLine')} commit {str(a.get('Commit'))[:8]}",
            secret,
        ))
    await context.emit_agent(AGENT_NAME, f"gitleaks found {len(alerts)} alert(s) on {base}")
    return findings


def _tool_available() -> bool:
    return bool(_git_dumper_path())


def _finding(title, location, evidence, secret):
    from models import Finding
    return Finding(
        source_tool="scan_secrets",
        title=title,
        severity="high",
        category="Secrets",
        description="A credential or API key appears to be committed to an "
                    "exposed git repository. Rotate the secret and remove it "
                    "from history.",
        location=location,
        raw_evidence=evidence,
        hint="Rotate the leaked credential immediately, scrub it from git "
             "history (e.g. filter-repo), and enable secret scanning to stop "
             "future commits.",
        cwe="CWE-798",
    )