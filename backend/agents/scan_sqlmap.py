"""SQL injection detection (sqlmap, detection-only, full mode).

Runs sqlmap in batch/smart mode against discovered pages with URL query
parameters. Detection only: sqlmap confirms injectability and reports the
vulnerable parameter + technique; no data extraction or exploitation flags
are ever passed.
"""

import asyncio

from agents._common import run_capture
from models import Finding

MAX_TARGETS = 4
PER_TARGET_TIMEOUT = 120
TOTAL_TIMEOUT = 240


class SqlmapScanAgent:
    name = "scan_sqlmap"

    async def run(self, context):
        if context.scan_mode != "full":
            await context.emit_agent(self.name, "sqlmap detection is full-mode only, skipping")
            return

        candidates = _candidates(context)
        if not candidates:
            await context.emit_agent(self.name, "no parameterized URLs to test")
            return

        await context.emit_agent(
            self.name, f"sqlmap detection on {len(candidates)} URL(s) (detection only)"
        )

        findings = []
        start = asyncio.get_event_loop().time()
        for url in candidates:
            if asyncio.get_event_loop().time() - start > TOTAL_TIMEOUT:
                await context.emit_agent(self.name, "hit total time budget, stopping")
                break
            await context.emit_agent(self.name, f"testing {url}")
            found, out, _, _ = await run_capture(
                [
                    "sqlmap", "-u", url,
                    "--batch", "--smart", "--flush-session",
                    "--level", "1", "--risk", "1",
                ],
                timeout=PER_TARGET_TIMEOUT,
            )
            if not found:
                await context.emit_agent(
                    self.name, "sqlmap not found — install with `brew install sqlmap`"
                )
                break
            if out is None:
                await context.emit_agent(self.name, f"sqlmap timed out on {url}, continuing")
                continue
            hits = _parse_hits((out or b"").decode(errors="replace"), url)
            findings.extend(hits)
            for f in hits:
                await context.emit_agent(self.name, f"{f.severity}: {f.title} @ {f.location}")

        context.findings.extend(findings)
        context.results[self.name] = {"tested": len(candidates), "found": len(findings)}
        await context.emit_agent(
            self.name, f"sqlmap detection done: {len(findings)} finding(s)"
        )


def _candidates(context) -> list[str]:
    out = []
    for page in (context.results.get("recon", {}) or {}).get("pages", []):
        u = page.get("url", "")
        if "?" in u and u not in out:
            out.append(u)
        if len(out) >= MAX_TARGETS:
            break
    return out[:MAX_TARGETS]


def _parse_hits(text: str, url: str) -> list[Finding]:
    params = []
    for line in text.splitlines():
        if "is vulnerable" in line and "parameter" in line.lower():
            try:
                param = line.split("'")[1]
            except IndexError:
                param = ""
            if param and param not in params:
                params.append(param)
    return [
        Finding(
            source_tool="scan_sqlmap",
            title="SQL injection (sqlmap detection)",
            severity="high",
            category="Web App / Injection",
            description=f"sqlmap confirmed SQL injection in parameter '{p}' at this URL. "
                        "Automated detection ran in read-only mode; verify and remediate "
                        "the vulnerable query.",
            location=url,
            raw_evidence=f"parameter '{p}' is vulnerable",
            cwe="CWE-89",
            hint="Use parameterized queries / prepared statements, validate and "
                 "whitelist input, and restrict DB account privileges.",
        )
        for p in params
    ]
