"""LLM-powered triage agent (agent.md §4.5).

Dedupes, re-ranks, and writes plain-English hints. Batches per category to keep
prompts small. If the LLM call fails (all keys exhausted / API error), falls
back to the deterministic dedupe so a scan never hangs.
"""

import asyncio
import json

from models import Finding
from llm.llm_client import triage_findings
from llm.prompts import build_recon_context

VALID_SEVERITIES = {"info", "low", "medium", "high", "critical"}


class TriageAgent:
    name = "triage"

    async def run(self, context):
        raw = context.findings
        if not raw:
            await context.emit_agent(self.name, "no findings to triage")
            return

        recon_ctx = build_recon_context(context)

        by_category: dict[str, list[Finding]] = {}
        for f in raw:
            by_category.setdefault(f.category, []).append(f)

        triaged: list[Finding] = []
        tasks = []
        for category, items in by_category.items():
            payload = json.dumps(
                {
                    "category": category,
                    "findings": [
                        {
                            "source_tool": f.source_tool,
                            "title": f.title,
                            "severity": f.severity,
                            "location": f.location,
                            "cwe": f.cwe,
                            "description": f.description,
                            "raw_evidence": f.raw_evidence[:500],
                        }
                        for f in items
                    ],
                }
            )
            tasks.append((category, items, _call_triage(payload, recon_ctx, category)))

        results = await asyncio.gather(
            *(t[2] for t in tasks), return_exceptions=True
        )
        for (category, items, _), result in zip(tasks, results):
            if isinstance(result, Exception):
                await context.emit_agent(
                    self.name,
                    f"LLM triage failed for {category} ({result}) — keeping raw findings",
                )
                triaged.extend(items)
                continue
            parsed = result.get("findings") or []
            for item in parsed:
                f = _normalize(item, items)
                if f:
                    triaged.append(f)
            await context.emit_agent(
                self.name,
                f"triaged {category}: {len(parsed)} finding(s)",
            )

        if not triaged:
            triaged = raw

        context.findings = triaged
        await context.emit_agent(
            self.name, f"triage complete: {len(triaged)} finding(s) in report"
        )


async def _call_triage(payload: str, recon_ctx: str, query: str) -> dict:
    # run the (blocking) LLM call in a thread so the event loop stays responsive
    import asyncio

    memory_ctx = await asyncio.to_thread(_memory_context, query)
    return await asyncio.to_thread(triage_findings, payload, recon_ctx, memory_ctx)


def _memory_context(query: str, n: int = 3) -> str:
    """Retrieve relevant past feedback verdicts + policy docs from Chroma.

    Local embeddings only; any failure returns an empty context so triage never
    depends on the memory layer being healthy."""
    try:
        from memory import feedback_store
    except Exception:  # noqa: BLE001
        return ""
    try:
        rows = feedback_store.search(query, n=n)
    except Exception:  # noqa: BLE001
        return ""
    if not rows:
        return ""
    lines = []
    for r in rows:
        kind = r.get("kind", "memory")
        verdict = r.get("verdict") or ""
        label = f"{kind}:{verdict}" if verdict else kind
        lines.append(f"  [{label}] {r.get('text', '')[:400]}")
    return "LEARNED CONTEXT (past verdicts / policy snippets):\n" + "\n".join(lines)


def _normalize(item: dict, raw_items: list[Finding]) -> Finding | None:
    """Map an LLM-returned finding back to its raw source so category, location,
    evidence, and CWE stay grounded in real tool output (the LLM may rename
    categories or truncate fields)."""
    try:
        severity = str(item.get("severity", "info")).lower()
        if severity not in VALID_SEVERITIES:
            severity = "info"
        raw = _match_raw(item, raw_items)
        return Finding(
            source_tool=str(item.get("source_tool") or "unknown"),
            title=str(item.get("title") or "").strip(),
            severity=severity,
            category=(raw.category if raw else str(item.get("category") or "Other")),
            description=str(item.get("description") or "").strip(),
            location=(raw.location if raw else str(item.get("location") or "")),
            raw_evidence=(raw.raw_evidence if raw else str(item.get("raw_evidence") or "")).strip(),
            hint=str(item.get("hint") or "").strip(),
            cwe=_norm_cwe((raw.cwe if raw else item.get("cwe")) or None),
        )
    except Exception:  # noqa: BLE001
        return None


def _match_raw(item: dict, raw_items: list[Finding]) -> Finding | None:
    title = (item.get("title") or "").strip().lower()
    for r in raw_items:
        rt = r.title.strip().lower()
        if rt == title or rt in title or title in rt:
            return r
    return None


def _norm_cwe(cwe) -> str | None:
    if not cwe:
        return None
    cwe = str(cwe).strip()
    if cwe.lower().startswith("cwe-"):
        return "CWE-" + cwe[4:].strip().upper()
    digits = "".join(ch for ch in cwe if ch.isdigit())
    return f"CWE-{digits}" if digits else None