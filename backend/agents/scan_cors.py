"""CORS misconfiguration checks (pure HTTP).

Sends requests with crafted Origin headers and flags servers that reflect
arbitrary origins (or `null`) in Access-Control-Allow-Origin, especially in
combination with Access-Control-Allow-Credentials: true."""

import asyncio

import httpx

USER_AGENT = "VulnAgent/0.1 (authorized security testing)"
TEST_ORIGINS = ["https://evil.example", "null"]
MAX_URLS = 10


class CorsScanAgent:
    name = "scan_cors"

    async def run(self, context):
        urls = _candidates(context)
        if not urls:
            await context.emit_agent(self.name, "no URLs to test")
            return

        await context.emit_agent(self.name, f"testing CORS on {len(urls)} URL(s)")
        sem = asyncio.Semaphore(6)

        async with httpx.AsyncClient(
            follow_redirects=False, timeout=10.0,
            headers={"User-Agent": USER_AGENT},
        ) as client:
            findings = []
            tasks = []
            for url in urls:
                for origin in TEST_ORIGINS:
                    tasks.append(_probe(client, sem, url, origin))
            for done in asyncio.as_completed(tasks):
                f = await done
                if f:
                    findings.append(f)
                    await context.emit_agent(self.name, f"{f.severity}: {f.title} @ {f.location}")

        context.findings.extend(findings)
        context.results[self.name] = {"checked": len(tasks), "found": len(findings)}
        await context.emit_agent(self.name, f"CORS checks done: {len(findings)} finding(s)")


async def _probe(client, sem, url, origin):
    async with sem:
        try:
            resp = await client.get(url, headers={"Origin": origin})
        except httpx.HTTPError:
            return None
    acao = resp.headers.get("access-control-allow-origin")
    if not acao:
        return None
    acac = (resp.headers.get("access-control-allow-credentials") or "").lower() == "true"

    if acao.strip() == origin and acac:
        return _finding(
            "high",
            f"CORS reflects arbitrary origin with credentials ({origin})",
            url,
            f"Sent Origin: {origin} -> ACAO: {acao}, ACAC: true",
            "Any website can make credentialed cross-origin requests and read the "
            "responses, leaking authenticated data.",
        )
    if acao.strip() in ("*", "null") and acac and acao.strip() != origin:
        return _finding(
            "medium",
            f"CORS allows '{acao}' with credentials",
            url,
            f"Sent Origin: {origin} -> ACAO: {acao}, ACAC: true",
            "Wildcard or null origins combined with credentials is a misconfiguration "
            "that can enable cross-origin data access.",
        )
    if acao.strip() == origin and not acac:
        return _finding(
            "medium",
            f"CORS reflects arbitrary origin ({origin})",
            url,
            f"Sent Origin: {origin} -> ACAO: {acao}",
            "The server trusts any Origin header without credentials; sensitive "
            "unauthenticated data could be read cross-origin.",
        )
    return None


def _candidates(context) -> list[str]:
    out = []
    for t in (context.targets or [context.url]):
        if t not in out:
            out.append(t)
    for page in (context.results.get("recon", {}) or {}).get("pages", []):
        u = page.get("url")
        if u and u not in out:
            out.append(u)
        if len(out) >= MAX_URLS:
            break
    return out[:MAX_URLS]


def _finding(severity, title, location, evidence, description):
    from models import Finding
    return Finding(
        source_tool="scan_cors",
        title=title,
        severity=severity,
        category="CORS",
        description=description,
        location=location,
        raw_evidence=evidence,
        hint="Restrict Access-Control-Allow-Origin to an explicit allowlist of "
             "trusted origins and never reflect arbitrary or null origins; keep "
             "Access-Control-Allow-Credentials consistent with that allowlist.",
    )