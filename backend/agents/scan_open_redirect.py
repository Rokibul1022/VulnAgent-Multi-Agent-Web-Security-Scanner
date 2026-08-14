"""Open-redirect checks (pure HTTP).

Tests common redirect parameters found on discovered URLs with a benign
external test domain. Flags unchecked off-domain redirects via Location
headers (3xx) or reflected links in the response body."""

import asyncio
from urllib.parse import quote, urlsplit

import httpx

USER_AGENT = "VulnAgent/0.1 (authorized security testing)"
TEST_VALUE = "https://example.com/redirect-probe"
REDIRECT_PARAMS = [
    "next", "url", "redirect", "redirect_url", "redirect_uri", "return",
    "returnUrl", "return_url", "continue", "continue_url", "dest",
    "destination", "target", "goto", "out", "view", "forward", "callback",
    "back", "returnto",
]
MAX_URLS = 10


class OpenRedirectScanAgent:
    name = "scan_open_redirect"

    async def run(self, context):
        urls = _candidates(context)
        if not urls:
            await context.emit_agent(self.name, "no URLs to test")
            return

        await context.emit_agent(self.name, f"testing open redirects on {len(urls)} URL(s)")
        sem = asyncio.Semaphore(6)

        async with httpx.AsyncClient(
            follow_redirects=False, timeout=10.0,
            headers={"User-Agent": USER_AGENT},
        ) as client:
            findings = []
            tasks = []
            for url in urls:
                for param in REDIRECT_PARAMS:
                    tasks.append(_probe(client, sem, url, param))
            for done in asyncio.as_completed(tasks):
                f = await done
                if f:
                    findings.append(f)
                    await context.emit_agent(self.name, f"{f.severity}: {f.title} @ {f.location}")

        context.findings.extend(findings)
        context.results[self.name] = {"checked": len(tasks), "found": len(findings)}
        await context.emit_agent(self.name, f"open-redirect checks done: {len(findings)} finding(s)")


async def _probe(client, sem, url, param):
    sep = "&" if "?" in url else "?"
    test_url = f"{url}{sep}{param}={quote(TEST_VALUE)}"
    async with sem:
        try:
            resp = await client.get(test_url)
        except httpx.HTTPError:
            return None

    if resp.status_code in (301, 302, 303, 307, 308):
        loc = resp.headers.get("location", "")
        if loc and _external(loc, url):
            return _finding(
                "medium",
                f"Open redirect via ?{param}=",
                test_url,
                f"{resp.status_code} Location: {loc}",
                "The server redirects an attacker-controlled parameter to an "
                "external domain unchecked; usable for phishing and OAuth "
                "token theft.",
            )

    if resp.status_code == 200 and TEST_VALUE in resp.text:
        return _finding(
            "medium",
            f"Reflected redirect target in ?{param}=",
            test_url,
            f"Response body contains {TEST_VALUE}",
            "An attacker-controlled parameter value is reflected into the page; "
            "if any client-side logic navigates to it, this is an open redirect.",
        )
    return None


def _external(loc: str, base: str) -> bool:
    if loc.startswith("//"):
        return True
    lh = (urlsplit(loc).hostname or "").lower()
    if not lh:
        return False
    bh = (urlsplit(base).hostname or "").lower()
    return lh != bh


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
        source_tool="scan_open_redirect",
        title=title,
        severity=severity,
        category="Web App / Injection",
        description=description,
        location=location,
        raw_evidence=evidence,
        hint="Validate redirect destinations against an internal allowlist of "
             "hosts and never trust user-supplied URLs verbatim.",
    )