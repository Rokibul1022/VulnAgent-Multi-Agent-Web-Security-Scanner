"""Header-check agent: pure Python audit of security response headers."""

import httpx

from models import Finding

USER_AGENT = "VulnAgent/0.1 (authorized security testing)"

SECURITY_HEADERS = [
    (
        "Content-Security-Policy",
        "low",
        "Response lacks a Content-Security-Policy header, so any injected script "
        "can execute with full page privileges.",
        "Add a Content-Security-Policy header that restricts script-src to trusted sources.",
    ),
    (
        "Strict-Transport-Security",
        "low",
        "Response lacks Strict-Transport-Security, leaving the connection open to "
        "SSL-stripping downgrade attacks over HTTP.",
        "Add an HSTS header (Strict-Transport-Security) with a reasonable max-age once the "
        "site is HTTPS-only.",
    ),
    (
        "X-Frame-Options",
        "low",
        "Response lacks X-Frame-Options, so the page can be framed by other sites "
        "and used in clickjacking.",
        "Set X-Frame-Options to DENY or SAMEORIGIN (or use CSP frame-ancestors).",
    ),
    (
        "X-Content-Type-Options",
        "low",
        "Response lacks X-Content-Type-Options: nosniff, so browsers may sniff "
        "mislabeled responses and mis-execute them.",
        "Send X-Content-Type-Options: nosniff on all responses.",
    ),
    (
        "Referrer-Policy",
        "info",
        "Response lacks a Referrer-Policy, potentially leaking URL query strings "
        "to third parties via the Referer header.",
        "Set Referrer-Policy to a restrictive value such as strict-origin-when-cross-origin.",
    ),
    (
        "Permissions-Policy",
        "info",
        "Response lacks a Permissions-Policy header, leaving browser feature "
        "access (camera, geolocation, etc.) unconstrained.",
        "Add a Permissions-Policy header that denies unnecessary browser features.",
    ),
]


class HeadersScanAgent:
    name = "scan_headers"

    async def run(self, context):
        pages = []
        recon = context.results.get("recon", {})
        if recon.get("pages"):
            pages = recon["pages"]
        else:
            url = context.url
            try:
                async with httpx.AsyncClient(
                    follow_redirects=True, timeout=10.0,
                    headers={"User-Agent": USER_AGENT},
                ) as client:
                    resp = await client.get(url)
                    pages = [{
                        "url": str(resp.url),
                        "status": resp.status_code,
                        "headers": dict(resp.headers),
                    }]
            except (httpx.HTTPError, httpx.TimeoutException):
                return

        findings = []
        checked = 0
        for page in pages:
            if page.get("status", 0) >= 400:
                continue
            headers = page.get("headers", {})
            checked += 1
            low = {k.lower() for k in headers}
            for name, sev, desc, hint in SECURITY_HEADERS:
                if name.lower() in low:
                    continue
                findings.append(
                    Finding(
                        source_tool=self.name,
                        title=f"Missing {name} header",
                        severity=sev,
                        category="Headers",
                        description=desc,
                        location=page["url"],
                        raw_evidence=f"GET {page['url']}\n{name}: <absent>",
                        hint=hint,
                    )
                )
            for name in ("server", "x-powered-by"):
                val = headers.get(name)
                if val:
                    findings.append(
                        Finding(
                            source_tool=self.name,
                            title=f"{name} header discloses version",
                            severity="info",
                            category="Headers",
                            description=f"The {name} header exposes '{val}', which an attacker "
                            "can use to look up known vulnerabilities for that component.",
                            location=page["url"],
                            raw_evidence=f"{name}: {val}",
                            hint="Suppress or strip version details from the {name} header.".format(name=name),
                        )
                    )

        context.findings.extend(findings)
        await context.emit_agent(self.name, f"checked headers on {checked} page(s), {len(findings)} finding(s)")