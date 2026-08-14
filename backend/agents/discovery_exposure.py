"""Exposed-file / sensitive-path checks (pure HTTP, no external tool).

Requests a curated list of sensitive paths on each target host and flags
anything that returns real content (200 with an expected marker).

SPA fallback handling: static hosts with a `/* -> /index.html 200` rewrite
return HTTP 200 with the identical index.html shell for *every* path, which
would otherwise false-positive on the marker checks (e.g. len(body) > 512).
Each base host is first probed with a random non-existent path; if that
returns 200, the shell body is recorded and any sensitive path returning the
same body is treated as not-present."""

import asyncio
import secrets
from urllib.parse import urlsplit

import httpx

USER_AGENT = "VulnAgent/0.1 (authorized security testing)"

# (path, severity, title, marker-check, description)
# marker-check: callable(body) -> bool, or a substring to look for.
CHECKS = [
    ("/.git/config", "high", ".git directory exposed",
     "[core]", "Source-control metadata is publicly readable, leaking "
     "repository structure, remote URLs, and possibly credentials."),
    ("/.git/HEAD", "high", ".git HEAD exposed",
     "ref:", "Source-control metadata is publicly readable (HEAD ref)."),
    ("/.env", "high", ".env file exposed",
     lambda b: b"=" in b and any(k in b.lower() for k in
                                (b"key", b"secret", b"token", b"pass", b"db_")),
     "Environment file exposed; commonly holds API keys, database passwords "
     "and other secrets."),
    ("/.env.bak", "high", ".env backup exposed",
     lambda b: b"=" in b and any(k in b.lower() for k in
                                (b"key", b"secret", b"token", b"pass")),
     "Backup of an environment file exposed."),
    ("/.DS_Store", "low", ".DS_Store exposed",
     b"\x00\x00\x00\x01", "macOS metadata file exposed; can leak file names "
     "and directory structure."),
    ("/backup.zip", "medium", "Backup archive exposed",
     lambda b: b[:2] == b"PK" or len(b) > 512,
     "Archive file reachable over HTTP; may contain source or data backups."),
    ("/backup.tar.gz", "medium", "Backup archive exposed",
     lambda b: b[:2] == b"\x1f\x8b" or len(b) > 512,
     "Archive file reachable over HTTP."),
    ("/site.zip", "medium", "Backup archive exposed",
     lambda b: b[:2] == b"PK" or len(b) > 512,
     "Archive file reachable over HTTP."),
    ("/db.sql", "medium", "SQL dump exposed",
     lambda b: b"CREATE TABLE" in b or b"INSERT INTO" in b,
     "SQL dump reachable over HTTP; leaks schema and data."),
    ("/database.sql", "medium", "SQL dump exposed",
     lambda b: b"CREATE TABLE" in b or b"INSERT INTO" in b,
     "SQL dump reachable over HTTP."),
    ("/wp-config.php.bak", "high", "wp-config.php backup exposed",
     b"<?php", "WordPress configuration backup exposed; contains DB credentials."),
    ("/wp-config.php.save", "high", "wp-config.php backup exposed",
     b"<?php", "WordPress configuration backup exposed."),
    ("/config.php.bak", "high", "config.php backup exposed",
     b"<?php", "PHP configuration backup exposed; may contain credentials."),
    ("/phpinfo.php", "medium", "phpinfo() exposed",
     lambda b: b"phpinfo" in b.lower() or b"PHP Version" in b,
     "phpinfo() output exposed; reveals PHP configuration and build details."),
    ("/info.php", "medium", "phpinfo() exposed",
     lambda b: b"phpinfo" in b.lower() or b"PHP Version" in b,
     "phpinfo() output exposed."),
    ("/test.php", "medium", "phpinfo() exposed",
     lambda b: b"phpinfo" in b.lower() or b"PHP Version" in b,
     "PHP info script exposed."),
    ("/server-status", "medium", "Apache server-status exposed",
     lambda b: b"Apache Server Status" in b or b"Server Version" in b,
     "Apache server-status exposed; reveals active requests, IPs and "
     "server internals."),
    ("/server-info", "medium", "Apache server-info exposed",
     lambda b: b"Server Settings" in b or b"Apache Server Information" in b,
     "Apache server-info exposed."),
    ("/.well-known/security.txt", "info", "security.txt present",
     lambda b: b"contact:" in b.lower() and b"canonical:" in b.lower(),
     "security.txt is published (positive signal)."),
    ("/uploads/", "low", "Directory listing enabled",
     lambda b: b"Index of /" in b, "Directory listing enabled on an uploads "
     "directory; exposes file names and possibly sensitive uploads."),
    ("/images/", "low", "Directory listing enabled",
     lambda b: b"Index of /" in b, "Directory listing enabled."),
    ("/backup/", "low", "Directory listing enabled",
     lambda b: b"Index of /" in b, "Directory listing enabled on a backup directory."),
    ("/admin/", "low", "Directory listing enabled",
     lambda b: b"Index of /" in b, "Directory listing enabled on an admin directory."),
]


class ExposureAgent:
    name = "discovery_exposure"

    async def run(self, context):
        bases = _bases(context)
        if not bases:
            await context.emit_agent(self.name, "no targets to probe")
            return

        await context.emit_agent(
            self.name, f"probing {len(bases)} host(s) for exposed files"
        )

        findings = []
        git_bases = []
        sem = asyncio.Semaphore(6 if context.scan_mode == "full" else 6)
        shell_bodies: dict[str, bytes | None] = {}

        async with httpx.AsyncClient(
            follow_redirects=False, timeout=6.0,
            headers={"User-Agent": USER_AGENT},
        ) as client:
            async def shell_body(base):
                rand = f"/vulnagent-probe-{secrets.token_hex(6)}.html"
                try:
                    resp = await client.get(base.rstrip("/") + rand)
                except httpx.HTTPError:
                    return None
                return resp.content if resp.status_code == 200 else None

            for base in bases:
                shell_bodies[base] = await shell_body(base)
                if shell_bodies[base] is not None:
                    await context.emit_agent(
                        self.name,
                        f"SPA/soft-404 fallback detected on {base}; filtering shell responses",
                    )

            async def probe(base, path, sev, title, marker, desc):
                url = base.rstrip("/") + path
                async with sem:
                    try:
                        resp = await client.get(url)
                    except httpx.HTTPError:
                        return None
                if resp.status_code != 200:
                    return None
                body = resp.content
                if shell_bodies.get(base) is not None and body == shell_bodies[base]:
                    return None
                if _marker(marker, body):
                    return _finding(title, sev, url, desc, path)
                return None

            tasks = [probe(b, p, sev, title, marker, desc)
                     for b in bases
                     for p, sev, title, marker, desc in CHECKS]
            for done in asyncio.as_completed(tasks):
                f = await done
                if f:
                    findings.append(f)
                    if f.raw_evidence.startswith("/.git"):
                        git_bases.append(_origin(f.location))
                    await context.emit_agent(self.name, f"{f.severity}: {f.title} @ {f.location}")
                await asyncio.sleep(0.02 if context.scan_mode == "light" else 0)

        context.findings.extend(findings)
        context.results[self.name] = {
            "checked": len(bases) * len(CHECKS), "found": len(findings),
            "git_urls": sorted(set(git_bases)),
        }
        await context.emit_agent(self.name, f"exposure checks done: {len(findings)} hit(s)")


def _origin(url: str) -> str:
    p = urlsplit(url)
    return f"{p.scheme}://{p.netloc}"


def _bases(context) -> list[str]:
    bases = []
    for t in (context.targets or [context.url]):
        if t not in bases:
            bases.append(t)
    return bases


def _marker(marker, body: bytes) -> bool:
    if callable(marker):
        try:
            return bool(marker(body))
        except Exception:
            return False
    if isinstance(marker, str):
        return marker.encode(errors="ignore") in body
    return marker in body  # bytes literal


def _finding(title, severity, location, description, evidence):
    from models import Finding
    return Finding(
        source_tool="discovery_exposure",
        title=title,
        severity=severity,
        category="Content Exposure",
        description=description,
        location=location,
        raw_evidence=evidence,
        hint="Remove the exposed file from the web root, block it at the web "
             "server level, and ensure it is never deployed to public servers.",
    )