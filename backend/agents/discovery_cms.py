AGENT_NAME = "discovery_cms"

"""CMS discovery, conditional on the recon tech fingerprint.

Runs only when a CMS (WordPress/Drupal/Joomla) is detected. Uses wpscan when
available for WordPress, otherwise lightweight pure-HTTP checks."""

import json
import re

import httpx
from bs4 import BeautifulSoup

from agents._common import run_capture

USER_AGENT = "VulnAgent/0.1 (authorized security testing)"


class CmsAgent:
    name = "discovery_cms"

    async def run(self, context):
        tech = (context.results.get("recon", {}) or {}).get("tech_stack", [])
        tech_blob = " ".join(t.lower() for t in tech)
        base = (context.targets or [context.url])[0]

        if "wordpress" in tech_blob:
            await context.emit_agent(AGENT_NAME, "WordPress detected")
            await _wordpress(context, base)
        elif "drupal" in tech_blob:
            await context.emit_agent(AGENT_NAME, "Drupal detected")
            await _drupal(context, base)
        elif "joomla" in tech_blob:
            await context.emit_agent(AGENT_NAME, "Joomla detected")
            await _joomla(context, base)
        else:
            await context.emit_agent(AGENT_NAME, "no known CMS detected, skipping")
            context.results[AGENT_NAME] = {"cms": None}


async def _wordpress(context, base):
    found, _, _, _ = await run_capture(["wpscan", "--version"], timeout=20)
    if found:
        await _wpscan_run(context, base)
    else:
        await context.emit_agent(AGENT_NAME, "wpscan not installed — lightweight checks")
        await _wp_light(context, base)


async def _wpscan_run(context, base):
    await context.emit_agent(AGENT_NAME, "running wpscan (enumerate plugins/themes/users)")
    cmd = [
        "wpscan", "--url", base, "--enumerate", "vp,vt,u",
        "--no-banner", "--format", "json", "--disable-tls-checks",
    ]
    found, out, _, rc = await run_capture(cmd, timeout=240)
    if not found:
        return
    if out is None:
        await context.emit_agent(AGENT_NAME, "wpscan timed out")
        return
    try:
        data = json.loads((out or b"").decode(errors="replace"))
    except json.JSONDecodeError:
        await context.emit_agent(AGENT_NAME, "wpscan output not parseable")
        return

    n = 0
    for k in ("plugins", "themes"):
        for name, info in (data.get(k) or {}).items():
            v = info.get("version") or {}
            ver = v.get("number") or v.get("latest_version")
            if v.get("vulnerabilities"):
                for vuln in v["vulnerabilities"][:3]:
                    title = f"Vulnerable WordPress {k[:-1]}: {name} {ver or ''}".strip()
                    context.findings.append(_finding(
                        "wpscan", title, "high" if _vuln_sev(vuln) == "high" else "medium",
                        f"{base}/wp-content/{k}/{name}/",
                        f"Version {ver or 'unknown'} has disclosed vulnerabilities "
                        f"(refs: {', '.join(vuln.get('references', {}).get('url', [])[:2]) or 'n/a'}).",
                        f"plugin/theme {name} @ {ver}", None,
                    ))
                    n += 1
                if n >= 15:
                    break
        if n >= 15:
            break

    if data.get("version"):
        context.findings.append(_finding(
            "wpscan", "WordPress version disclosed", "low",
            f"{base}/", f"WordPress {data['version']['number']} identified.",
            data["version"]["number"], "CWE-200",
        ))
    await context.emit_agent(AGENT_NAME, f"wpscan done, {n} vulnerable component(s)")


def _vuln_sev(vuln: dict) -> str:
    cvss = vuln.get("cvss", {}) or {}
    score = float(cvss.get("score") or 0)
    if score >= 9.0:
        return "high"
    if score >= 4.0:
        return "medium"
    return "low"


async def _wp_light(context, base):
    findings = []
    async with httpx.AsyncClient(follow_redirects=True, timeout=10.0,
                                 headers={"User-Agent": USER_AGENT}) as client:
        if await _exists(client, f"{base}/wp-login.php"):
            findings.append(_finding(
                "discovery_cms", "WordPress login exposed", "info",
                f"{base}/wp-login.php", "WordPress login page reachable.",
                "wp-login.php 200", None,
            ))
        if await _exists(client, f"{base}/wp-json/"):
            findings.append(_finding(
                "discovery_cms", "WordPress REST API exposed", "info",
                f"{base}/wp-json/", "WordPress REST API responds.",
                "wp-json 200", None,
            ))
        if await _exists(client, f"{base}/readme.html"):
            findings.append(_finding(
                "discovery_cms", "WordPress readme.html exposed", "low",
                f"{base}/readme.html", "readme.html discloses WordPress version info.",
                "readme.html 200", "CWE-200",
            ))
    context.findings.extend(findings)


async def _drupal(context, base):
    findings = []
    async with httpx.AsyncClient(follow_redirects=True, timeout=10.0,
                                 headers={"User-Agent": USER_AGENT}) as client:
        for p, label in (("/core/CHANGELOG.txt", "Drupal CHANGELOG.txt"),
                         ("/CHANGELOG.txt", "Drupal CHANGELOG.txt")):
            txt = await _fetch_text(client, base + p)
            if txt:
                m = re.search(r"Drupal\s+(\d+\.\d+)", txt, re.I)
                ver = f"Drupal {m.group(1)}" if m else "Drupal"
                findings.append(_finding(
                    "discovery_cms", f"{label} exposed", "low",
                    base + p, f"{ver} version information publicly readable.",
                    txt[:120], "CWE-200",
                ))
                break
        if await _exists(client, f"{base}/user/login"):
            findings.append(_finding(
                "discovery_cms", "Drupal login exposed", "info",
                f"{base}/user/login", "Drupal login page reachable.",
                "user/login 200", None,
            ))
    context.findings.extend(findings)


async def _joomla(context, base):
    findings = []
    async with httpx.AsyncClient(follow_redirects=True, timeout=10.0,
                                 headers={"User-Agent": USER_AGENT}) as client:
        if await _exists(client, f"{base}/administrator/"):
            findings.append(_finding(
                "discovery_cms", "Joomla admin exposed", "info",
                f"{base}/administrator/", "Joomla admin panel reachable.",
                "administrator/ 200", None,
            ))
        txt = await _fetch_text(client, f"{base}/language/en-GB/en-GB.xml")
        if txt:
            m = re.search(r"<version>([^<]+)</version>", txt)
            ver = m.group(1) if m else "unknown"
            findings.append(_finding(
                "discovery_cms", "Joomla version disclosed", "low",
                f"{base}/language/en-GB/en-GB.xml", f"Joomla {ver} identified.",
                txt[:120], "CWE-200",
            ))
    context.findings.extend(findings)


async def _exists(client, url) -> bool:
    try:
        r = await client.get(url)
        return r.status_code < 500
    except httpx.HTTPError:
        return False


async def _fetch_text(client, url) -> str | None:
    try:
        r = await client.get(url)
        if r.status_code != 200:
            return None
        return r.text[:2000]
    except httpx.HTTPError:
        return None


def _finding(source, title, severity, location, description, evidence, cwe):
    from models import Finding
    return Finding(
        source_tool=source, title=title, severity=severity, category="Attack Surface",
        description=description, location=location, raw_evidence=evidence or "",
        hint="Upgrade the CMS and its components, and restrict access to "
             "version-metadata endpoints and admin surfaces.",
        cwe=cwe,
    )