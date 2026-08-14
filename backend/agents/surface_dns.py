"""DNS record analysis: SPF/DMARC presence, dangling CNAMEs, resolving hosts."""

import asyncio
import tempfile

from agents._common import run_capture, strip_ansi
from models import Finding


class DnsAgent:
    name = "surface_dns"

    async def run(self, context):
        sub_res = context.results.get("surface_subdomains", {}) or {}
        domain = sub_res.get("domain")
        if not domain:
            await context.emit_agent(self.name, "no domain from subdomains stage, skipping")
            return

        subdomains = sub_res.get("subdomains", []) or []
        if context.scan_mode == "light":
            subdomains = subdomains[:20]
        targets = [domain] + [s for s in subdomains if not s.endswith("." + domain) or s != domain]

        records = {}

        found, out, _, _ = await run_capture(
            ["dnsx", "-a", "-mx", "-ns", "-resp", "-nc", "-silent"],
            timeout=90,
            input_data=("\n".join(targets[:200]) + "\n").encode(),
        )
        if not found:
            await context.emit_agent(self.name, "dnsx not found — install with `brew install dnsx`")
            return
        for line in strip_ansi((out or b"").decode(errors="replace")).splitlines():
            records.setdefault(_rec_host(line), []).append(_rec_val(line))

        resolving = [
            h for h, rs in records.items()
            if any(r.startswith("[A]") or r.startswith("[AAAA]") for r in rs)
        ]

        findings = []

        spf_ok = await _has_txt(domain, "v=spf1")
        if spf_ok is False:
            findings.append(_finding("Missing SPF record", "info",
                "No SPF (v=spf1) TXT record found; mail from this domain can be spoofed.", domain,
                "TXT _spf: <absent>", "CWE-345"))
        elif spf_ok is True:
            await context.emit_agent(self.name, f"SPF present for {domain}")

        dmarc_ok = await _has_txt(f"_dmarc.{domain}", "v=dmarc1")
        if dmarc_ok is False:
            findings.append(_finding("Missing DMARC record", "info",
                "No DMARC (v=dmarc1) TXT record found on _dmarc.<domain>; spoofed mail has no "
                "enforcement policy.", f"_dmarc.{domain}",
                "TXT _dmarc: <absent>", "CWE-345"))
        elif dmarc_ok is True:
            await context.emit_agent(self.name, f"DMARC present for {domain}")

        dangling = await _dangling_cnames(subdomains)
        for host, cname in dangling:
            findings.append(_finding("Dangling CNAME (potential takeover)", "low",
                f"CNAME for {host} points to {cname} which does not resolve — a classic "
                "subdomain takeover vector if the target is unclaimed.", host,
                f"CNAME {cname} (unresolvable)", "CWE-345"))

        context.findings.extend(findings)
        context.results[self.name] = {
            "records": records,
            "resolving": sorted(resolving),
            "spf": spf_ok,
            "dmarc": dmarc_ok,
        }
        await context.emit_agent(
            self.name,
            f"{len(resolving)} resolving host(s), {len(findings)} finding(s), "
            f"{len(dangling)} dangling CNAME(s)",
        )


async def _has_txt(host: str, marker: str) -> bool | None:
    found, out, _, _ = await run_capture(
        ["dnsx", "-txt", "-resp", "-nc", "-silent"],
        timeout=30,
        input_data=(host + "\n").encode(),
    )
    if not found or out is None:
        return None
    text = strip_ansi(out.decode(errors="replace"))
    return marker.lower() in text.lower()


async def _dangling_cnames(subdomains) -> list[tuple[str, str]]:
    if not subdomains:
        return []
    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as tf:
        for s in subdomains:
            tf.write(s + "\n")
        listfile = tf.name
    try:
        found, out, _, _ = await run_capture(
            ["dnsx", "-l", listfile, "-cname", "-resp", "-nc", "-silent"], timeout=90
        )
    finally:
        import os

        os.unlink(listfile)
    if not found or not out:
        return []

    dangling = []
    sem = asyncio.Semaphore(10)

    async def _check(host, cname_target):
        async with sem:
            return (host, cname_target) if not await _resolves(cname_target) else None

    tasks = []
    for line in strip_ansi(out.decode(errors="replace")).splitlines():
        parts = [p for p in line.split("[") if p]
        if len(parts) < 2:
            continue
        host = parts[0].strip()
        val = parts[-1].split("]")[0].strip()
        if not val:
            continue
        cname_target = _first_hostname(val)
        if cname_target:
            tasks.append(_check(host, cname_target))
    for done in asyncio.as_completed(tasks):
        r = await done
        if r:
            dangling.append(r)
    return dangling


async def _resolves(host: str) -> bool:
    found, out, _, _ = await run_capture(
        ["dnsx", "-a", "-silent", "-nc"],
        timeout=20,
        input_data=(host + "\n").encode(),
    )
    return bool(found and out and out.strip())


def _first_hostname(text: str) -> str:
    for tok in text.replace(",", " ").split():
        tok = tok.strip(".")
        if "." in tok:
            return tok
    return ""


def _rec_host(line: str) -> str:
    parts = line.split("[")
    return parts[0].strip() if parts else ""


def _rec_val(line: str) -> str:
    parts = line.split("[")
    if len(parts) >= 3:
        return "[" + parts[1].split("]")[0] + "] " + parts[2].split("]")[0]
    return ""


def _finding(title, sev, desc, location, evidence, cwe):
    return Finding(
        source_tool="surface_dns",
        title=title,
        severity=sev,
        category="DNS Configuration",
        description=desc,
        location=location,
        raw_evidence=evidence,
        cwe=cwe,
    )