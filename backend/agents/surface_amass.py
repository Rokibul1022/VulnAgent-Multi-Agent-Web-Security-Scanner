"""Active subdomain enumeration (amass, full mode only).

Full-mode scan runs amass active enumeration to augment the passive subfinder
results. Results are merged into the surface_subdomains list so downstream
stages (dns resolution, recon fan-out) pick up the additional hosts.
"""

from urllib.parse import urlparse

from agents._common import run_capture, strip_ansi

AMASS_TIMEOUT = 150


class AmassAgent:
    name = "surface_amass"

    async def run(self, context):
        if context.scan_mode != "full":
            await context.emit_agent(self.name, "amass active enum is full-mode only, skipping")
            return

        host = (urlparse(context.url).hostname or "").lower()
        if not host:
            return
        labels = host.split(".")
        domain = ".".join(labels[-2:]) if len(labels) > 2 else host

        await context.emit_agent(self.name, f"amass active enumeration of {domain}")
        found, out, _, _ = await run_capture(
            ["amass", "enum", "-silent", "-d", domain, "-timeout", "2"],
            timeout=AMASS_TIMEOUT,
        )
        if not found:
            await context.emit_agent(
                self.name, "amass not found — install with `brew install amass`"
            )
            return
        if out is None:
            await context.emit_agent(self.name, "amass hit its timeout, keeping partial results")

        discovered = sorted({
            l.strip().lower()
            for l in strip_ansi((out or b"").decode(errors="replace")).splitlines()
            if l.strip() and not l.strip().startswith("--")
        })

        sub_res = context.results.setdefault("surface_subdomains", {}) or {}
        existing = set(sub_res.get("subdomains", []) or [])
        added = [s for s in discovered if s not in existing]
        sub_res["subdomains"] = sorted(existing | set(discovered))
        context.results["surface_subdomains"] = sub_res

        await context.emit_agent(
            self.name, f"amass enum done: {len(discovered)} host(s), {len(added)} new"
        )
