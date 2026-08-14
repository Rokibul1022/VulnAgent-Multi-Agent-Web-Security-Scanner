"""Subdomain enumeration (passive sources only, subfinder)."""

import ipaddress

from agents._common import run_capture, strip_ansi

CC_SLDS = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk",
    "com.au", "net.au", "org.au", "edu.au", "gov.au",
    "co.jp", "ne.jp", "or.jp", "co.in", "com.br",
    "com.mx", "co.nz", "net.nz", "org.nz", "com.sg",
    "com.hk", "com.my", "co.kr", "or.kr", "com.cn",
    "net.cn", "org.cn", "gov.cn", "com.ru", "co.za",
    "org.za", "com.tr", "com.pl",
}


class SubdomainsAgent:
    name = "surface_subdomains"

    async def run(self, context):
        host = _host_of(context.url)
        if _is_ip(host):
            await context.emit_agent(self.name, "IP target — skipping subdomain enumeration")
            context.results[self.name] = {"domain": None, "subdomains": []}
            return

        domain = _domain_of(host)
        if not domain:
            await context.emit_agent(self.name, "no domain parsed, skipping")
            context.results[self.name] = {"domain": None, "subdomains": []}
            return

        await context.emit_agent(self.name, f"enumerating subdomains of {domain}")
        found, out, _, _ = await run_capture(
            ["subfinder", "-d", domain, "-silent"], timeout=120
        )
        if not found:
            await context.emit_agent(
                self.name, "subfinder not found — install with `brew install subfinder`"
            )
            context.results[self.name] = {"domain": domain, "subdomains": []}
            return

        subdomains = sorted(
            {
                l.strip().lower()
                for l in strip_ansi((out or b"").decode(errors="replace")).splitlines()
                if l.strip()
            }
        )
        context.results[self.name] = {"domain": domain, "subdomains": subdomains}
        await context.emit_agent(
            self.name, f"found {len(subdomains)} subdomain(s) (passive)"
        )


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host or "")
        return True
    except ValueError:
        return False


def _host_of(url: str) -> str:
    from urllib.parse import urlparse

    url = (url or "").strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return (urlparse(url).hostname or "").lower()


def _domain_of(host: str) -> str:
    labels = host.split(".")
    if len(labels) <= 2:
        return host
    if ".".join(labels[-2:]) in CC_SLDS and len(labels) >= 3:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])