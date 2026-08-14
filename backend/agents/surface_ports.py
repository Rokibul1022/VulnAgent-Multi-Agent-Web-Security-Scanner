"""Port scanning (nmap). Light mode: top-100 ports. Full mode: -p-."""

from agents._common import run_capture, strip_ansi
from models import Finding

PORT_NOTES = {
    80: None, 443: None, 8080: None, 8443: None,
    22: ("info", "SSH"),
    21: ("low", "FTP"),
    23: ("high", "Telnet"),
    445: ("high", "SMB"),
    3389: ("medium", "RDP"),
    5900: ("medium", "VNC"),
    5901: ("medium", "VNC"),
    3306: ("high", "MySQL"),
    5432: ("high", "PostgreSQL"),
    27017: ("high", "MongoDB"),
    6379: ("high", "Redis"),
    11211: ("high", "Memcached"),
    9200: ("high", "Elasticsearch"),
    2375: ("high", "Docker (unencrypted)"),
    2376: ("high", "Docker TLS"),
    21: ("low", "FTP"),
    25: ("info", "SMTP"),
    53: ("info", "DNS"),
    8081: ("info", "Alt HTTP"),
    8888: ("info", "Alt HTTP"),
    9000: ("info", "Dev console"),
    3000: ("info", "Dev server"),
    4000: ("info", "Dev server"),
    5000: ("info", "Dev server"),
    7000: ("info", "Dev server"),
}

NMAP_TIMEOUT = 110


class PortsAgent:
    name = "surface_ports"

    async def run(self, context):
        host = _host_of(context.url)
        if not host:
            await context.emit_agent(self.name, "no host parsed, skipping")
            return

        await context.emit_agent(self.name, f"nmap scanning {host} (light: top-100 ports)")
        cmd = [
            "nmap", "-Pn", "-T4", "-sV",
            "--top-ports", "100",
            "--min-rate", "500", "--max-retries", "2",
                "--host-timeout", "40s",
            host,
        ]
        if context.scan_mode == "full":
            cmd = [
                "nmap", "-Pn", "-T4", "-sV",
                "-p-",
                "--min-rate", "300", "--max-retries", "2",
                "--host-timeout", "300s",
                host,
            ]

        found, out, _, _ = await run_capture(cmd, timeout=NMAP_TIMEOUT)
        if not found:
            await context.emit_agent(self.name, "nmap not found — install with `brew install nmap`")
            return
        if out is None:
            await context.emit_agent(self.name, "nmap hit its host-timeout, keeping partial results")

        ports = _parse_ports((out or b"").decode(errors="replace"))
        findings = []
        for port, state, service in ports:
            if port in (80, 443):
                continue  # normal web ports
            note = PORT_NOTES.get(port)
            if note is None:
                findings.append(_finding(
                    f"Unexpected open port {port}", "info",
                    f"Port {port}/tcp is open ({service or 'unknown service'}) and exposed "
                    "to the internet; confirm it is intentionally exposed and hardened.",
                    f"{host}:{port}", f"{port}/tcp open {service or 'unknown'}", None,
                ))
                continue
            sev, label = note
            if sev in ("info", "low", "medium", "high"):
                findings.append(_finding(
                    f"Exposed {label} ({port})", sev,
                    f"Port {port}/tcp ({label or service}) is open to the internet. "
                    f"{_impact(sev, label)}",
                    f"{host}:{port}", f"{port}/tcp open {service or label}", None,
                ))

        context.findings.extend(findings)
        context.results[self.name] = {"open_ports": [p[0] for p in ports]}
        await context.emit_agent(
            self.name, f"nmap done: {len(ports)} open port(s), {len(findings)} finding(s)"
        )


def _parse_ports(text: str) -> list[tuple[int, str, str]]:
    ports = []
    in_table = False
    for line in text.splitlines():
        s = line.strip()
        if s.startswith("PORT"):
            in_table = True
            continue
        if not in_table:
            continue
        if not s or s.startswith("Nmap") or s.startswith("Not shown") or s.startswith("Host is"):
            break
        parts = s.split()
        if len(parts) >= 3 and "/" in parts[0]:
            port = parts[0].split("/")[0]
            state = parts[1]
            service = parts[2]
            if port.isdigit() and state == "open":
                ports.append((int(port), state, service))
    return ports


def _impact(sev: str, label: str) -> str:
    if sev == "high":
        return "Databases/admin services should never be internet-facing; restrict to trusted networks."
    if sev == "medium":
        return "Exposing this service increases the attack surface; restrict access or patch it."
    if sev == "low":
        return "Consider restricting this service to trusted sources."
    return "Verify this is intentionally exposed."


def _finding(title, sev, desc, location, evidence, cwe):
    return Finding(
        source_tool="surface_ports",
        title=title,
        severity=sev,
        category="Network",
        description=desc,
        location=location,
        raw_evidence=evidence,
        cwe=cwe,
    )


def _host_of(url: str) -> str:
    from urllib.parse import urlparse

    url = (url or "").strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return (urlparse(url).hostname or "").lower()