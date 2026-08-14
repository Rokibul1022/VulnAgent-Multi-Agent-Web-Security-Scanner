"""WAF/CDN fingerprinting (wafw00f). Context only — tempers triage expectations."""

from agents._common import run_capture, strip_ansi


class WafAgent:
    name = "surface_waf"

    async def run(self, context):
        await context.emit_agent(self.name, f"probing WAF for {context.url}")
        found, out, _, _ = await run_capture(["wafw00f", context.url], timeout=45)
        if not found:
            await context.emit_agent(
                self.name, "wafw00f not found — install with `pipx install wafw00f`"
            )
            context.results[self.name] = {"waf": None}
            return

        waf = _detect((out or b"").decode(errors="replace"))
        context.results[self.name] = {"waf": waf}
        if waf:
            await context.emit_agent(self.name, f"WAF/CDN detected: {waf}")
        else:
            await context.emit_agent(self.name, "no WAF detected")


def _detect(text: str) -> str | None:
    clean = strip_ansi(text)
    for line in clean.splitlines():
        if "is behind" in line.lower() and "waf" in line.lower():
            start = line.find("behind") + len("behind")
            end = line.find("waf", start)
            name = line[start:end].strip(" .)(-")
            return name.strip() or None
    if "no waf detected" in clean.lower():
        return None
    return None