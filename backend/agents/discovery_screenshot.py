"""Visual screenshot capture (Chrome headless, agent.md §5 visual triage).

gowitness is not installable via Homebrew anymore, so we drive headless Chrome
directly. Light mode screenshots the root URL only; full mode captures more
targets. Files land under backend/storage/screenshots/<job_id>/ and are served
by the backend so the report UI can show them.
"""

import os

import config
from agents._common import run_capture

CHROME_PATHS = [
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    "/Applications/Chromium.app/Contents/MacOS/Chromium",
    "/usr/bin/chromium",
    "/usr/bin/chromium-browser",
    "/usr/bin/google-chrome",
]


class ScreenshotAgent:
    name = "discovery_screenshot"

    async def run(self, context):
        chrome = next((p for p in CHROME_PATHS if os.path.exists(p)), None)
        if not chrome:
            await context.emit_agent(
                self.name, "no headless Chrome found — install Chrome or Chromium to enable screenshots"
            )
            return

        targets = (context.targets or [context.url])[:4]
        if context.scan_mode == "light":
            targets = targets[:1]

        outdir = os.path.join(config.SCREENSHOTS_DIR, context.job.job_id)
        os.makedirs(outdir, exist_ok=True)

        captured = []
        for i, url in enumerate(targets):
            name = f"shot_{i}.png"
            path = os.path.join(outdir, name)
            await context.emit_agent(self.name, f"capturing {url}")
            found, _, _, _ = await run_capture(
                [
                    chrome, "--headless=new", "--no-sandbox", "--disable-gpu",
                    "--disable-dev-shm-usage", "--hide-scrollbars",
                    "--window-size=1280,800", "--virtual-time-budget=3000",
                    f"--screenshot={path}", url,
                ],
                timeout=25,
            )
            if found and os.path.exists(path) and os.path.getsize(path) > 0:
                captured.append({"url": url, "file": name})

        context.results[self.name] = {"screenshots": captured}
        await context.emit_agent(
            self.name, f"captured {len(captured)} screenshot(s)"
        )
