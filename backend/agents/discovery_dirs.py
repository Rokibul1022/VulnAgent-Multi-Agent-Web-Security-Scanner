"""Directory/file brute force with ffuf.

Wordlist: SecLists common.txt (moderate). Rate-limited to avoid hammering
the target. Full mode may raise the rate limit and scan more hosts."""

import asyncio
import json
import os
import tempfile

import config

SENSITIVE = ("admin", "login", "config", "backup", "staging", "test", "dev",
             "wp-", "env", "git", "phpmyadmin", "dashboard", "upload", "db",
             "sql", "old", "tmp", "debug", "console", "panel", "api")

FFUF_MC = "200,204,301,302,307,308,401,403"


class DirDiscoveryAgent:
    name = "discovery_dirs"

    async def run(self, context):
        full = context.scan_mode == "full"
        wordlist = config.WORDLIST_COMMON if full else config.WORDLIST_MICRO
        if not os.path.exists(wordlist):
            wordlist = config.WORDLIST_LIGHT
        if not os.path.exists(wordlist):
            wordlist = config.WORDLIST_COMMON
        if not os.path.exists(wordlist):
            await context.emit_agent(self.name, f"wordlist missing: {wordlist}")
            return

        bases = _bases(context)
        if not full:
            bases = bases[:2]  # keep light-mode polite

        rate = 300 if full else 200
        threads = 20
        maxtime = 300 if full else 20

        await context.emit_agent(
            self.name, f"brute-forcing {len(bases)} host(s) @ {rate} req/s "
                       f"(wordlist: {os.path.basename(wordlist)})"
        )

        for base in bases:
            findings = await _ffuf_one(context, base, wordlist, rate, threads, maxtime)
            context.findings.extend(findings)
            for f in findings:
                await context.emit_agent(self.name, f"{f.severity}: {f.title} @ {f.location}")

        await context.emit_agent(self.name, "directory discovery done")


async def _ffuf_one(context, base, wordlist, rate, threads, maxtime):
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as tf:
        outfile = tf.name

    url = base.rstrip("/") + "/FUZZ"
    cmd = [
        "ffuf", "-u", url, "-w", wordlist,
        "-mc", FFUF_MC, "-t", str(threads), "-rate", str(rate),
        "-maxtime", str(maxtime), "-of", "json", "-o", outfile, "-s",
    ]
    from agents._common import run_capture
    found, out, err, rc = await run_capture(cmd, timeout=maxtime + 5)
    if not found:
        await context.emit_agent(self.name, "ffuf not found — install with `brew install ffuf`")
        return []
    if out is None:  # timed out; salvage partial output
        pass

    try:
        with open(outfile, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        results = data.get("results", [])
    except (OSError, json.JSONDecodeError):
        results = []
    finally:
        try:
            os.unlink(outfile)
        except OSError:
            pass

    if not results:
        return []

    results = _drop_soft404(results)
    if not results:
        await context.emit_agent(
            "discovery_dirs",
            f"all matches on {base} are the SPA/soft-404 shell (identical length); skipped",
        )
        return []

    findings = []
    seen = set()
    for r in results:
        url_found = r.get("url", "")
        if not url_found or url_found in seen:
            continue
        seen.add(url_found)
        status = r.get("status")
        word = r.get("input", {}).get("FUZZ", "").lower()
        sev, title = _classify(word, status)
        findings.append(_finding(title, sev, url_found, word, status))
    return findings


def _drop_soft404(results: list[dict]) -> list[dict]:
    """Drop ffuf hits that share one dominant response length.

    SPA/static hosts with a `/* -> /index.html 200` rewrite serve the same
    shell body (same content-length) for every unknown path, so the whole
    result set collapses to a single length. If one length covers most hits,
    it is the fallback shell — filter those out and keep any real outliers."""
    if len(results) < 3:
        return results
    from collections import Counter
    lengths = Counter(r.get("length") for r in results)
    dominant_len, dominant_count = lengths.most_common(1)[0]
    if dominant_len is None or dominant_count < max(2, len(results) // 2):
        return results
    kept = [r for r in results if r.get("length") != dominant_len]
    return kept


def _classify(word: str, status) -> tuple[str, str]:
    if any(s in word for s in SENSITIVE):
        return "medium", f"Interesting path exposed: /{word}"
    if status in (401, 403):
        return "info", f"Restricted path returns {status}: /{word}"
    return "info", f"Discovered path: /{word}"


def _finding(title, severity, location, word, status):
    from models import Finding
    return Finding(
        source_tool="discovery_dirs",
        title=title,
        severity=severity,
        category="Attack Surface",
        description=f"Path /{word} returned HTTP {status} during directory "
                    "brute-force. Review whether it should be publicly reachable.",
        location=location,
        raw_evidence=f"ffuf /{word} -> {status}",
        hint="Restrict or remove unlinked paths, require authentication where "
             "appropriate, and keep staging/admin endpoints off the public host.",
    )


def _bases(context) -> list[str]:
    bases = []
    for t in (context.targets or [context.url]):
        if t not in bases:
            bases.append(t)
    return bases