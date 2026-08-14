"""Static JWT analysis (no server calls).

Scans headers captured during recon (Authorization, Set-Cookie) for JWTs and
decodes them client-side to flag weak/none algorithms, missing expiry, and
overly long expiry. Flags only — never forges or cracks tokens."""

import base64
import json
import re
from datetime import datetime, timezone

JWT_RE = re.compile(
    r"[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"
)
KNOWN_ALGS = {
    "HS256", "HS384", "HS512",
    "RS256", "RS384", "RS512",
    "ES256", "ES384", "ES512",
    "PS256", "PS384", "PS512",
}
LONG_EXPIRY_DAYS = 90
MAX_TOKENS = 20


class JwtScanAgent:
    name = "scan_jwt"

    async def run(self, context):
        headers = (context.results.get("recon", {}) or {}).get("headers", {})
        tokens = _extract_tokens(headers)
        if not tokens:
            await context.emit_agent(self.name, "no JWT found in recon headers")
            return

        await context.emit_agent(self.name, f"found {len(tokens)} JWT candidate(s), analyzing")
        findings = []
        now = datetime.now(timezone.utc)

        for location, token in tokens[:MAX_TOKENS]:
            decoded = _decode(token)
            if decoded is None:
                continue
            header, payload = decoded

            alg = header.get("alg", "")
            if alg.lower() == "none":
                findings.append(_finding(
                    "high", "JWT signed with 'none' algorithm", location,
                    f"header alg=none for token {_snippet(token)}",
                    "Token accepts the 'none' algorithm; an attacker can forge a "
                    "token with arbitrary claims and it will be accepted.",
                    "CWE-347",
                ))
            elif alg not in KNOWN_ALGS:
                findings.append(_finding(
                    "low", f"JWT uses non-standard algorithm '{alg}'", location,
                    f"header alg={alg} for token {_snippet(token)}",
                    "Unusual signing algorithm; confirm the token is from a "
                    "trusted issuer using a recognized, secure algorithm.",
                    None,
                ))

            exp = payload.get("exp")
            if exp is None:
                findings.append(_finding(
                    "medium", "JWT has no expiry", location,
                    f"payload lacks exp for token {_snippet(token)}",
                    "Token never expires, so a leaked token stays valid "
                    "indefinitely.",
                    None,
                ))
            elif isinstance(exp, (int, float)):
                exp_dt = datetime.fromtimestamp(exp, tz=timezone.utc)
                age = (exp_dt - now).days
                if age > LONG_EXPIRY_DAYS:
                    findings.append(_finding(
                        "low", "JWT has overly long expiry", location,
                        f"exp {exp_dt.isoformat()} ({age} days) for token {_snippet(token)}",
                        "A very long-lived token widens the window in which a "
                        "leaked token can be abused.",
                        None,
                    ))

        context.findings.extend(findings)
        context.results[self.name] = {"tokens_found": len(tokens), "findings": len(findings)}
        await context.emit_agent(self.name, f"JWT analysis done: {len(findings)} finding(s)")


def _extract_tokens(headers) -> list[tuple[str, str]]:
    """Return [(location, token)] for JWTs found in response headers."""
    out = []
    seen = set()
    for url, hdrs in headers.items():
        for key, value in hdrs.items():
            k = key.lower()
            if k in ("authorization", "set-cookie", "cookie"):
                vals = value
                if isinstance(vals, str):
                    vals = [vals]
                for v in vals:
                    for piece in v.split(";"):
                        piece = piece.strip()
                        if piece.lower().startswith("bearer "):
                            piece = piece[7:]
                        if "=" in piece and k in ("set-cookie", "cookie"):
                            piece = piece.split("=", 1)[1]
                        m = JWT_RE.search(piece)
                        if m and len(m.group(0)) > 40:
                            tok = m.group(0)
                            if tok not in seen:
                                seen.add(tok)
                                out.append((url, tok))
    return out


def _decode(token: str) -> tuple[dict, dict] | None:
    parts = token.split(".")
    try:
        header = json.loads(_b64(parts[0]))
        payload = json.loads(_b64(parts[1]))
        return header, payload
    except (json.JSONDecodeError, ValueError):
        return None


def _b64(s: str) -> bytes:
    s = s.encode()
    return base64.urlsafe_b64decode(s + b"=" * (-len(s) % 4))


def _snippet(token: str) -> str:
    return token[:25] + "..." if len(token) > 28 else token


def _finding(severity, title, location, evidence, description, cwe):
    from models import Finding
    return Finding(
        source_tool="scan_jwt",
        title=title,
        severity=severity,
        category="Auth/JWT",
        description=description,
        location=location,
        raw_evidence=evidence,
        hint="Use a recognized signing algorithm (e.g. RS256), always set an "
             "expiry and validate it, and reject the 'none' algorithm at the "
             "server.",
        cwe=cwe,
    )