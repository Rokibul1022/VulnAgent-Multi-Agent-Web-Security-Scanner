# agent.md — AI-Powered Web Vulnerability Scanner (Multi-Agent)

This file is the build spec/instructions for an AI coding agent (or a human) to
scaffold and implement this project. Follow it top to bottom.

---

## 0. Scope & Ground Rules

- **Authorized testing only.** The React UI must require the user to check a box
  confirming they own or have written permission to test the target domain
  before a scan can start. Log this confirmation with a timestamp.
- **Detection = real tools. LLM = interpretation.** Never ask the LLM to "find"
  vulnerabilities by reasoning over raw HTML/JS alone. It triages, deduplicates,
  ranks, and explains findings produced by actual scanners.
- **Output = hints, not exploits.** The final report gives remediation *direction*
  (e.g. "parameterize this query" / "add CSP header restricting script-src"),
  never working exploit payloads or step-by-step attack instructions.
- **Maximum coverage mode.** This spec now aims for the fullest realistic sweep
  across network, host, app, and content layers — see §4 for the complete
  agent roster. Some of these tools (sqlmap, full-range nmap, active ZAP scans)
  are noisy/intrusive and can trip IDS/WAF or affect site performance — the UI
  must let the user pick "passive/light" vs "full/active" scan mode, and
  active-mode tools should only ever run against the pre-authorized target.
- **LLM provider:** Groq API (OpenAI-compatible chat completions endpoint),
  not Anthropic. Model: `llama-3.3-70b-versatile` (or `openai/gpt-oss-120b` /
  whichever current Groq-hosted model is best for structured JSON output —
  check Groq's model list at build time since it changes).

---

## 1. High-Level Architecture

```
React (Vite) SPA
   │  REST + SSE
   ▼
FastAPI backend
   │
   ├── /scan (POST)        → creates ScanJob, kicks off orchestrator (background task)
   ├── /scan/{id}/stream    → SSE, streams stage progress + partial findings
   ├── /scan/{id}/report    → GET final structured report (JSON)
   │
   └── orchestrator.py
         ├── 1. Attack-Surface Agents  (subdomains, DNS, ports, WAF/tech fingerprint)
         ├── 2. Recon Agent            (crawl, forms, endpoints, screenshots)
         ├── 3. Content-Discovery Agents (dir/file brute force, exposed files, CMS ID)
         ├── 4. Scan Agents            (parallel: nuclei, zap, testssl, sqlmap, headers,
         │                              CORS, JWT, open-redirect, secrets)
         ├── 5. Triage Agent (LLM)     (dedupe, rank, explain, hint)
         └── 6. Report Builder         (assemble final JSON + markdown)
```

Each "agent" is just a Python class with a `run(context) -> context` method.
The orchestrator threads a shared `ScanContext` object through them. No need
for a heavy agent framework — this pipeline is a DAG, not an open-ended
reasoning loop, so plain asyncio orchestration is easier to debug than
LangGraph/CrewAI for v1.

---

## 2. Repo Structure

```
vuln-agent/
├── backend/
│   ├── venv/                      (gitignored)
│   ├── requirements.txt
│   ├── .env                       (GROQ_API_KEY, etc — gitignored)
│   ├── main.py                    FastAPI app entrypoint
│   ├── config.py
│   ├── models.py                  Pydantic models: ScanJob, Finding, Report
│   ├── orchestrator.py
│   ├── agents/
│   │   ├── recon.py
│   │   ├── surface_subdomains.py   subfinder/amass
│   │   ├── surface_dns.py          dig/dnsx records, zone leaks
│   │   ├── surface_ports.py        nmap
│   │   ├── surface_waf.py          wafw00f
│   │   ├── discovery_dirs.py       ffuf/gobuster content discovery
│   │   ├── discovery_cms.py        wpscan (or generic CMS fingerprint)
│   │   ├── discovery_exposure.py   .git/.env/backup-file exposure checks
│   │   ├── discovery_screenshot.py gowitness (visual triage of found hosts/paths)
│   │   ├── scan_nuclei.py
│   │   ├── scan_zap.py
│   │   ├── scan_tls.py
│   │   ├── scan_sqlmap.py          detection-only mode
│   │   ├── scan_headers.py
│   │   ├── scan_cors.py
│   │   ├── scan_jwt.py
│   │   ├── scan_open_redirect.py
│   │   ├── scan_secrets.py         trufflehog/gitleaks if repo/source reachable
│   │   └── triage_llm.py          Groq API calls live here
│   ├── llm/
│   │   ├── groq_client.py
│   │   └── prompts.py
│   ├── memory/
│   │   ├── embeddings.py           local embedding model (no external API)
│   │   ├── vector_store.py         Chroma wrapper: add/query/delete
│   │   ├── ingestion.py            doc upload → chunk → embed → store
│   │   ├── feedback_store.py       per-finding human feedback (SQLite)
│   │   └── lessons.py              periodic "lessons learned" summarizer
│   └── storage/
│       └── jobs.py                in-memory or SQLite job store
├── frontend/
│   └── (Vite + React app)
└── agent.md                       (this file)
```

---

## 3. Environment Setup (macOS)

```bash
# --- backend ---
mkdir -p vuln-agent/backend && cd vuln-agent/backend
python3 -m venv venv
source venv/bin/activate

pip install fastapi uvicorn[standard] httpx pydantic python-dotenv sse-starlette groq

# --- memory / RAG layer ---
pip install chromadb sentence-transformers pypdf python-multipart sqlalchemy

# --- external scanner binaries (via Homebrew) ---
brew install nuclei
brew install testssl.sh
brew install nmap
brew install subfinder
brew install amass
brew install dnsx
brew install ffuf
brew install wafw00f       # may need: pipx install wafw00f (not always in core brew)
brew install gowitness
brew install sqlmap
brew install gitleaks
pip install wpscan-python || true   # or use the Ruby gem: gem install wpscan
# OWASP ZAP: run headless via Docker instead of brew (more reliable CLI/API mode)
brew install --cask docker   # if not already installed
docker pull zaproxy/zap-stable

# --- wordlists for content discovery ---
brew install seclists      # provides /opt/homebrew/share/seclists

# --- frontend ---
cd ../
npm create vite@latest frontend -- --template react
cd frontend && npm install
npm install axios
```

`.env` (backend):
```
# Comma-separated — supports key rotation/failover, see §6.1
GROQ_API_KEYS=key_one,key_two,key_three
ZAP_DOCKER_IMAGE=zaproxy/zap-stable
NUCLEI_TEMPLATES_PATH=~/nuclei-templates
```

---

## 4. Agent Definitions

### 4.1 Attack-Surface Agents (run first, feed everything downstream)

- **`surface_subdomains.py`** — `subfinder -d <domain> -silent` (optionally
  chain into `amass enum -passive` for more coverage). Passive-only sources —
  don't do active brute-force subdomain guessing unless "full" mode is on.
  Output feeds every later stage: each live subdomain gets its own mini
  recon + scan pass, not just the root domain.
- **`surface_dns.py`** — pull A/AAAA/MX/TXT/NS records (`dnsx` or `dig`),
  check for SPF/DMARC presence, flag dangling CNAMEs (a common subdomain
  takeover vector).
- **`surface_ports.py`** — `nmap -sV --top-ports 100 <target>` in light mode;
  `nmap -sV -p- <target>` (full 65535) only in "full/active" mode since it's
  slow. Flags unexpected open services (DB ports, admin panels, debug ports).
- **`surface_waf.py`** — `wafw00f <target>` to detect if a WAF/CDN is in
  front of the site. Informs how the triage agent interprets scan noise
  (e.g. blocked requests aren't necessarily "no vulnerability," they may
  just be WAF-blocked) and tempers expectations for active scans.

### 4.2 Recon Agent (`agents/recon.py`)
Input: target URL + subdomains from 4.1.
Does:
- Fetch homepage, parse with BeautifulSoup for links/forms/inputs.
- Lightweight crawl (depth-limited, same-domain only, respect robots.txt).
- Grab response headers, cookies, detect tech stack from headers/meta tags.
Output: `{urls: [...], forms: [...], headers: {...}, tech_stack: [...]}`

### 4.3 Content-Discovery Agents

- **`discovery_dirs.py`** — `ffuf -u <target>/FUZZ -w <wordlist>` (or
  gobuster) to find unlinked paths: admin panels, backup dirs, staging
  endpoints. Use a moderate wordlist (e.g. SecLists `common.txt`) by default;
  large wordlists only in full mode, and rate-limit requests to avoid
  hammering the target.
- **`discovery_cms.py`** — if tech fingerprint from recon says WordPress/
  Drupal/Joomla, run the matching specialized scanner (`wpscan --url <target>
  --enumerate vp,vt,u` for WordPress: vulnerable plugins/themes/users). Skip
  entirely if no CMS is detected — don't run CMS scanners blind.
- **`discovery_exposure.py`** — pure HTTP checks (no special tool needed):
  request `/.git/config`, `/.env`, `/.DS_Store`, `/backup.zip`, `/wp-config.php.bak`,
  common source-map files, `/.well-known/`, exposed `phpinfo()`, directory
  listing on common dirs. Flag anything that returns 200 with real content.
- **`discovery_screenshot.py`** — `gowitness scan file -f urls.txt` to
  screenshot every discovered host/path. Not a vulnerability finding itself,
  but attaches visual context to the report (e.g. "this exposed admin panel
  looks like — screenshot") which helps a human triage faster.

### 4.4 Scan Agents (parallel, subprocess-based)
Each wraps a CLI tool and normalizes its output into a common `Finding` schema:

```python
class Finding(BaseModel):
    source_tool: str
    title: str
    severity: str  # info/low/medium/high/critical
    description: str
    location: str  # URL, param, or header name
    raw_evidence: str
    cwe: str | None = None
```

- **`scan_nuclei.py`** — `nuclei -u <target> -json-export out.json` — best
  signal-to-noise, covers CVEs, exposed panels, misconfig templates.
- **`scan_zap.py`** — drive ZAP via its Docker API (`zap-baseline.py` or full
  active scan via ZAP's REST API) for XSS/SQLi/injection-class findings.
- **`scan_tls.py`** — `testssl.sh --jsonfile out.json <target>` for cert/cipher
  issues.
- **`scan_headers.py`** — pure Python check (no external tool needed) for
  missing security headers: CSP, HSTS, X-Frame-Options, X-Content-Type-Options,
  Referrer-Policy, Permissions-Policy.
- **`scan_sqlmap.py`** — **detection-only mode**: `sqlmap -u <url> --batch
  --level=1 --risk=1 --smart` against forms/params found in recon. Never run
  `--dump`, `--os-shell`, or any data-extraction/exploitation flags — the
  goal is a boolean "this parameter appears injectable," not proof-of-concept
  extraction. Only run in "full/active" mode given how intrusive even
  detection-level sqlmap traffic is.
- **`scan_cors.py`** — send requests with crafted `Origin` headers and check
  if `Access-Control-Allow-Origin` reflects arbitrary origins or `null`
  combined with `Access-Control-Allow-Credentials: true` (classic CORS
  misconfig letting any site read authenticated responses).
- **`scan_jwt.py`** — if a JWT is spotted in cookies/headers during recon,
  statically decode it (no server calls) to flag weak/none algorithm usage,
  missing expiry, or overly long expiry — flag only, don't attempt to forge
  or crack signing keys.
- **`scan_open_redirect.py`** — test common redirect params (`?next=`,
  `?url=`, `?redirect=`, etc. found in recon) against a benign external
  test domain to see if the app redirects off-domain unchecked.
- **`scan_secrets.py`** — if a repo URL or exposed `.git` directory was found
  by `discovery_exposure.py`, run `trufflehog` or `gitleaks` against it to
  flag committed secrets (API keys, credentials). Skip if no source is
  reachable — don't invent a target.

Run these concurrently with `asyncio.gather` + `asyncio.create_subprocess_exec`,
respecting the passive/light vs full/active mode toggle from the UI.

### 4.5 Triage Agent (`agents/triage_llm.py`) — Groq-powered, memory-augmented
Input: full list of raw `Finding` objects + recon context + **retrieved
memory** (relevant past feedback + relevant uploaded-doc chunks — see §5).
Job:
1. Deduplicate near-identical findings across tools.
2. Re-rank severity using context (e.g. a missing header on a static marketing
   page matters less than the same header missing on a login page) **and**
   using retrieved memory (e.g. "past feedback says this tool/finding
   combination is usually a false positive here — downweight confidence").
3. For each finding, generate:
   - plain-English explanation of the risk
   - a **hint**, not a fix: point at the right concept/technique/OWASP
     category without giving copy-pasteable exploit or full solution code.
     If a retrieved doc chunk contains a relevant org policy/standard,
     ground the hint in it (e.g. "per your uploaded security policy §4.2,
     all admin endpoints require IP allowlisting").
4. Return strict JSON matching the `Report` schema — Groq's OpenAI-compatible
   endpoint supports `response_format={"type": "json_object"}`, use it.

Prompt lives in `llm/prompts.py`. Keep the system prompt explicit about the
hints-not-fixes constraint and about not inventing findings that weren't in
the tool output (no hallucinated vulns) — retrieved memory informs framing
and confidence, it never becomes a new finding on its own.

### 4.6 Report Builder
Merges triaged findings into the final `Report` object, sorted by severity,
grouped by category (Injection, Auth, Config, Transport, Headers, etc.),
written to the job store and served via `/scan/{id}/report`. Each finding
carries a `finding_id` so the frontend can attach human feedback to it later.

---

## 5. Memory, Feedback & Document Learning Layer

**Important framing:** this is *not* RLHF. RLHF means updating a model's
weights via a reward model trained on human preference data — that requires
owning and training the underlying model, which isn't possible against a
hosted Groq model. What's built here is the practical equivalent for a
system built on API-based LLMs: a **retrieval + feedback loop** that makes
the agent's output *behave* like it's learning, without ever touching model
weights. This is the standard, correct pattern for this kind of project.

### 5.1 Components

- **Vector store (`memory/vector_store.py`)** — Chroma, running locally
  (embedded, persisted to disk under `backend/chroma_data/`). No external
  vector DB service needed for v1; swap for Qdrant/Pinecone later only if
  you outgrow local storage.
- **Embeddings (`memory/embeddings.py`)** — run locally via
  `sentence-transformers` (e.g. `all-MiniLM-L6-v2`), not through Groq —
  Groq doesn't currently serve an embeddings endpoint, so this must be a
  separate, free, local model. Keeps the whole memory layer dependency-free
  of any second paid API.
- **Feedback store (`memory/feedback_store.py`)** — SQLite table:
  `finding_id, scan_id, tool, finding_title, human_label
  (true_positive/false_positive/useful_hint/bad_hint), note, timestamp`.
  This is structured data used both directly (filter/query) and embedded
  into the vector store for semantic retrieval.
- **Document ingestion (`memory/ingestion.py`)** — user uploads PDFs/docs
  (security policy, past pentest reports, coding standards) → extract text
  (reuse the `pdf` handling patterns already in this project) → chunk
  (~500 tokens, ~50 token overlap) → embed → store in Chroma with metadata
  (`doc_name`, `chunk_index`, `upload_date`).
- **Lessons summarizer (`memory/lessons.py`)** — a scheduled or
  post-scan job: take recent feedback entries, send them to Groq to produce
  a short "lessons learned" digest (e.g. "nuclei's `exposed-panel` template
  frequently false-positives on this target's staging subdomain"). Store
  the digest itself as a memory entry, and inject the *latest* digest into
  every triage system prompt. This is the actual "self-improvement" loop —
  it happens via prompt content, not weight updates.

### 5.2 Retrieval flow (RAG) at triage time

```
new findings + recon context
        │
        ▼
embed a query summary of this scan
        │
        ▼
query Chroma for top-k relevant:
  - past feedback entries (same tool/finding-type, this domain or similar)
  - uploaded-doc chunks (policy/standards relevant to affected asset)
  - latest "lessons learned" digest
        │
        ▼
inject retrieved context into triage_llm.py system/user prompt
        │
        ▼
Groq triage call → report
```

### 5.3 New Endpoints

```
POST /documents/upload
  multipart file upload (pdf/docx/txt)
  → chunks, embeds, stores in Chroma
  → { "doc_id": str, "chunks_indexed": int }

GET /documents
  → list of uploaded docs with metadata

POST /feedback
  body: { "finding_id": str, "scan_id": str, "label": str, "note": str? }
  → stores in feedback_store, and embeds a compact representation into
    Chroma so it's retrievable in future triage calls

GET /memory/lessons
  → latest "lessons learned" digest (mostly for debugging/transparency —
    lets you see what the agent has "learned" in plain English)
```

### 5.4 Frontend additions

- **Document upload panel** — drag/drop PDFs/docs, shows indexed status.
- **Feedback controls on each finding card** — 👍 true positive / 👎 false
  positive / "hint was useful" / "hint was bad" + optional free-text note.
  This is the whole human-feedback UI; no separate review workflow needed
  for v1.
- Optional: a small "what the agent has learned" panel showing the latest
  lessons digest from `/memory/lessons` — good for building trust that
  feedback is actually doing something.

### 5.5 What this deliberately does NOT do

- No model fine-tuning or weight updates — everything above is retrieval +
  prompting against the same fixed Groq model.
- No automatic action from lessons learned without human review of the
  digest at least periodically — a bad batch of feedback (e.g. a user
  mislabeling real findings as false positives) shouldn't silently poison
  future triage without some visibility. The `/memory/lessons` endpoint
  exists partly so this stays inspectable, not a black box.

---

## 6. Groq Client (`llm/groq_client.py`)

### 6.1 Multi-key rotation / failover

The pattern you want is: hold a pool of keys, try the current one, and on a
rate-limit error move to the next key and retry — cycling back to the first
once you've gone through the pool. One real caveat worth building in from
day one: **if every key is rate-limited, don't spin forever** — that's not
resilience, that's a hung request and (if it's inside a retry loop with no
cap) a way to silently hammer Groq's API. Cap total attempts at pool-size ×
small-retry-count, and if everything's exhausted, fail that triage call
gracefully (queue it / mark that stage as "delayed, retrying" in the SSE
stream) rather than blocking the whole scan.

```python
import os
import time
import itertools
from groq import Groq
from groq import RateLimitError, APIStatusError

class GroqKeyPool:
    def __init__(self, keys: list[str]):
        if not keys:
            raise ValueError("No Groq API keys configured")
        self._clients = [Groq(api_key=k) for k in keys]
        self._cycle = itertools.cycle(range(len(self._clients)))
        self._current = next(self._cycle)

    def _advance(self):
        self._current = next(self._cycle)

    def chat_completion(self, max_attempts: int = None, **kwargs) -> dict:
        max_attempts = max_attempts or len(self._clients) * 2
        last_err = None
        for attempt in range(max_attempts):
            client = self._clients[self._current]
            try:
                return client.chat.completions.create(**kwargs)
            except RateLimitError as e:
                last_err = e
                self._advance()          # try the next key
                time.sleep(min(2 ** (attempt % 4), 10))  # light backoff
                continue
            except APIStatusError as e:
                # non-rate-limit API error (bad request, server error, etc.)
                # — don't burn through keys for this, it'll fail on all of them
                raise
        raise RuntimeError(
            f"All Groq keys exhausted after {max_attempts} attempts"
        ) from last_err

_pool = GroqKeyPool(os.environ["GROQ_API_KEYS"].split(","))

def triage_findings(findings_json: str, recon_context: str, memory_context: str = "") -> dict:
    completion = _pool.chat_completion(
        model="llama-3.3-70b-versatile",
        response_format={"type": "json_object"},
        messages=[
            {"role": "system", "content": TRIAGE_SYSTEM_PROMPT + "\n\n" + memory_context},
            {"role": "user", "content": f"RECON:\n{recon_context}\n\nFINDINGS:\n{findings_json}"},
        ],
        temperature=0.2,
    )
    return completion.choices[0].message.content  # JSON string, parse it
```

A few things worth deciding explicitly rather than leaving implicit:
- **Per-key usage tracking** (optional but useful): log which key served
  each request and any 429s per key, so you can see in practice whether
  you actually need 2 keys or 5 — easy to over-provision keys you don't need.
- **Free-tier key pooling has ToS implications** — check Groq's terms on
  using multiple free-tier keys under one account/project before relying on
  this in anything beyond personal/local use; this pattern is standard for
  paid-tier keys but worth confirming for free-tier ones specifically.

Note the Groq Python SDK mirrors the OpenAI SDK shape. Verify current model
names, exception class names (`RateLimitError`/`APIStatusError`), and
`response_format` support against Groq's docs at build time — their model
lineup and SDK details change fairly often.

---

## 7. FastAPI Endpoints

```
POST /scan
  body: {
    "url": str,
    "authorization_confirmed": bool,
    "scan_mode": "light" | "full"   // gates nmap full-range, sqlmap,
                                     // large-wordlist ffuf, amass active
  }
  → 202 { "job_id": str }

GET /scan/{job_id}/stream   (SSE)
  → stage events: surface_done, recon_done, discovery_done, scans_done,
    triage_done, report_ready  (plus per-agent sub-events if you want a
    granular progress view, e.g. "nuclei_done", "sqlmap_done")

GET /scan/{job_id}/report
  → full Report JSON
```

Reject `/scan` with 400 if `authorization_confirmed` is false. In "full"
mode, consider also requiring a second explicit confirmation in the UI
(separate from the base authorization checkbox) since full mode runs
active/intrusive tools (sqlmap, full nmap, active ZAP).

---

## 8. React Frontend (v1 scope)

### 8.1 Visual direction — dark theme, grounded in the subject

Skip the generic "near-black background + neon-green/acid accent" hacker
look — it's become the default AI reaches for on any dark security-ish UI,
which means it reads as templated rather than considered. This tool's real
subject is *signal in noise*: raw scanner output, severity triage, evidence.
Lean into that instead of a generic "hacker terminal" skin.

**Token system:**

| Token | Value | Use |
|---|---|---|
| `--bg` | `#14120F` | app background — warm ink, not blue-black |
| `--surface` | `#1D1A16` | cards, panels |
| `--surface-raised` | `#26221C` | modals, active/hovered cards |
| `--border` | `#332D24` | hairline dividers |
| `--text-primary` | `#EDE6DA` | warm off-white, not pure white |
| `--text-secondary` | `#9C9184` | muted taupe, secondary copy |
| `--accent` | `#C98A3E` | brass/amber — primary interactive color |
| `--accent-dim` | `#8A6230` | hover/disabled states of accent |

**Severity colors are functional, not decorative** — pick a set that's
distinct enough to be readable by colorblind users too (pair color with an
icon/label, don't rely on hue alone):
- Critical `#E0524A` · High `#D98B3E` · Medium `#D9C23E` · Low `#4A90A4` · Info `#6B7280`

**Typography:** three roles, each earning its place from the subject matter
rather than picked for looks —
- **Display** (headers, scan status): a technical grotesk with some
  character — e.g. `Space Grotesk` — used with restraint, not on every label.
- **Body** (descriptions, hints, UI copy): `IBM Plex Sans` or `Inter` —
  clean, readable at small sizes for dense finding cards.
- **Mono** (raw tool output, evidence snippets, headers/params): `IBM Plex
  Mono` or `JetBrains Mono` — this one isn't a stylistic flourish, it's
  actually correct for the content: real scanner output *is* monospace
  text, so use it there and nowhere else.

**Signature element:** rather than decorative animation, make the one
memorable thing *functional* — a live "signal feed" panel during an active
scan that streams raw agent output (via the SSE connection you're already
building) line by line, monospace, like watching the scan actually happen.
This does double duty: it's visually distinctive *and* gives the user real
transparency into what's running, which matters for a security tool where
"trust the black box" is a bad look.

**Restraint:** one accent color, used sparingly (primary buttons, active
states, links) — not gradients, not glow effects. Severity colors carry the
emotional weight of the UI; the accent color should stay quiet so severity
colors read clearly against it. Keep border-radius modest and consistent
(not zero — that's the "broadsheet" default; not fully rounded either).

If frontend scaffolding is done via Claude Code / an agentic tool, point it
at `/mnt/skills/public/frontend-design/SKILL.md`-equivalent guidance (or
just this section) before generating components, so token choices stay
consistent across files instead of drifting per-component.

### 8.2 Structure

- Single page: URL input + authorization checkbox + light/full scan-mode
  toggle (+ second confirmation if "full" selected) + "Start Scan" button.
- Progress view: subscribes to `/scan/{id}/stream` (EventSource), shows a
  stepper (Surface → Recon → Discovery → Scanning → Triage → Report), with
  each active agent (nuclei, zap, sqlmap, etc.) listed as it completes,
  alongside the live signal-feed panel described above.
- Report view: findings grouped first by category (Network, Attack Surface,
  Content Exposure, Web App / Injection, Transport, Headers, Auth/JWT, CORS,
  Secrets), then by severity within each. Expandable cards show description +
  hint + source tool + location, with screenshots attached where available
  (from `discovery_screenshot.py`). Severity shown via color + icon/label.
- Feedback controls (👍/👎 + note) on each finding card, per §5.4.
- Document upload panel + "what the agent has learned" panel, per §5.4.

Keep state management simple (useState/useReducer) — no need for Redux at
this scale.

---

## 9. Build Order (milestones)

1. FastAPI skeleton + `/scan` endpoint returning a hardcoded fake report →
   wire up React to confirm end-to-end plumbing works. Set up the dark-theme
   design tokens (§8.1) as CSS variables from the start — retrofitting a
   theme after components exist is more work than starting with it.
2. Recon agent + header-check agent (pure Python, no external binaries) →
   real but limited findings.
3. Add nuclei agent (single subprocess call, easiest external tool to wire up).
4. Add Groq triage agent via `GroqKeyPool` (§6.1) from the start, even with
   just one key configured — the pool interface is the same whether it holds
   one key or five, so there's no rework later when you add more.
5. Add testssl.sh agent.
6. Add attack-surface agents: subfinder, dnsx, nmap (light mode), wafw00f.
   Fan out recon + later stages across discovered subdomains.
7. Add content-discovery agents: discovery_exposure.py (cheap, no external
   tool), then ffuf, then discovery_cms.py (conditional on tech fingerprint).
8. Add scan_cors.py, scan_jwt.py, scan_open_redirect.py — all pure Python,
   no new binaries, quick wins for coverage.
9. Add ZAP (Docker) agent — slowest and most infra-heavy of the core scanners.
10. Add scan_secrets.py (gitleaks/trufflehog) — conditional on exposed `.git`.
11. Add full/active mode gating: nmap full-range, sqlmap detection-only,
    amass active, large-wordlist ffuf — all behind the second confirmation.
12. Add discovery_screenshot.py (gowitness) for visual triage in the report.
13. Add the memory layer: Chroma + local embeddings + feedback_store.py
    first (pure infra, no UI yet) — verify embed/query works standalone.
14. Wire `/feedback` endpoint + feedback buttons on report cards; confirm
    entries land in both SQLite and Chroma.
15. Add `/documents/upload` + ingestion pipeline; test retrieval quality
    with a real policy doc before trusting it in triage prompts.
16. Wire retrieval into `triage_llm.py` (§5.2) — start with just feedback
    retrieval, add doc-chunk retrieval once that's working cleanly.
17. Add `memory/lessons.py` summarizer + `/memory/lessons` endpoint last —
    it depends on having enough real feedback volume to be worth running.
18. Polish report grouping/severity ranking across categories, tune SSE
    progress granularity down to per-agent events.

---

## 10. Open Questions to Resolve During Build

- Job persistence: in-memory dict is fine for local/demo use; move to SQLite
  if scans need to survive a backend restart.
- Timeouts: ZAP active scans can run long — set a hard cap (e.g. 10 min) and
  surface partial results if it's exceeded.
- Rate limiting Groq calls if triaging findings in batches vs. one call —
  with this many agents, findings per scan could be large; consider
  batching triage calls per category rather than one giant prompt.
- Subdomain fan-out cost: if `surface_subdomains.py` returns 50+ live hosts,
  decide whether to scan all of them or cap to top N (by response/interest)
  to keep scan time and Groq usage reasonable — surface this as a setting.
- Tool overlap/noise: nuclei, ZAP, and the header/CORS/JWT checks will often
  flag the same underlying issue from different angles — the triage agent's
  dedup step is doing real work here and is worth testing on messy real
  output early, not just clean synthetic examples.
- Legal/rate-limit courtesy: even with authorization, throttle discovery
  (ffuf) and sqlmap requests (e.g. `--delay`, `-rate`) to avoid degrading
  the target's performance for real users during the test.
- Memory hygiene: decide whether feedback/memory is scoped per-target-domain
  or global across all scans — global learning is more useful (more data)
  but risks lessons from one site's quirks leaking into another's triage;
  namespacing Chroma collections by domain is the simplest fix if it
  becomes a problem.
- Feedback volume threshold: decide how much feedback is needed before the
  lessons summarizer produces something meaningful vs. just noise — don't
  run it automatically until there's a reasonable sample (e.g. 20+ labeled
  findings).
