"""Memory layer: SQLite feedback/document store + Chroma vector index.

Feedback verdicts and uploaded policy docs are stored in SQLite (source of
truth) and mirrored into a persistent Chroma collection so triage can retrieve
relevant past verdicts and policy snippets (§5.1/§5.2 of agent.md).
"""

import os
import sqlite3
import uuid
from datetime import datetime, timezone

import chromadb

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STORAGE = os.path.join(BASE, "storage")
os.makedirs(STORAGE, exist_ok=True)
DB_PATH = os.path.join(STORAGE, "memory.db")
CHROMA_DIR = os.path.join(STORAGE, "chroma")

_client = None

VALID_VERDICTS = {"true_positive", "false_positive", "uncertain"}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS feedback (
            id TEXT PRIMARY KEY,
            finding_id TEXT,
            job_id TEXT,
            url TEXT,
            title TEXT,
            severity TEXT,
            category TEXT,
            verdict TEXT,
            note TEXT,
            created_at TEXT
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS documents (
            id TEXT PRIMARY KEY,
            name TEXT,
            text TEXT,
            created_at TEXT
        )
        """
    )
    return conn


def _chroma():
    global _client
    if _client is None:
        _client = chromadb.PersistentClient(path=CHROMA_DIR)
    return _client


def _collection():
    return _chroma().get_or_create_collection(
        name="memory",
        metadata={"hnsw:space": "cosine"},
    )


def add_feedback(finding_id, job_id, url, title, severity, verdict, note="", category=""):
    verdict = verdict if verdict in VALID_VERDICTS else "uncertain"
    conn = _db()
    fid = uuid.uuid4().hex[:12]
    conn.execute(
        "INSERT INTO feedback VALUES (?,?,?,?,?,?,?,?,?,?)",
        (fid, finding_id, job_id, url, title, severity, category, verdict, note, _now()),
    )
    conn.commit()
    text = f"{title} @ {url} [severity: {severity}] verdict: {verdict}. {note}".strip()
    try:
        _collection().upsert(
            ids=[fid],
            documents=[text],
            metadatas=[{
                "kind": "feedback", "verdict": verdict,
                "finding_id": finding_id, "job_id": job_id, "category": category,
            }],
        )
    except Exception:  # noqa: BLE001  (never let memory break the app)
        pass
    return fid


def add_document(name, text):
    text = text or ""
    conn = _db()
    did = uuid.uuid4().hex[:12]
    conn.execute("INSERT INTO documents VALUES (?,?,?,?)", (did, name, text, _now()))
    conn.commit()
    chunks = _chunk(text)
    ids = [f"{did}:{i}" for i in range(len(chunks))]
    try:
        _collection().upsert(
            ids=ids,
            documents=chunks,
            metadatas=[{"kind": "document", "doc_id": did, "name": name}] * len(chunks),
        )
    except Exception:  # noqa: BLE001
        pass
    return did


def search(query: str, n: int = 5, kind: str | None = None) -> list[dict]:
    where = {"kind": kind} if kind else None
    try:
        res = _collection().query(query_texts=[query], n_results=max(n, 1), where=where)
    except Exception:  # noqa: BLE001
        return []
    out = []
    docs = (res.get("documents") or [[]])[0]
    metas = (res.get("metadatas") or [[]])[0]
    dists = (res.get("distances") or [[]])[0]
    for doc, meta, dist in zip(docs, metas, dists):
        out.append({
            "text": doc,
            "kind": (meta or {}).get("kind"),
            "verdict": (meta or {}).get("verdict"),
            "name": (meta or {}).get("name"),
            "distance": dist,
        })
    return out


def list_feedback(limit: int = 100) -> list[dict]:
    conn = _db()
    rows = conn.execute(
        "SELECT * FROM feedback ORDER BY created_at DESC LIMIT ?", (limit,)
    ).fetchall()
    return [dict(r) for r in rows]


def list_documents() -> list[dict]:
    conn = _db()
    rows = conn.execute(
        "SELECT id, name, length(text) AS chars, created_at FROM documents "
        "ORDER BY created_at DESC"
    ).fetchall()
    return [dict(r) for r in rows]


def feedback_stats() -> dict:
    conn = _db()
    rows = conn.execute(
        "SELECT verdict, COUNT(*) AS n FROM feedback GROUP BY verdict"
    ).fetchall()
    counts = {r["verdict"]: r["n"] for r in rows}
    by_cat = {}
    for r in conn.execute(
        "SELECT category, COUNT(*) AS n FROM feedback WHERE category != '' "
        "GROUP BY category ORDER BY n DESC LIMIT 20"
    ).fetchall():
        by_cat[r["category"]] = r["n"]
    return {
        "total": sum(counts.values()),
        "verdicts": counts,
        "top_categories": by_cat,
    }


def lessons() -> list[dict]:
    """Simple deterministic lessons from stored feedback (agent.md §5.3).

    Surfaces recurring true-positive categories and past false positives so a
    user can see what the scanner learned."""
    stats = feedback_stats()
    conn = _db()
    recent_tp = conn.execute(
        "SELECT title, category, severity, COUNT(*) AS n FROM feedback "
        "WHERE verdict = 'true_positive' GROUP BY title ORDER BY n DESC LIMIT 8"
    ).fetchall()
    recent_fp = conn.execute(
        "SELECT title, category, COUNT(*) AS n FROM feedback "
        "WHERE verdict = 'false_positive' GROUP BY title ORDER BY n DESC LIMIT 8"
    ).fetchall()
    return {
        "generated_at": _now(),
        "summary": stats,
        "recurring_true_positives": [dict(r) for r in recent_tp],
        "recurring_false_positives": [dict(r) for r in recent_fp],
    }


def _chunk(text: str, size: int = 1200) -> list[str]:
    if not text:
        return [""]
    if len(text) <= size:
        return [text]
    return [text[i : i + size] for i in range(0, len(text), size)]
