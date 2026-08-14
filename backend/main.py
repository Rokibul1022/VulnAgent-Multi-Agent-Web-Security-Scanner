import asyncio
import json

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from sse_starlette.sse import EventSourceResponse

import config
from memory import feedback_store
from models import ScanMode, ScanRequest
from orchestrator import scan_worker, subscribers
from storage.jobs import jobs

app = FastAPI(title="VulnAgent", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.mount("/screenshots", StaticFiles(directory=config.SCREENSHOTS_DIR), name="screenshots")


class FeedbackBody(BaseModel):
    finding_id: str = ""
    job_id: str = ""
    url: str = ""
    title: str = ""
    severity: str = "info"
    category: str = ""
    verdict: str = "uncertain"
    note: str = ""


@app.post("/feedback")
def submit_feedback(body: FeedbackBody):
    fid = feedback_store.add_feedback(
        finding_id=body.finding_id,
        job_id=body.job_id,
        url=body.url,
        title=body.title,
        severity=body.severity,
        verdict=body.verdict,
        note=body.note,
        category=body.category,
    )
    return {"id": fid}


@app.get("/feedback")
def get_feedback(limit: int = 100):
    return {"items": feedback_store.list_feedback(limit=limit)}


@app.post("/documents/upload")
async def upload_document(file: UploadFile = File(...)):
    raw = (await file.read()).decode(errors="replace")
    name = file.filename or "unnamed.txt"
    if not raw.strip():
        raise HTTPException(status_code=400, detail="Empty file")
    did = feedback_store.add_document(name, raw)
    return {"id": did, "name": name, "chars": len(raw)}


@app.get("/documents")
def get_documents():
    return {"items": feedback_store.list_documents()}


@app.get("/memory/lessons")
def get_lessons():
    return feedback_store.lessons()


@app.get("/")
def root():
    return {"service": "vuln-agent", "status": "ok"}


@app.post("/scan")
async def create_scan(req: ScanRequest):
    if not req.authorization_confirmed:
        raise HTTPException(
            status_code=400,
            detail="Authorization must be confirmed before a scan can start.",
        )
    job = jobs.create(
        url=req.url,
        scan_mode=req.scan_mode,
        authorization_confirmed=req.authorization_confirmed,
    )
    subscribers[job.job_id] = subscribers.get(job.job_id) or _make_subscriber()
    asyncio.create_task(scan_worker(job.job_id))
    return {"job_id": job.job_id}


@app.get("/scan/{job_id}/stream")
async def stream_scan(job_id: str):
    job = jobs.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Scan job not found")

    sub = subscribers[job.job_id] = _make_subscriber()

    async def event_gen():
        try:
            for entry in job.feed:
                yield {"event": entry["event"], "data": json.dumps(entry["data"])}
            while True:
                entry = await sub.next()
                yield {"event": entry["event"], "data": json.dumps(entry["data"])}
                if entry["event"] == "report_ready":
                    break
        except asyncio.CancelledError:
            pass

    return EventSourceResponse(event_gen())


@app.get("/scan/{job_id}/report")
async def get_report(job_id: str):
    job = jobs.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Scan job not found")
    if job.status != "completed" or not job.report:
        raise HTTPException(status_code=409, detail="Report not ready yet")
    return job.report


def _make_subscriber():
    from orchestrator import Subscriber

    return Subscriber()
