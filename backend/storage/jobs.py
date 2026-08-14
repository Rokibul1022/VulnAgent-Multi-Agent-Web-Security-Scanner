"""In-memory job store for local/demo use."""

import uuid

from models import ScanJob


class JobStore:
    def __init__(self):
        self._jobs: dict[str, ScanJob] = {}

    def create(self, url: str, scan_mode, authorization_confirmed: bool) -> ScanJob:
        job = ScanJob(
            job_id=uuid.uuid4().hex[:12],
            url=url,
            scan_mode=scan_mode,
            authorization_confirmed=authorization_confirmed,
        )
        self._jobs[job.job_id] = job
        return job

    def get(self, job_id: str) -> ScanJob | None:
        return self._jobs.get(job_id)

    def update(self, job: ScanJob) -> None:
        self._jobs[job.job_id] = job


jobs = JobStore()