import os
import fcntl
from dataclasses import dataclass, field
from threading import Lock
from typing import Optional

from api.logger import logger

from .dfp import DFPManager
from .payload import PayloadManager


OFFSET_FILE = os.path.join("/var/lib/rest.dfp-challenger", "order_offset.txt")

@dataclass
class Job:
    """Encapsulates all state for a single scoring job."""
    request_id: str
    manager: DFPManager
    payload_mgr: PayloadManager
    start_id: int
    session_map: dict[int, int] = field(default_factory=dict)

class JobRegistry:
    """Registry to manage multiple jobs."""
    def __init__(self):
        self._jobs: dict[str, Job] = {}
        self._jobs_lock = Lock()
        self._order_to_request: dict[int, str] = {}
        self._order_lock = Lock()

    def register(self, job: Job):
           with self._jobs_lock:
               self._jobs[job.request_id] = job
           with self._order_lock:
               for order_id in job.session_map:
                   self._order_to_request[order_id] = job.request_id

    def get_by_request(self, request_id: str) -> Optional[Job]:
           """Get job by request_id."""
           with self._jobs_lock:
               return self._jobs.get(request_id)

    def get_by_order(self, order_id: int) -> Optional[Job]:
           """Get job by order_id (reverse lookup)."""
           with self._order_lock:
               request_id = self._order_to_request.get(order_id)
           if not request_id:
               return None
           return self.get_by_request(request_id)

    def unregister(self, request_id: str) -> None:
           """Clean up job after scoring completes."""
           with self._jobs_lock:
               job = self._jobs.pop(request_id, None)
           if job:
               with self._order_lock:
                   for order_id in job.session_map:
                       self._order_to_request.pop(order_id, None)


job_registry = JobRegistry()


def reserve_offset_range(count: int) -> int:
    """Atomically reserve a range of order IDs and return the start ID."""
    try:
        os.makedirs(os.path.dirname(OFFSET_FILE), exist_ok=True)
        with open(OFFSET_FILE, "a+") as f:
            fcntl.flock(f.fileno(), fcntl.LOCK_EX)
            try:
                f.seek(0)
                content = f.read().strip()
                start_id = int(content) if content else 0
                f.seek(0)
                f.truncate()
                f.write(str(start_id + count))
                return start_id
            finally:
                fcntl.flock(f.fileno(), fcntl.LOCK_UN)
    except Exception as e:
        logger.error(f"Failed to reserve offset range: {e}")
        return 0
    
__all__ = [
    "Job",
    "JobRegistry",
    "job_registry",
    "reserve_offset_range",
]
