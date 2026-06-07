import logging
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class ScanTask:
    task_id: str
    fn: Callable
    args: tuple = field(default_factory=tuple)
    kwargs: Dict[str, Any] = field(default_factory=dict)
    attempt: int = 0
    result: Optional[Any] = None
    error: Optional[str] = None
    success: bool = False


class ScanScheduler:
   

    def __init__(
        self,
        max_workers: int = 10,
        rate_limit_delay: float = 0.1,
        retry_attempts: int = 2,
        retry_delay: float = 3.0,
    ) -> None:
        self.max_workers = max_workers
        self.rate_limit_delay = rate_limit_delay
        self.retry_attempts = retry_attempts
        self.retry_delay = retry_delay
        self._executor: Optional[ThreadPoolExecutor] = None

    def __enter__(self) -> "ScanScheduler":
        self._executor = ThreadPoolExecutor(max_workers=self.max_workers)
        return self

    def __exit__(self, *_: Any) -> None:
        if self._executor:
            self._executor.shutdown(wait=True)
            self._executor = None

    def _run_with_retry(self, task: ScanTask) -> ScanTask:

        for attempt in range(self.retry_attempts + 1):
            task.attempt = attempt + 1
            try:
                logger.debug(
                    "Task %s attempt %d/%d",
                    task.task_id,
                    task.attempt,
                    self.retry_attempts + 1,
                )
                task.result = task.fn(*task.args, **task.kwargs)
                task.success = True
                return task
            except Exception as exc:
                task.error = str(exc)
                logger.warning(
                    "Task %s failed (attempt %d): %s",
                    task.task_id,
                    task.attempt,
                    exc,
                )
                if attempt < self.retry_attempts:
                    logger.debug("Retrying task %s in %ss", task.task_id, self.retry_delay)
                    time.sleep(self.retry_delay)

        logger.error("Task %s exhausted all retry attempts", task.task_id)
        return task

    def submit_tasks(self, tasks: List[ScanTask]) -> List[ScanTask]:
        
        if not self._executor:
            raise RuntimeError("ScanScheduler must be used as a context manager")

        futures: list = []
        for task in tasks:
            futures.append(self._executor.submit(self._run_with_retry, task))
            time.sleep(self.rate_limit_delay)  # rate limiting

        completed: List[ScanTask] = []
        for future in futures:
            try:
                completed.append(future.result())
            except Exception as exc:
                logger.error("Unhandled future error: %s", exc)

        success_count = sum(1 for t in completed if t.success)
        logger.info(
            "Scheduler: %d/%d tasks succeeded", success_count, len(completed)
        )
        return completed


def make_scan_mode_config(mode: str, config: dict) -> dict:

    modes = config.get("scanner", {}).get("modes", {})
    mode_cfg = modes.get(mode, modes.get("fast", {}))
    return {
        "nmap_args": mode_cfg.get("nmap_args", "-T4 -F --open"),
        "top_ports": mode_cfg.get("top_ports", 100),
    }
