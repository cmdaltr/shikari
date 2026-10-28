import os
import json
import time
from typing import Dict, Any
from .. import filelock
from ..config import PROGRESS_DIR


def ensure_progress_dir():
    os.makedirs(PROGRESS_DIR, exist_ok=True)


def progress_path(group_name: str) -> str:
    ensure_progress_dir()
    safe = group_name.replace("/", "_")
    return os.path.join(PROGRESS_DIR, f"{safe}.json")


def write_progress(group_name: str, data: Dict[str, Any]):
    """
    Write progress data with atomic read-merge-write using file locking.
    This prevents race conditions where different parts of the code
    update different fields and overwrite each other.
    """
    import traceback

    path = progress_path(group_name)
    lock_path = path + ".lock"

    max_retries = 10
    retry_delay = 0.05  # 50ms

    for attempt in range(max_retries):
        try:
            # Use lock file for synchronization
            lock_file = open(lock_path, 'a')
            try:
                # Acquire exclusive lock (blocks if another process holds it)
                filelock.lock(lock_file)

                # Read existing data
                existing = {}
                if os.path.exists(path):
                    try:
                        with open(path, "r", encoding="utf-8") as fh:
                            existing = json.load(fh)
                    except Exception:
                        existing = {}

                # Merge new data into existing (new data takes precedence)
                merged = {**existing, **data}
                # Stamp each phase's start, so the progress page can show real elapsed times
                phase = data.get("phase")
                if phase and phase != existing.get("phase"):
                    merged.setdefault("phase_started", {})
                    merged["phase_started"] = {**merged["phase_started"], phase: time.time()}

                # DEBUG LOGGING: Track what's being written
                if "processed" in data or "processed" in existing:
                    old_processed = existing.get("processed", 0)
                    new_processed = merged.get("processed", 0)
                    old_status = existing.get("status", "none")
                    new_status = merged.get("status", "none")

                    # Progress validation (silent - no logging needed)

                if phase == "complete" and existing.get("phase") != "complete":
                    _finish_run(group_name, merged.get("started_at"))
                terminal = ((phase == "complete" and existing.get("phase") != "complete")
                            or (merged.get("status") in FAILED and existing.get("status") not in FAILED))

                # Write merged data atomically
                temp_path = path + ".tmp"
                with open(temp_path, "w", encoding="utf-8") as fh:
                    json.dump(merged, fh, indent=2)

                # Atomic replace
                os.replace(temp_path, path)

                # Success - release lock and return
                filelock.unlock(lock_file)
                if terminal:
                    _notify(group_name, merged)
                return

            finally:
                lock_file.close()

        except (IOError, OSError) as e:
            # Lock acquisition failed, retry
            if attempt < max_retries - 1:
                time.sleep(retry_delay)
            else:
                # Last attempt failed, log and give up
                print(f"⚠️  Progress write failed after {max_retries} retries for '{group_name}': {e}")
        except Exception as e:
            # Other error, log and give up
            print(f"⚠️  Progress write error for '{group_name}': {e}")
            import traceback
            traceback.print_exc()


FAILED = ("error", "failed", "cancelled")


def _notify(group_name: str, progress: Dict[str, Any]):
    try:
        from archer import webhooks

        webhooks.emit_run(group_name, progress)
    except Exception as e:
        print(f"⚠️  Webhooks for '{group_name}' not sent: {e}")


def _finish_run(group_name: str, started_at):
    try:
        from .run_files import finish

        finish(group_name, started_at)
    except Exception as e:
        print(f"⚠️  Could not record the run's files for '{group_name}': {e}")


def start_progress(group_name: str, data: Dict[str, Any]):
    """
    Begin a run's progress record afresh.

    write_progress merges into the existing record, so a previous run's correlation
    counters would otherwise show on the next run's progress page. Call this before
    starting the run's background thread, so the thread's own updates land after it.
    """
    path = progress_path(group_name)
    lock_path = path + ".lock"
    now = time.time()
    record = {"status": "started", "phase": "preparing", "started_at": now,
              "phase_started": {"preparing": now}, **data}
    from .run_files import begin

    begin(group_name, regenerate=bool(data.get("regenerate")))
    with open(lock_path, "a") as lock_file:
        filelock.lock(lock_file)
        try:
            temp_path = path + ".tmp"
            with open(temp_path, "w", encoding="utf-8") as fh:
                json.dump(record, fh, indent=2)
            os.replace(temp_path, path)
        finally:
            filelock.unlock(lock_file)


def read_progress(group_name: str) -> Dict[str, Any]:
    path = progress_path(group_name)
    if not os.path.exists(path):
        return {}
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except Exception:
        return {}
