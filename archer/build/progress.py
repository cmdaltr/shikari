import os
import json
import fcntl
import time
from typing import Dict, Any
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
            lock_file = open(lock_path, 'w')
            try:
                # Acquire exclusive lock (blocks if another process holds it)
                fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)

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

                # DEBUG LOGGING: Track what's being written
                if "processed" in data or "processed" in existing:
                    old_processed = existing.get("processed", 0)
                    new_processed = merged.get("processed", 0)
                    old_status = existing.get("status", "none")
                    new_status = merged.get("status", "none")

                    # Log if progress goes backwards
                    if old_processed > 0 and new_processed < old_processed:
                        caller_info = "".join(traceback.format_stack()[-3:-1])
                        print(f"\n⚠️  PROGRESS WENT BACKWARDS!")
                        print(f"   Old: processed={old_processed}, status={old_status}")
                        print(f"   New: processed={new_processed}, status={new_status}")
                        print(f"   Data being written: {data}")
                        print(f"   Existing data: {existing}")
                        print(f"   Called from:\n{caller_info}")

                    # Log if processed field disappears
                    if old_processed > 0 and "processed" not in data:
                        caller_info = "".join(traceback.format_stack()[-3:-1])
                        print(f"\n⚠️  'PROCESSED' FIELD NOT IN NEW DATA!")
                        print(f"   Old processed: {old_processed}")
                        print(f"   Data being written: {data}")
                        print(f"   This will preserve old value: {new_processed}")
                        print(f"   Called from:\n{caller_info}")

                    # Log status changes during processing
                    if old_status == "genai_processing" and new_status != "genai_processing" and new_status != "genai_complete":
                        caller_info = "".join(traceback.format_stack()[-3:-1])
                        print(f"\n⚠️  STATUS CHANGED DURING PROCESSING!")
                        print(f"   Old status: {old_status}, processed={old_processed}")
                        print(f"   New status: {new_status}, processed={new_processed}")
                        print(f"   Data being written: {data}")
                        print(f"   Called from:\n{caller_info}")

                # Write merged data atomically
                temp_path = path + ".tmp"
                with open(temp_path, "w", encoding="utf-8") as fh:
                    json.dump(merged, fh, indent=2)

                # Atomic replace
                os.replace(temp_path, path)

                # Success - release lock and return
                fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)
                return

            finally:
                lock_file.close()

        except (IOError, OSError) as e:
            # Lock acquisition failed, retry
            if attempt < max_retries - 1:
                time.sleep(retry_delay)
            else:
                # Last attempt failed, give up
                pass
        except Exception:
            # Other error, give up
            pass


def read_progress(group_name: str) -> Dict[str, Any]:
    path = progress_path(group_name)
    if not os.path.exists(path):
        return {}
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except Exception:
        return {}
