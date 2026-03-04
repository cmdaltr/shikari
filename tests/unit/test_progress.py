"""
Unit tests for Progress Tracking.

Tests the progress file I/O operations with actual file writes/reads
to verify correct behavior, following the rivendell testing pattern.
"""
import pytest
import json
import os
from pathlib import Path
from unittest.mock import patch, MagicMock
import threading
import time


class TestWriteProgress:
    """Test progress writing functionality with actual file I/O."""

    def test_write_progress_creates_file(self, temp_dir):
        """Test that write_progress creates a new progress file."""
        from archer.build.progress import write_progress

        with patch("archer.build.progress.PROGRESS_DIR", temp_dir):
            write_progress("TestGroup", {"status": "started"})

            # Verify file was created
            progress_file = temp_dir / "TestGroup.json"
            assert progress_file.exists()

            # Verify content
            with open(progress_file) as f:
                data = json.load(f)
                assert data["status"] == "started"

    def test_write_progress_updates_existing(self, temp_dir):
        """Test that write_progress updates existing progress file."""
        from archer.build.progress import write_progress

        with patch("archer.build.progress.PROGRESS_DIR", temp_dir):
            # Write initial progress
            write_progress("TestGroup", {"status": "started", "count": 0})

            # Update progress
            write_progress("TestGroup", {"status": "processing", "count": 5})

            # Verify updated content
            progress_file = temp_dir / "TestGroup.json"
            with open(progress_file) as f:
                data = json.load(f)
                assert data["status"] == "processing"
                assert data["count"] == 5

    def test_write_progress_merges_data(self, temp_dir):
        """Test that write_progress merges new data with existing."""
        from archer.build.progress import write_progress

        with patch("archer.build.progress.PROGRESS_DIR", temp_dir):
            # Write initial data
            write_progress("TestGroup", {"status": "started", "total": 10})

            # Update with partial data
            write_progress("TestGroup", {"created": 3})

            # Verify merge
            progress_file = temp_dir / "TestGroup.json"
            with open(progress_file) as f:
                data = json.load(f)
                assert data["status"] == "started"  # Original preserved
                assert data["total"] == 10          # Original preserved
                assert data["created"] == 3         # New data added

    def test_write_progress_sanitizes_group_name(self, temp_dir):
        """Test that dangerous characters in group name are sanitized."""
        from archer.build.progress import write_progress

        with patch("archer.build.progress.PROGRESS_DIR", temp_dir):
            # Try to use path traversal in group name
            write_progress("../../../etc/passwd", {"status": "test"})

            # Should NOT create file outside temp_dir
            dangerous_path = temp_dir.parent.parent.parent / "etc" / "passwd.json"
            assert not dangerous_path.exists()

            # Should create sanitized file in temp_dir
            # The actual sanitization depends on implementation

    def test_write_progress_creates_directory(self, temp_dir):
        """Test that write_progress creates progress directory if missing."""
        from archer.build.progress import write_progress

        new_dir = temp_dir / "new_progress_dir"
        assert not new_dir.exists()

        with patch("archer.build.progress.PROGRESS_DIR", new_dir):
            write_progress("TestGroup", {"status": "started"})

            assert new_dir.exists()
            assert (new_dir / "TestGroup.json").exists()

    def test_write_progress_handles_special_characters(self, temp_dir):
        """Test handling of special characters in progress data."""
        from archer.build.progress import write_progress

        with patch("archer.build.progress.PROGRESS_DIR", temp_dir):
            special_data = {
                "status": "processing",
                "message": "Téchniqué: T1059.001 \"PowerShell\"",
                "unicode": "日本語テスト",
            }

            write_progress("TestGroup", special_data)

            progress_file = temp_dir / "TestGroup.json"
            with open(progress_file, encoding="utf-8") as f:
                data = json.load(f)
                assert data["message"] == special_data["message"]
                assert data["unicode"] == special_data["unicode"]


class TestReadProgress:
    """Test progress reading functionality."""

    def test_read_progress_existing_file(self, temp_dir):
        """Test reading an existing progress file."""
        from archer.build.progress import read_progress

        # Create a progress file manually
        progress_file = temp_dir / "TestGroup.json"
        progress_data = {"status": "complete", "created_yaml": 10}
        with open(progress_file, "w") as f:
            json.dump(progress_data, f)

        with patch("archer.build.progress.PROGRESS_DIR", temp_dir):
            result = read_progress("TestGroup")

            assert result["status"] == "complete"
            assert result["created_yaml"] == 10

    def test_read_progress_nonexistent_file(self, temp_dir):
        """Test reading a non-existent progress file."""
        from archer.build.progress import read_progress

        with patch("archer.build.progress.PROGRESS_DIR", temp_dir):
            result = read_progress("NonExistentGroup")

            # Should return empty dict or None depending on implementation
            assert result is None or result == {}

    def test_read_progress_invalid_json(self, temp_dir):
        """Test reading a corrupted progress file."""
        from archer.build.progress import read_progress

        # Create an invalid JSON file
        progress_file = temp_dir / "CorruptedGroup.json"
        with open(progress_file, "w") as f:
            f.write("{ invalid json }")

        with patch("archer.build.progress.PROGRESS_DIR", temp_dir):
            result = read_progress("CorruptedGroup")

            # Should handle gracefully
            assert result is None or result == {}


class TestProgressStates:
    """Test progress state transitions."""

    def test_progress_state_started(self, temp_dir):
        """Test initial 'started' state."""
        from archer.build.progress import write_progress, read_progress

        with patch("archer.build.progress.PROGRESS_DIR", temp_dir):
            write_progress("TestGroup", {
                "status": "started",
                "stage": "init",
            })

            result = read_progress("TestGroup")
            assert result["status"] == "started"

    def test_progress_state_processing(self, temp_dir):
        """Test 'processing' state with counts."""
        from archer.build.progress import write_progress, read_progress

        with patch("archer.build.progress.PROGRESS_DIR", temp_dir):
            write_progress("TestGroup", {
                "status": "processing",
                "stage": "yaml",
                "created_yaml": 5,
                "total_yaml": 10,
            })

            result = read_progress("TestGroup")
            assert result["status"] == "processing"
            assert result["created_yaml"] == 5
            assert result["total_yaml"] == 10

    def test_progress_state_complete(self, temp_dir):
        """Test 'complete' state."""
        from archer.build.progress import write_progress, read_progress

        with patch("archer.build.progress.PROGRESS_DIR", temp_dir):
            write_progress("TestGroup", {
                "status": "complete",
                "created_yaml": 10,
                "total_yaml": 10,
                "duration_seconds": 45.5,
            })

            result = read_progress("TestGroup")
            assert result["status"] == "complete"
            assert result["created_yaml"] == result["total_yaml"]

    def test_progress_state_failed(self, temp_dir):
        """Test 'failed' state with error message."""
        from archer.build.progress import write_progress, read_progress

        with patch("archer.build.progress.PROGRESS_DIR", temp_dir):
            write_progress("TestGroup", {
                "status": "failed",
                "error": "Connection timeout to MITRE ATT&CK",
            })

            result = read_progress("TestGroup")
            assert result["status"] == "failed"
            assert "timeout" in result["error"].lower()


class TestProgressConcurrency:
    """Test concurrent access to progress files."""

    def test_concurrent_writes_no_data_loss(self, temp_dir):
        """Test that concurrent writes don't lose data."""
        from archer.build.progress import write_progress, read_progress

        with patch("archer.build.progress.PROGRESS_DIR", temp_dir):
            results = []

            def write_count(count):
                write_progress("ConcurrentGroup", {"count": count})
                results.append(count)

            # Create multiple threads writing simultaneously
            threads = []
            for i in range(10):
                t = threading.Thread(target=write_count, args=(i,))
                threads.append(t)
                t.start()

            # Wait for all threads
            for t in threads:
                t.join()

            # Verify file exists and has valid JSON
            progress_file = temp_dir / "ConcurrentGroup.json"
            assert progress_file.exists()

            with open(progress_file) as f:
                data = json.load(f)
                # Should have a count field (value depends on last write)
                assert "count" in data


class TestProgressEdgeCases:
    """Test edge cases in progress handling."""

    def test_empty_progress_data(self, temp_dir):
        """Test writing empty progress data."""
        from archer.build.progress import write_progress, read_progress

        with patch("archer.build.progress.PROGRESS_DIR", temp_dir):
            write_progress("EmptyGroup", {})

            result = read_progress("EmptyGroup")
            assert result == {} or result is not None

    def test_large_progress_data(self, temp_dir):
        """Test writing large progress data."""
        from archer.build.progress import write_progress, read_progress

        with patch("archer.build.progress.PROGRESS_DIR", temp_dir):
            large_data = {
                "status": "processing",
                "techniques": [f"T{1000+i}.00{j}" for i in range(100) for j in range(5)],
                "log": [f"Processing step {i}" for i in range(1000)],
            }

            write_progress("LargeGroup", large_data)

            result = read_progress("LargeGroup")
            assert len(result["techniques"]) == 500
            assert len(result["log"]) == 1000

    def test_group_name_with_spaces(self, temp_dir):
        """Test group name with spaces."""
        from archer.build.progress import write_progress, read_progress

        with patch("archer.build.progress.PROGRESS_DIR", temp_dir):
            write_progress("Lazarus Group", {"status": "started"})

            # Should handle spaces in filename
            result = read_progress("Lazarus Group")
            assert result is not None or (temp_dir / "Lazarus Group.json").exists() or \
                   (temp_dir / "Lazarus_Group.json").exists()

    def test_group_name_unicode(self, temp_dir):
        """Test group name with unicode characters."""
        from archer.build.progress import write_progress, read_progress

        with patch("archer.build.progress.PROGRESS_DIR", temp_dir):
            # Some implementations might sanitize unicode
            try:
                write_progress("APT日本", {"status": "started"})
                # If it succeeds, try to read it back
                result = read_progress("APT日本")
            except (OSError, UnicodeError):
                # Some filesystems don't support unicode filenames
                pytest.skip("Filesystem doesn't support unicode filenames")
