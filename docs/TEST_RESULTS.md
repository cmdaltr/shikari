# Progress Bar Fix - Test Results

## Test Date
October 14, 2025

## Problem Summary
Progress bar for Sole-vendor correlation was jumping backwards during processing:
- Pattern observed: `0 → 5 → 15 → 8 → 10 → 15 → 20 → 15 → 20 → 25...`
- Progress would increase, then decrease, then catch up again
- This indicated multiple processes writing conflicting progress values

## Root Cause Identified
The `generate_correlations()` function was being called **twice simultaneously** from different code paths:

1. **Direct call**: `orchestrator.py:145` → `generate_correlations()`
2. **Background thread**: `app.py:686,786` → `process_genai()` → `generate_correlations()`

Each call had its own local `cumulative_count` variable, causing:
- Thread A at iteration 50: writes `processed=50`
- Thread B at iteration 40: writes `processed=40` (overwrites A)
- Result: Progress jumps backwards from 50% to 40%

## Fix Applied
Added thread-safe locking mechanism in `archer/genai/engine.py`:

```python
# Global lock dictionary per group
_CORRELATION_LOCKS: Dict[str, threading.Lock] = {}
_LOCKS_LOCK = threading.Lock()

def generate_correlations(group_name, yaml_dir, ...):
    # Get or create lock for this group
    with _LOCKS_LOCK:
        if group_name not in _CORRELATION_LOCKS:
            _CORRELATION_LOCKS[group_name] = threading.Lock()
        group_lock = _CORRELATION_LOCKS[group_name]

    # Try to acquire - if already held, exit immediately
    if not group_lock.acquire(blocking=False):
        print(f"GenAI: Correlation generation already in progress, skipping duplicate call")
        return {"vendor_correlations": [], "cross_vendor_correlations": []}

    try:
        # ... actual processing ...
    finally:
        group_lock.release()
```

## Test Results

### Test 1: Full Integration Test
**Command**: `python3 test_progress_fix.py`

**Results**:
- ✅ YAML Generation: 36/36 (100%)
- ✅ Vendor Correlation: 14913/14913 (100%)
- ✅ Status: complete
- ✅ Correlations Generated: 9979
- ✅ Both progress bars reached 100%
- ✅ No backwards jumps detected
- ✅ Process completed successfully

### Test 2: Duplicate Call Prevention
**Command**: Direct Python test with two threads calling `generate_correlations()`

**Results**:
- ✅ Thread 1: Started processing and generated correlations
- ✅ Thread 2: Detected lock, skipped processing (returned empty result)
- ✅ No race condition occurred
- ✅ Lock mechanism working correctly

### Test 3: Progress Monotonicity
**Analysis**: Terminal output from Test 1 showed:
```
GenAI: Evaluated 10 pairs total
GenAI: Evaluated 20 pairs total
GenAI: Evaluated 30 pairs total
...
GenAI: Evaluated 14913 pairs total
```

**Results**:
- ✅ Progress values always increased: 10 → 20 → 30 → ... → 14913
- ✅ No backwards jumps detected
- ✅ Monotonic progress confirmed

## Commits Applied

1. **e1c8e60**: Fix progress tracking to count all evaluated pairs, not just kept ones
   - Moved `cumulative_count` increment to top of loop
   - Ensures count matches total_pairs calculation

2. **cc0cb52**: Prevent duplicate correlation generation with thread-safe locking
   - Added global lock dictionary per group
   - Non-blocking lock acquisition with immediate exit if already held
   - Finally block ensures lock is always released

3. **e46db88**: Prevent /complete_yaml from interfering with active correlation processing
   - Added `"genai_processing"` to excluded statuses in `/complete_yaml` endpoint
   - Prevents frontend from changing status while correlation is actively running
   - Fixes the bug where progress reset at 70% when using browser

## Test Scripts Updated

The test script `test_progress_fix.py` has been enhanced to include:

**Browser Simulation Mode** (default):
- Simulates the frontend calling `/complete_yaml` when YAML reaches 100%
- Tests that this call doesn't interfere with active correlation processing
- Verifies the fix from commit e46db88

**Command-Line Only Mode**:
- Use `--no-browser-sim` flag to test without frontend simulation
- Tests the basic command-line flow

**Usage**:
```bash
# Test with browser simulation (default)
python3 test_progress_fix.py

# Test command-line only
python3 test_progress_fix.py --no-browser-sim

# Test a different group
python3 test_progress_fix.py --group "APT29"
```

## Expected Behavior in Production

When running Scattered Spider (or any group) with correlation enabled:

1. **First call** (from orchestrator or background thread):
   - Acquires lock
   - Processes all correlations
   - Progress smoothly increases: 0% → 10% → 20% → ... → 100%
   - Releases lock

2. **Second call** (from alternate code path):
   - Attempts to acquire lock
   - Finds lock already held
   - Prints: "GenAI: Correlation generation already in progress for 'Scattered Spider', skipping duplicate call"
   - Returns immediately with empty results
   - No duplicate processing occurs

3. **Progress Bar Display**:
   - Detection Generation: Smooth progress to 100%
   - Sole-vendor Correlation: Smooth progress to 100% (no resets, no backwards jumps)
   - Both bars complete successfully

## Verification Steps

To verify the fix in your environment:

1. **Check terminal output** for the message:
   ```
   GenAI: Correlation generation already in progress for 'X', skipping duplicate call
   ```

2. **Watch the progress bar** - it should:
   - Start at 0%
   - Increase monotonically (never decrease)
   - Reach exactly 100%
   - Never reset or jump backwards

3. **Check final progress file**:
   ```bash
   cat "data/progress/Scattered Spider.json" | python3 -m json.tool
   ```

   Should show:
   ```json
   {
     "status": "complete",
     "processed": 14913,
     "total_pairs": 14913,
     "vendor_count": 9979
   }
   ```

## Conclusion

✅ **All tests passed successfully**

The fix correctly prevents duplicate correlation generation by using thread-safe locking at the function level. Only one thread can process correlations for a given group at a time, eliminating the race condition that caused backwards jumps in progress.

The progress bar now displays smooth, monotonic progress from 0% to 100% with no resets or backwards jumps.
