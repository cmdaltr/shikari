# 🧪 Progress Bar Testing Guide


---

## 📋 Overview

This guide explains how to test the progress bar fixes using the command-line test script, which simulates both command-line and browser behavior.


---

## ⚡ Quick Start

```bash
# Activate virtual environment
source .venv/bin/activate

# Run test with browser simulation (default)
python3 test_progress_fix.py

# Run command-line only test
python3 test_progress_fix.py --no-browser-sim

# Test a different group
python3 test_progress_fix.py --group "APT29"
```bash


---

## 📌 Test Modes

### 📌 Browser Simulation Mode (Default)

This mode simulates the complete browser workflow:

1. **Process Start**: `process_group()` runs with `run_correlation=True`
2. **YAML Generation**: Creates detection YAML files
3. **YAML Complete**: When progress reaches 100%...
4. **Frontend Call**: Simulates browser calling `/complete_yaml` endpoint
5. **Correlation Start**: `generate_correlations()` begins processing
6. **Progress Monitoring**: Tracks progress for backwards jumps

**What It Tests**:
- ✅ Command-line flow
- ✅ Browser `/complete_yaml` endpoint behavior
- ✅ Frontend interference prevention (commit e46db88)
- ✅ Thread-safe locking (commit cc0cb52)
- ✅ Progress monotonicity
- ✅ No reset at 70% or any other point

**Expected Output**:
```bash
[BROWSER SIMULATION] Frontend detected YAML complete, calling /complete_yaml
[BROWSER SIMULATION] Current status: genai_processing
[BROWSER SIMULATION] Status is 'genai_processing' - skipping (correlation already active)
```bash

This confirms the `/complete_yaml` endpoint is **not interfering** with active processing.

### 📌 Command-Line Only Mode

Use `--no-browser-sim` to test without frontend simulation:

```bash
python3 test_progress_fix.py --no-browser-sim
```bash

This tests the basic orchestrator → generate_correlations flow without the `/complete_yaml` call.

**What It Tests**:
- ✅ Basic command-line flow
- ✅ Thread-safe locking
- ✅ Progress monotonicity
- ❌ Does NOT test frontend interference prevention


---

## 📌 Understanding Test Output

### 📌 Progress Display

```bash
YAML Generation: [████████████████████░░░░░░] 80% (29/36)
Vendor Correlation: [██████████░░░░░░░░░░░░░░░] 40% (5965/14913)
```bash

### 📌 Status Changes

```bash
[3.7s] Status: started
[8.5s] Status: creating_yamls
[45.2s] Status: genai_starting
[45.5s] Status: genai_processing
[180.3s] Status: genai_complete
```bash

### 📌 Backwards Jump Detection

If a backwards jump is detected, you'll see:

```bash
⚠️  WARNING: Progress went BACKWARDS: 70% → 50%
    This indicates duplicate processing or race condition!
```bash

### 📌 Success Message

```bash
✅ TEST PASSED: No backwards jumps detected!
✅ Browser simulation: /complete_yaml handled correctly
   (Did not interfere with active correlation processing)
```bash


---

## 📌 What Each Test Verifies

### 📌 1. Thread-Safe Locking (commit cc0cb52)

**Fix**: Only one thread can process correlations at a time.

**Test**: If duplicate `generate_correlations()` is called, you'll see:
```bash
GenAI: Correlation generation already in progress for 'Scattered Spider', skipping duplicate call
```bash

**Prevents**: Multiple threads writing conflicting progress values.

### 📌 2. Frontend Interference Prevention (commit e46db88)

**Fix**: `/complete_yaml` skips if status is `"genai_processing"`.

**Test**: Browser simulation calls endpoint and verifies it skips:
```bash
[BROWSER SIMULATION] Status is 'genai_processing' - skipping (correlation already active)
```bash

**Prevents**: Frontend changing status while correlation is at 70%, causing reset.

### 📌 3. Progress Monotonicity (commit e1c8e60)

**Fix**: Count all evaluated pairs, not just kept ones.

**Test**: Progress values are collected and analyzed:
```bash
Progress sequence: 0 → 5 → 10 → 15 → 20 → ... → 100
```bash

**Prevents**: Mismatched counts causing progress calculation errors.

### 📌 4. Atomic File Operations (commit b812432)

**Fix**: File locking with read-merge-write.

**Test**: Multiple writes from orchestrator and engine don't conflict.

**Prevents**: Race conditions overwriting progress fields.


---

## 🔧 Troubleshooting

### 📌 Test Fails with "backwards jumps detected"

**Symptom**:
```bash
❌ TEST FAILED: Detected 3 backwards jumps in progress!
   Progress sequence: 0 → 5 → 15 → 8 → 10 → 15...
```bash

**Possible Causes**:
1. Missing commit e46db88 (frontend interference)
2. Missing commit cc0cb52 (thread-safe locking)
3. Missing commit e1c8e60 (count all pairs)

**Solution**: Verify all commits are applied with `git log --oneline`

### 📌 Test Times Out

**Symptom**:
```bash
⚠️  Timeout after 600s
```bash

**Possible Causes**:
1. Very large group with many techniques
2. System resource constraints

**Solution**: Reduce group size or increase timeout in script

### 📌 Browser Simulation Changes Status

**Symptom**:
```bash
[BROWSER SIMULATION] Status not in GenAI phase, would start background thread
[BROWSER SIMULATION] Changed status to 'genai_starting'
```bash

**Problem**: This means the fix is NOT working. Status should be `"genai_processing"` by the time `/complete_yaml` is called.

**Solution**: Verify commit e46db88 is applied and includes `"genai_processing"` in the excluded statuses list.


---

## 📌 Running Tests in CI/CD

For automated testing, use:

```bash
#!/bin/bash
set -e

source .venv/bin/activate

# Run both modes
echo "Testing command-line mode..."
python3 test_progress_fix.py --no-browser-sim

echo "Testing browser simulation mode..."
python3 test_progress_fix.py

echo "All tests passed!"
```bash


---

## 📌 Files Modified

### 📌 Core Fixes
- `archer/genai/engine.py` - Thread-safe locking, count all pairs
- `archer/build/progress.py` - Atomic file operations
- `archer/app.py` - Frontend interference prevention

### 📌 Test Files
- `test_progress_fix.py` - Main test script with browser simulation
- `TEST_RESULTS.md` - Comprehensive test results documentation
- `TESTING_GUIDE.md` - This guide


---

## 📌 Summary

The test script now comprehensively tests all four fixes:

1. ✅ **Atomic file locking** (b812432) - Race condition prevention
2. ✅ **Count all pairs** (e1c8e60) - Progress calculation accuracy
3. ✅ **Thread-safe locking** (cc0cb52) - Duplicate processing prevention
4. ✅ **Frontend interference** (e46db88) - Browser `/complete_yaml` handling

This ensures the progress bar works correctly in **both** command-line and browser environments, with smooth monotonic progress from 0% to 100% and no resets.
