#!/bin/bash

echo "================================================"
echo "  ARCHER ULTRA CLEAN START"
echo "  Aggressively killing ALL interfering processes"
echo "================================================"
echo ""

# 1. Kill ALL Python processes (includes all uvicorn servers)
echo "[1/8] Killing ALL Python processes..."
killall -9 python3 2>/dev/null
killall -9 python 2>/dev/null
killall -9 Python 2>/dev/null
sleep 2

# 2. Kill processes by name pattern (uvicorn, archer)
echo "[2/8] Killing processes matching 'uvicorn' and 'archer'..."
pkill -9 -f "uvicorn.*archer" 2>/dev/null
pkill -9 -f "python.*archer" 2>/dev/null
sleep 1

# 3. Force kill processes on ports 8000-8010
echo "[3/8] Force killing processes on ports 8000-8010..."
for port in {8000..8010}; do
    pids=$(lsof -ti:$port 2>/dev/null)
    if [ ! -z "$pids" ]; then
        echo "  Killing processes on port $port: $pids"
        echo "$pids" | xargs kill -9 2>/dev/null
    fi
done
sleep 2

# 4. Verify all ports are free
echo "[4/8] Verifying all ports 8000-8010 are free..."
ports_in_use=0
for port in {8000..8010}; do
    if lsof -ti:$port >/dev/null 2>&1; then
        echo "  ⚠️  WARNING: Port $port still in use!"
        ports_in_use=1
        lsof -ti:$port | xargs kill -9 2>/dev/null
    fi
done

if [ $ports_in_use -eq 0 ]; then
    echo "  ✅ All ports are free"
else
    echo "  ⚠️  Some ports were stubborn, waiting 3 more seconds..."
    sleep 3
fi

# 5. Clear Python bytecode cache
echo "[5/8] Clearing Python bytecode cache..."
find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null
find . -type f -name "*.pyc" -delete 2>/dev/null
echo "  ✅ Cache cleared"

# 6. Clear CVE progress files
echo "[6/8] Clearing CVE progress files..."
rm -f data/progress/CVE-*.json* 2>/dev/null
echo "  ✅ Progress files cleared"

# 7. Check for any remaining Python processes
echo "[7/8] Final check for remaining Python processes..."
remaining=$(ps aux | grep -i "python.*archer\|uvicorn" | grep -v grep | wc -l)
if [ $remaining -gt 0 ]; then
    echo "  ⚠️  Found $remaining remaining processes, force killing..."
    ps aux | grep -i "python.*archer\|uvicorn" | grep -v grep | awk '{print $2}' | xargs kill -9 2>/dev/null
    sleep 2
else
    echo "  ✅ No remaining processes"
fi

# 8. Start fresh server
echo "[8/8] Starting fresh server on port 8000..."
echo ""
echo "================================================"
echo "  🚀 CLEAN SERVER STARTING..."
echo "  Port: 8000"
echo "  Press Ctrl+C to stop"
echo "================================================"
echo ""

# Activate venv and start server
source .venv/bin/activate && python3 -m uvicorn archer.app:app --host 127.0.0.1 --port 8000
