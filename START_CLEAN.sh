#!/bin/bash

echo "=== ARCHER CLEAN START ==="
echo "Killing all existing servers..."

# Kill all Python/uvicorn processes
killall -9 python3 2>/dev/null
pkill -9 -f uvicorn 2>/dev/null

# Wait for processes to die
sleep 3

# Clear Python cache
echo "Clearing Python cache..."
find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null
find . -type f -name "*.pyc" -delete 2>/dev/null

echo "Starting fresh server on port 8000..."
source .venv/bin/activate
python3 -m uvicorn archer.app:app --host 127.0.0.1 --port 8000 --reload

echo "Server started! Visit http://localhost:8000"
