#!/bin/bash

echo "======================================"
echo "   ARCHER CLEAN START SCRIPT"
echo "======================================"
echo ""
echo "This script will:"
echo "  1. Kill all running Python/uvicorn processes"
echo "  2. Clear Python cache (__pycache__ and .pyc files)"
echo "  3. Start a fresh Archer server on port 8000"
echo ""
echo "WARNING: This will stop ALL Python processes!"
echo ""
read -p "Do you want to continue? (y/N): " -n 1 -r
echo ""

if [[ ! $REPLY =~ ^[Yy]$ ]]
then
    echo "Aborted."
    exit 1
fi

echo ""
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
