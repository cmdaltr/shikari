#!/bin/bash
# Download MITRE ATT&CK data to local cache
# This is useful for offline use or when GitHub is unreachable

# Get the script directory and find the project root
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PROJECT_ROOT="$( cd "$SCRIPT_DIR/.." && pwd )"
CACHE_DIR="$PROJECT_ROOT/archer/data/cache"
MITRE_URL="https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"
CACHE_FILE="$CACHE_DIR/enterprise-attack.json"

echo "Downloading MITRE ATT&CK Enterprise data..."
echo "URL: $MITRE_URL"
echo "Cache location: $CACHE_FILE"
echo ""

# Create cache directory if it doesn't exist
mkdir -p "$CACHE_DIR"

# Download the file
if curl -L -o "$CACHE_FILE" "$MITRE_URL"; then
    echo ""
    echo "✓ Successfully downloaded MITRE ATT&CK data"
    echo "  File size: $(ls -lh "$CACHE_FILE" | awk '{print $5}')"
    echo "  Location: $CACHE_FILE"
    echo ""
    echo "The Archer app will now use this cached data for the next 7 days."
else
    echo ""
    echo "✗ Failed to download MITRE ATT&CK data"
    echo "  Please check your internet connection and try again."
    exit 1
fi
