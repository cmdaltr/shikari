#!/bin/bash
#
# Quick Start Script for Fidelity Enhancement System
#
# This script automates the setup of the RAG-based fidelity enhancement system.
#
# Usage:
#   ./scripts/quickstart_fidelity_system.sh
#
# Or step-by-step:
#   ./scripts/quickstart_fidelity_system.sh --step 1  # Only run step 1
#

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_step() {
    echo -e "${BLUE}===================================================================${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}===================================================================${NC}"
    echo ""
}

print_success() {
    echo -e "${GREEN}✓ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠ $1${NC}"
}

print_error() {
    echo -e "${RED}✗ $1${NC}"
}

# Check if running from archer directory
if [ ! -f "archer.py" ]; then
    print_error "Please run this script from the archer project root directory"
    exit 1
fi

# Parse arguments
STEP=""
if [ "$1" == "--step" ] && [ -n "$2" ]; then
    STEP=$2
fi

# Step 1: Check dependencies
if [ -z "$STEP" ] || [ "$STEP" == "1" ]; then
    print_step "Step 1: Checking Dependencies"

    # Check Python
    if ! command -v python3 &> /dev/null; then
        print_error "Python 3 is not installed"
        exit 1
    fi
    print_success "Python 3 found: $(python3 --version)"

    # Check if in virtual environment (recommended)
    if [ -z "$VIRTUAL_ENV" ]; then
        print_warning "Not in a virtual environment. Consider creating one:"
        echo "  python3 -m venv venv"
        echo "  source venv/bin/activate"
        echo ""
    fi

    # Install dependencies
    print_step "Installing Python dependencies..."
    pip install -q sentence-transformers==2.2.2 faiss-cpu==1.7.4 pyyaml==6.0.1

    print_success "Dependencies installed"
    echo ""

    if [ -n "$STEP" ]; then
        print_success "Step 1 complete!"
        exit 0
    fi
fi

# Step 2: Setup knowledge base structure
if [ -z "$STEP" ] || [ "$STEP" == "2" ]; then
    print_step "Step 2: Setting Up Knowledge Base Structure"

    python3 scripts/setup_knowledge_base.py

    print_success "Knowledge base structure created"
    echo ""

    if [ -n "$STEP" ]; then
        print_success "Step 2 complete!"
        exit 0
    fi
fi

# Step 3: Clone community repositories
if [ -z "$STEP" ] || [ "$STEP" == "3" ]; then
    print_step "Step 3: Cloning Community Detection Repositories"

    cd data/external

    # Clone Sigma if not exists
    if [ ! -d "sigma" ]; then
        echo "Cloning Sigma rules (this may take a few minutes)..."
        git clone --depth 1 https://github.com/SigmaHQ/sigma.git
        print_success "Sigma repository cloned"
    else
        print_warning "Sigma repository already exists, skipping clone"
    fi

    # Optional: Clone other repos
    # Uncomment to enable

    # if [ ! -d "security_content" ]; then
    #     echo "Cloning Splunk Security Content..."
    #     git clone --depth 1 https://github.com/splunk/security_content.git
    # fi

    # if [ ! -d "detection-rules" ]; then
    #     echo "Cloning Elastic Detection Rules..."
    #     git clone --depth 1 https://github.com/elastic/detection-rules.git
    # fi

    cd ../..
    echo ""

    if [ -n "$STEP" ]; then
        print_success "Step 3 complete!"
        exit 0
    fi
fi

# Step 4: Import community rules
if [ -z "$STEP" ] || [ "$STEP" == "4" ]; then
    print_step "Step 4: Importing Community Detection Rules"

    echo "Importing Sigma rules (this will take 5-10 minutes)..."
    python3 scripts/import_community_rules.py --source sigma --min-level medium

    print_success "Community rules imported"
    echo ""

    if [ -n "$STEP" ]; then
        print_success "Step 4 complete!"
        exit 0
    fi
fi

# Step 5: Build vector embeddings
if [ -z "$STEP" ] || [ "$STEP" == "5" ]; then
    print_step "Step 5: Building Vector Embeddings"

    echo "Generating embeddings (this will take 7-10 minutes)..."
    python3 scripts/build_embeddings.py

    print_success "Vector embeddings built"
    echo ""

    if [ -n "$STEP" ]; then
        print_success "Step 5 complete!"
        exit 0
    fi
fi

# Step 6: Test the system
if [ -z "$STEP" ] || [ "$STEP" == "6" ]; then
    print_step "Step 6: Testing the System"

    echo "Testing retrieval for T1003.001 (LSASS Memory Dump)..."
    python3 scripts/test_retrieval.py --technique T1003.001 --platform Splunk --top-k 3

    print_success "System test complete"
    echo ""

    if [ -n "$STEP" ]; then
        print_success "Step 6 complete!"
        exit 0
    fi
fi

# All done!
print_step "Setup Complete!"

echo -e "${GREEN}✓ Fidelity Enhancement System is ready!${NC}"
echo ""
echo "Next steps:"
echo "  1. Set up LLM provider (optional):"
echo "     export OPENAI_API_KEY='your-key-here'"
echo ""
echo "  2. Test enhancement:"
echo "     python scripts/test_retrieval.py --technique T1003.001 --show-query"
echo ""
echo "  3. Generate enhanced detections:"
echo "     python archer.py generate APT29"
echo ""
echo "  4. Read the documentation:"
echo "     cat FIDELITY_IMPLEMENTATION_GUIDE.md"
echo "     cat FIDELITY_SYSTEM_SUMMARY.md"
echo ""
print_success "Happy hunting!"
