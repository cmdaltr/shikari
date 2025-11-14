#!/bin/bash

# ==============================================================================
# Archer Local LLM Setup Script
# ==============================================================================
# This script automatically configures a local LLM (Ollama) based on available
# system resources. It will:
# 1. Detect or prompt for available RAM
# 2. Install Ollama (if needed)
# 3. Select and download the best model for your system
# 4. Configure Archer to use the local LLM
# 5. Start Ollama server
# ==============================================================================

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Print colored output
print_info() {
    echo -e "${BLUE}ℹ ${NC}$1"
}

print_success() {
    echo -e "${GREEN}✓${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}⚠${NC} $1"
}

print_error() {
    echo -e "${RED}✗${NC} $1"
}

print_header() {
    echo ""
    echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${BLUE}  $1${NC}"
    echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
    echo ""
}

# ==============================================================================
# Detect System Information
# ==============================================================================

detect_os() {
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        echo "linux"
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        echo "macos"
    elif [[ "$OSTYPE" == "msys" ]] || [[ "$OSTYPE" == "cygwin" ]]; then
        echo "windows"
    else
        echo "unknown"
    fi
}

detect_ram_gb() {
    local os=$(detect_os)

    if [[ "$os" == "linux" ]]; then
        # Linux: Use free command
        free -g | awk '/^Mem:/{print $2}'
    elif [[ "$os" == "macos" ]]; then
        # macOS: Use sysctl
        echo $(( $(sysctl -n hw.memsize) / 1024 / 1024 / 1024 ))
    else
        echo "0"
    fi
}

# ==============================================================================
# Model Selection Based on RAM
# ==============================================================================

select_model_for_ram() {
    local ram_gb=$1
    local model_name=""
    local model_size=""
    local recommended=""

    if (( ram_gb >= 64 )); then
        model_name="llama3.1:70b-instruct-q4_K_M"
        model_size="~40GB"
        recommended="Best Quality - Perfect for detection engineering"
    elif (( ram_gb >= 32 )); then
        model_name="qwen2.5:32b-instruct-q4_K_M"
        model_size="~20GB"
        recommended="Excellent Quality - Great for code/query generation"
    elif (( ram_gb >= 16 )); then
        model_name="llama3.1:8b-instruct-q4_K_M"
        model_size="~5GB"
        recommended="Good Quality - Balanced performance"
    elif (( ram_gb >= 8 )); then
        model_name="mistral:7b-instruct-q4_K_M"
        model_size="~4GB"
        recommended="Lightweight - Suitable for basic tasks"
    else
        model_name="phi3:mini"
        model_size="~2GB"
        recommended="Minimal - Very basic LLM capabilities"
    fi

    echo "$model_name|$model_size|$recommended"
}

# ==============================================================================
# Ollama Installation
# ==============================================================================

check_ollama_installed() {
    if command -v ollama &> /dev/null; then
        return 0  # Installed
    else
        return 1  # Not installed
    fi
}

install_ollama() {
    local os=$(detect_os)

    print_header "Installing Ollama"

    if [[ "$os" == "linux" ]] || [[ "$os" == "macos" ]]; then
        print_info "Downloading and installing Ollama..."
        curl -fsSL https://ollama.com/install.sh | sh
        print_success "Ollama installed successfully"
    else
        print_error "Automatic installation not supported on Windows"
        print_info "Please download Ollama from: https://ollama.com/download/windows"
        exit 1
    fi
}

# ==============================================================================
# Ollama Server Management
# ==============================================================================

check_ollama_running() {
    if curl -s http://localhost:11434/api/tags &> /dev/null; then
        return 0  # Running
    else
        return 1  # Not running
    fi
}

start_ollama_server() {
    print_info "Starting Ollama server..."

    # Start in background
    nohup ollama serve > /tmp/ollama.log 2>&1 &

    # Wait for server to start (max 10 seconds)
    local max_attempts=10
    local attempt=0

    while ! check_ollama_running && (( attempt < max_attempts )); do
        sleep 1
        ((attempt++))
    done

    if check_ollama_running; then
        print_success "Ollama server started successfully"
    else
        print_error "Failed to start Ollama server"
        print_info "Check logs at: /tmp/ollama.log"
        exit 1
    fi
}

# ==============================================================================
# Model Download and Configuration
# ==============================================================================

download_model() {
    local model_name=$1

    print_header "Downloading Model: $model_name"
    print_info "This may take several minutes depending on your internet connection..."

    if ollama pull "$model_name"; then
        print_success "Model downloaded successfully"
    else
        print_error "Failed to download model"
        exit 1
    fi
}

configure_archer() {
    local model_name=$1

    print_header "Configuring Archer"

    # Create or update .env file
    local env_file=".env"

    if [[ ! -f "$env_file" ]]; then
        if [[ -f ".env.example" ]]; then
            cp .env.example .env
            print_info "Created .env from .env.example"
        else
            touch .env
            print_info "Created new .env file"
        fi
    fi

    # Update or add LLM configuration
    if grep -q "^LLM_PROVIDER=" "$env_file"; then
        sed -i.bak "s/^LLM_PROVIDER=.*/LLM_PROVIDER=ollama/" "$env_file"
    else
        echo "LLM_PROVIDER=ollama" >> "$env_file"
    fi

    if grep -q "^LLM_MODEL=" "$env_file"; then
        sed -i.bak "s/^LLM_MODEL=.*/LLM_MODEL=$model_name/" "$env_file"
    else
        echo "LLM_MODEL=$model_name" >> "$env_file"
    fi

    if grep -q "^OLLAMA_BASE_URL=" "$env_file"; then
        sed -i.bak "s|^OLLAMA_BASE_URL=.*|OLLAMA_BASE_URL=http://localhost:11434|" "$env_file"
    else
        echo "OLLAMA_BASE_URL=http://localhost:11434" >> "$env_file"
    fi

    # Remove backup file
    rm -f .env.bak

    print_success "Archer configured to use local LLM"
}

# ==============================================================================
# Docker Compose Configuration
# ==============================================================================

configure_docker_compose() {
    local model_name=$1

    if [[ ! -f "docker-compose.yml" ]]; then
        print_warning "docker-compose.yml not found, skipping Docker configuration"
        return
    fi

    print_info "Updating docker-compose.yml for local LLM..."

    # Check if environment section exists
    if grep -q "environment:" docker-compose.yml; then
        # Add/update LLM variables
        if ! grep -q "LLM_PROVIDER" docker-compose.yml; then
            sed -i.bak "/environment:/a\\
      - LLM_PROVIDER=ollama\\
      - LLM_MODEL=$model_name\\
      - OLLAMA_BASE_URL=http://host.docker.internal:11434
" docker-compose.yml
            rm -f docker-compose.yml.bak
            print_success "Docker Compose configured"
        else
            print_info "Docker Compose already has LLM configuration"
        fi
    fi
}

# ==============================================================================
# Verification
# ==============================================================================

verify_setup() {
    local model_name=$1

    print_header "Verifying Setup"

    # Check Ollama is running
    if check_ollama_running; then
        print_success "Ollama server is running"
    else
        print_error "Ollama server is not running"
        return 1
    fi

    # Check model is available
    if ollama list | grep -q "$model_name"; then
        print_success "Model '$model_name' is available"
    else
        print_error "Model '$model_name' not found"
        return 1
    fi

    # Test model
    print_info "Testing model (this may take a few seconds)..."
    local test_response=$(ollama run "$model_name" "Say 'hello' in one word" 2>&1 | head -n 1)

    if [[ -n "$test_response" ]]; then
        print_success "Model test successful: $test_response"
    else
        print_warning "Model test inconclusive, but model is loaded"
    fi
}

# ==============================================================================
# Main Script
# ==============================================================================

main() {
    clear
    print_header "Archer Local LLM Setup"

    echo "This script will set up a local LLM (Ollama) for Archer based on your system resources."
    echo ""

    # Detect RAM
    local detected_ram=$(detect_ram_gb)
    local ram_gb

    if (( detected_ram > 0 )); then
        print_info "Detected RAM: ${detected_ram}GB"
        read -p "Is this correct? (y/n, or enter custom value in GB): " ram_input

        if [[ "$ram_input" =~ ^[0-9]+$ ]]; then
            ram_gb=$ram_input
            print_info "Using custom RAM value: ${ram_gb}GB"
        elif [[ "$ram_input" == "n" ]] || [[ "$ram_input" == "N" ]]; then
            read -p "Enter available RAM in GB: " ram_gb
        else
            ram_gb=$detected_ram
        fi
    else
        read -p "Enter available RAM in GB: " ram_gb
    fi

    # Validate RAM input
    if ! [[ "$ram_gb" =~ ^[0-9]+$ ]]; then
        print_error "Invalid RAM value"
        exit 1
    fi

    # Select model
    IFS='|' read -r model_name model_size recommended <<< "$(select_model_for_ram $ram_gb)"

    print_header "Recommended Configuration"
    echo "  System RAM:    ${ram_gb}GB"
    echo "  Model:         $model_name"
    echo "  Model Size:    $model_size"
    echo "  Description:   $recommended"
    echo ""

    read -p "Proceed with this configuration? (y/n): " proceed
    if [[ "$proceed" != "y" ]] && [[ "$proceed" != "Y" ]]; then
        print_info "Setup cancelled"
        exit 0
    fi

    # Check Ollama installation
    if ! check_ollama_installed; then
        print_warning "Ollama is not installed"
        read -p "Install Ollama now? (y/n): " install_choice
        if [[ "$install_choice" == "y" ]] || [[ "$install_choice" == "Y" ]]; then
            install_ollama
        else
            print_error "Ollama is required. Please install it manually from: https://ollama.com"
            exit 1
        fi
    else
        print_success "Ollama is already installed"
    fi

    # Start Ollama server if not running
    if ! check_ollama_running; then
        start_ollama_server
    else
        print_success "Ollama server is already running"
    fi

    # Download model
    if ollama list | grep -q "$model_name"; then
        print_success "Model '$model_name' is already downloaded"
    else
        download_model "$model_name"
    fi

    # Configure Archer
    configure_archer "$model_name"

    # Configure Docker Compose (if applicable)
    configure_docker_compose "$model_name"

    # Verify setup
    verify_setup "$model_name"

    # Success summary
    print_header "Setup Complete!"
    echo ""
    echo "  ✓ Ollama server is running on http://localhost:11434"
    echo "  ✓ Model '$model_name' is ready"
    echo "  ✓ Archer is configured to use local LLM"
    echo ""
    print_info "Next steps:"
    echo ""
    echo "  1. Start Archer web application:"
    echo "     - Docker:       docker-compose up --build"
    echo "     - Local Python: uvicorn archer.app:app --reload"
    echo ""
    echo "  2. Access Archer at http://localhost:8000"
    echo "     - Login: admin@archer.app"
    echo "     - Password: £missary_0f_the_G0rg0nite$"
    echo ""
    echo "  3. Start using AI-powered detection generation!"
    echo ""
    print_info "To stop Ollama server: killall ollama"
    print_info "To check Ollama status: curl http://localhost:11434/api/tags"
    echo ""
}

# Run main function
main "$@"
