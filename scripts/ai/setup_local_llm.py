#!/usr/bin/env python3
"""
Archer Local LLM Setup Script
==============================================================================
This script automatically configures a local LLM (Ollama) based on available
system resources. It will:
1. Detect or prompt for available RAM
2. Install Ollama (if needed)
3. Select and download the best model for your system
4. Configure Archer to use the local LLM
5. Start Ollama server

Usage:
    python scripts/setup_local_llm.py
    python scripts/setup_local_llm.py --ram 32  # Specify RAM manually
"""

import argparse
import os
import platform
import re
import subprocess
import sys
import time
import urllib.request
from pathlib import Path
from typing import Dict, Tuple, Optional

# Colors for terminal output
class Colors:
    RED = '\033[0;31m'
    GREEN = '\033[0;32m'
    YELLOW = '\033[1;33m'
    BLUE = '\033[0;34m'
    NC = '\033[0m'  # No Color
    BOLD = '\033[1m'

def print_info(msg: str):
    print(f"{Colors.BLUE}ℹ {Colors.NC}{msg}")

def print_success(msg: str):
    print(f"{Colors.GREEN}✓{Colors.NC} {msg}")

def print_warning(msg: str):
    print(f"{Colors.YELLOW}⚠{Colors.NC} {msg}")

def print_error(msg: str):
    print(f"{Colors.RED}✗{Colors.NC} {msg}")

def print_header(msg: str):
    print()
    print(f"{Colors.BLUE}{'═' * 67}{Colors.NC}")
    print(f"{Colors.BLUE}  {msg}{Colors.NC}")
    print(f"{Colors.BLUE}{'═' * 67}{Colors.NC}")
    print()

# ==============================================================================
# System Detection
# ==============================================================================

def detect_os() -> str:
    """Detect operating system."""
    system = platform.system().lower()
    if system == 'darwin':
        return 'macos'
    elif system == 'linux':
        return 'linux'
    elif system == 'windows':
        return 'windows'
    else:
        return 'unknown'

def detect_ram_gb() -> int:
    """Detect available RAM in GB."""
    try:
        if platform.system() == 'Darwin':  # macOS
            output = subprocess.check_output(['sysctl', '-n', 'hw.memsize'])
            ram_bytes = int(output.strip())
            return ram_bytes // (1024 ** 3)
        elif platform.system() == 'Linux':
            with open('/proc/meminfo', 'r') as f:
                meminfo = f.read()
            match = re.search(r'MemTotal:\s+(\d+)', meminfo)
            if match:
                ram_kb = int(match.group(1))
                return ram_kb // (1024 ** 2)
        elif platform.system() == 'Windows':
            import ctypes
            kernel32 = ctypes.windll.kernel32
            c_ulong = ctypes.c_ulong
            class MEMORYSTATUSEX(ctypes.Structure):
                _fields_ = [
                    ('dwLength', c_ulong),
                    ('dwMemoryLoad', c_ulong),
                    ('ullTotalPhys', ctypes.c_ulonglong),
                    ('ullAvailPhys', ctypes.c_ulonglong),
                    ('ullTotalPageFile', ctypes.c_ulonglong),
                    ('ullAvailPageFile', ctypes.c_ulonglong),
                    ('ullTotalVirtual', ctypes.c_ulonglong),
                    ('ullAvailVirtual', ctypes.c_ulonglong),
                    ('ullAvailExtendedVirtual', ctypes.c_ulonglong),
                ]
            memoryStatus = MEMORYSTATUSEX()
            memoryStatus.dwLength = ctypes.sizeof(MEMORYSTATUSEX)
            kernel32.GlobalMemoryStatusEx(ctypes.byref(memoryStatus))
            return memoryStatus.ullTotalPhys // (1024 ** 3)
    except Exception:
        pass
    return 0

# ==============================================================================
# Model Selection
# ==============================================================================

MODEL_RECOMMENDATIONS = {
    'ultra': {
        'min_ram': 64,
        'model': 'llama3.1:70b-instruct-q4_K_M',
        'size': '~40GB',
        'description': 'Best Quality - Perfect for detection engineering'
    },
    'high': {
        'min_ram': 32,
        'model': 'qwen2.5:32b-instruct-q4_K_M',
        'size': '~20GB',
        'description': 'Excellent Quality - Great for code/query generation'
    },
    'medium': {
        'min_ram': 16,
        'model': 'llama3.1:8b-instruct-q4_K_M',
        'size': '~5GB',
        'description': 'Good Quality - Balanced performance'
    },
    'low': {
        'min_ram': 8,
        'model': 'mistral:7b-instruct-q4_K_M',
        'size': '~4GB',
        'description': 'Lightweight - Suitable for basic tasks'
    },
    'minimal': {
        'min_ram': 4,
        'model': 'phi3:mini',
        'size': '~2GB',
        'description': 'Minimal - Very basic LLM capabilities'
    }
}

def select_model_for_ram(ram_gb: int) -> Dict[str, str]:
    """Select the best model based on available RAM."""
    if ram_gb >= 64:
        return MODEL_RECOMMENDATIONS['ultra']
    elif ram_gb >= 32:
        return MODEL_RECOMMENDATIONS['high']
    elif ram_gb >= 16:
        return MODEL_RECOMMENDATIONS['medium']
    elif ram_gb >= 8:
        return MODEL_RECOMMENDATIONS['low']
    else:
        return MODEL_RECOMMENDATIONS['minimal']

# ==============================================================================
# Ollama Management
# ==============================================================================

def check_ollama_installed() -> bool:
    """Check if Ollama is installed."""
    try:
        subprocess.run(['ollama', '--version'],
                      capture_output=True,
                      check=True)
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False

def install_ollama():
    """Install Ollama based on OS."""
    os_type = detect_os()

    print_header("Installing Ollama")

    if os_type in ['linux', 'macos']:
        print_info("Downloading and installing Ollama...")
        try:
            script = urllib.request.urlopen('https://ollama.com/install.sh').read()
            subprocess.run(['sh', '-c', script.decode()], check=True)
            print_success("Ollama installed successfully")
        except Exception as e:
            print_error(f"Failed to install Ollama: {e}")
            sys.exit(1)
    elif os_type == 'windows':
        print_error("Automatic installation not supported on Windows")
        print_info("Please download Ollama from: https://ollama.com/download/windows")
        print_info("After installation, run this script again")
        sys.exit(1)
    else:
        print_error("Unsupported operating system")
        sys.exit(1)

def check_ollama_running() -> bool:
    """Check if Ollama server is running."""
    try:
        urllib.request.urlopen('http://localhost:11434/api/tags', timeout=2)
        return True
    except Exception:
        return False

def start_ollama_server():
    """Start Ollama server."""
    print_info("Starting Ollama server...")

    try:
        if platform.system() == 'Windows':
            subprocess.Popen(['ollama', 'serve'],
                           creationflags=subprocess.CREATE_NEW_CONSOLE)
        else:
            subprocess.Popen(['ollama', 'serve'],
                           stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL)

        # Wait for server to start
        max_attempts = 10
        for _ in range(max_attempts):
            time.sleep(1)
            if check_ollama_running():
                print_success("Ollama server started successfully")
                return

        print_error("Failed to start Ollama server")
        sys.exit(1)
    except Exception as e:
        print_error(f"Failed to start Ollama: {e}")
        sys.exit(1)

def download_model(model_name: str):
    """Download Ollama model."""
    print_header(f"Downloading Model: {model_name}")
    print_info("This may take several minutes depending on your internet connection...")

    try:
        subprocess.run(['ollama', 'pull', model_name], check=True)
        print_success("Model downloaded successfully")
    except subprocess.CalledProcessError:
        print_error("Failed to download model")
        sys.exit(1)

def list_ollama_models() -> list:
    """List installed Ollama models."""
    try:
        result = subprocess.run(['ollama', 'list'],
                              capture_output=True,
                              text=True,
                              check=True)
        return result.stdout
    except subprocess.CalledProcessError:
        return ""

# ==============================================================================
# Configuration
# ==============================================================================

def configure_archer(model_name: str):
    """Configure Archer .env file."""
    print_header("Configuring Archer")

    env_file = Path('.env')
    env_example = Path('.env.example')

    # Create .env if it doesn't exist
    if not env_file.exists():
        if env_example.exists():
            env_file.write_text(env_example.read_text())
            print_info("Created .env from .env.example")
        else:
            env_file.touch()
            print_info("Created new .env file")

    # Read current content
    content = env_file.read_text() if env_file.exists() else ""
    lines = content.split('\n')

    # Update or add LLM configuration
    config_updates = {
        'LLM_PROVIDER': 'ollama',
        'LLM_MODEL': model_name,
        'OLLAMA_BASE_URL': 'http://localhost:11434'
    }

    for key, value in config_updates.items():
        found = False
        for i, line in enumerate(lines):
            if line.startswith(f'{key}='):
                lines[i] = f'{key}={value}'
                found = True
                break
        if not found:
            lines.append(f'{key}={value}')

    # Write back
    env_file.write_text('\n'.join(lines))
    print_success("Archer configured to use local LLM")

def configure_docker_compose(model_name: str):
    """Update docker-compose.yml with LLM configuration."""
    docker_compose = Path('docker-compose.yml')

    if not docker_compose.exists():
        print_warning("docker-compose.yml not found, skipping Docker configuration")
        return

    print_info("Note: You may need to manually update docker-compose.yml")
    print_info("Add these environment variables to the archer service:")
    print(f"      - LLM_PROVIDER=ollama")
    print(f"      - LLM_MODEL={model_name}")
    print(f"      - OLLAMA_BASE_URL=http://host.docker.internal:11434")

# ==============================================================================
# Verification
# ==============================================================================

def verify_setup(model_name: str) -> bool:
    """Verify the setup is working."""
    print_header("Verifying Setup")

    # Check Ollama is running
    if not check_ollama_running():
        print_error("Ollama server is not running")
        return False
    print_success("Ollama server is running")

    # Check model is available
    models_output = list_ollama_models()
    if model_name not in models_output:
        print_error(f"Model '{model_name}' not found")
        return False
    print_success(f"Model '{model_name}' is available")

    # Test model
    print_info("Testing model (this may take a few seconds)...")
    try:
        result = subprocess.run(
            ['ollama', 'run', model_name, 'Say hello in one word'],
            capture_output=True,
            text=True,
            timeout=30
        )
        if result.stdout.strip():
            print_success(f"Model test successful: {result.stdout.strip()[:50]}")
        else:
            print_warning("Model test inconclusive, but model is loaded")
    except subprocess.TimeoutExpired:
        print_warning("Model test timed out, but model appears to be loaded")
    except Exception as e:
        print_warning(f"Model test failed: {e}")

    return True

# ==============================================================================
# Main Function
# ==============================================================================

def main():
    parser = argparse.ArgumentParser(
        description='Set up local LLM (Ollama) for Archer',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Auto-detect RAM and configure
  python scripts/setup_local_llm.py

  # Specify RAM manually (32GB)
  python scripts/setup_local_llm.py --ram 32

  # Skip confirmation prompts
  python scripts/setup_local_llm.py --yes
        """
    )
    parser.add_argument('--ram', type=int, help='Available RAM in GB')
    parser.add_argument('--yes', '-y', action='store_true',
                       help='Skip confirmation prompts')
    args = parser.parse_args()

    print_header("Archer Local LLM Setup")
    print("This script will set up a local LLM (Ollama) for Archer based on your system resources.")
    print()

    # Detect or get RAM
    if args.ram:
        ram_gb = args.ram
        print_info(f"Using specified RAM: {ram_gb}GB")
    else:
        detected_ram = detect_ram_gb()
        if detected_ram > 0:
            print_info(f"Detected RAM: {detected_ram}GB")
            if not args.yes:
                try:
                    user_input = input("Is this correct? (y/n, or enter custom value in GB): ").strip()
                    if user_input.lower() in ['n', 'no']:
                        ram_gb = int(input("Enter available RAM in GB: "))
                    elif user_input.isdigit():
                        ram_gb = int(user_input)
                    else:
                        ram_gb = detected_ram
                except ValueError:
                    print_error("Invalid input")
                    sys.exit(1)
            else:
                ram_gb = detected_ram
        else:
            try:
                ram_gb = int(input("Enter available RAM in GB: "))
            except ValueError:
                print_error("Invalid RAM value")
                sys.exit(1)

    # Select model
    model_config = select_model_for_ram(ram_gb)

    print_header("Recommended Configuration")
    print(f"  System RAM:    {ram_gb}GB")
    print(f"  Model:         {model_config['model']}")
    print(f"  Model Size:    {model_config['size']}")
    print(f"  Description:   {model_config['description']}")
    print()

    if not args.yes:
        proceed = input("Proceed with this configuration? (y/n): ").strip().lower()
        if proceed not in ['y', 'yes']:
            print_info("Setup cancelled")
            sys.exit(0)

    # Check Ollama installation
    if not check_ollama_installed():
        print_warning("Ollama is not installed")
        if args.yes or input("Install Ollama now? (y/n): ").strip().lower() in ['y', 'yes']:
            install_ollama()
        else:
            print_error("Ollama is required. Please install it manually from: https://ollama.com")
            sys.exit(1)
    else:
        print_success("Ollama is already installed")

    # Start Ollama server if not running
    if not check_ollama_running():
        start_ollama_server()
    else:
        print_success("Ollama server is already running")

    # Download model
    model_name = model_config['model']
    if model_name in list_ollama_models():
        print_success(f"Model '{model_name}' is already downloaded")
    else:
        download_model(model_name)

    # Configure Archer
    configure_archer(model_name)
    configure_docker_compose(model_name)

    # Verify setup
    verify_setup(model_name)

    # Success summary
    print_header("Setup Complete!")
    print()
    print(f"  ✓ Ollama server is running on http://localhost:11434")
    print(f"  ✓ Model '{model_name}' is ready")
    print(f"  ✓ Archer is configured to use local LLM")
    print()
    print_info("Next steps:")
    print()
    print("  1. Start Archer web application:")
    print("     - Docker:       docker-compose up --build")
    print("     - Local Python: uvicorn archer.app:app --reload")
    print()
    print("  2. Access Archer at http://localhost:8000")
    print("     - Login: admin@archer.app")
    print("     - Password: £missary_0f_the_G0rg0nite$")
    print()
    print("  3. Start using AI-powered detection generation!")
    print()
    print_info("To check Ollama status: curl http://localhost:11434/api/tags")
    if platform.system() != 'Windows':
        print_info("To stop Ollama server: killall ollama")
    print()

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print()
        print_info("Setup cancelled by user")
        sys.exit(0)
    except Exception as e:
        print_error(f"Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
