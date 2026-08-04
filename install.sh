#!/usr/bin/env bash
set -euo pipefail

echo "=== HiveBreach Installer (Linux/macOS) ==="

# Check Python 3.10+
if command -v python3 &>/dev/null; then
    PY=python3
elif command -v python &>/dev/null; then
    PY=python
else
    echo "ERROR: Python not found. Install Python 3.10+ first."
    exit 1
fi

PY_VERSION=$($PY --version 2>&1)
echo "Found: $PY_VERSION"

MAJOR=$($PY -c "import sys; print(sys.version_info.major)")
MINOR=$($PY -c "import sys; print(sys.version_info.minor)")

if [ "$MAJOR" -lt 3 ] || [ "$MAJOR" -eq 3 -a "$MINOR" -lt 10 ]; then
    echo "ERROR: Python 3.10+ required, got $MAJOR.$MINOR"
    exit 1
fi

# Create virtual environment
if [ ! -d ".venv" ]; then
    echo "Creating virtual environment..."
    $PY -m venv .venv
fi

# Activate and install deps
echo "Installing dependencies..."
source .venv/bin/activate
pip install --upgrade pip
pip install -e .

# Copy .env.example to .env if not exists
ENV_FILE="${1:-.env}"
if [ ! -f "$ENV_FILE" ]; then
    if [ -f ".env.example" ]; then
        cp .env.example "$ENV_FILE"
        echo "Created $ENV_FILE from .env.example"
    fi
else
    echo "$ENV_FILE already exists, skipping"
fi

# Create sessions directory
if [ ! -d "sessions" ]; then
    mkdir -p sessions
    echo "Created sessions/ directory"
fi

echo "=== Install complete ==="
echo "Activate: source .venv/bin/activate"
