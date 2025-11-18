#!/bin/bash
# Linux/macOS startup script for AD Web Interface

echo "Starting AD Web Interface on Linux/macOS..."
echo

# Get script directory
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$SCRIPT_DIR"

# Check if Python is available
if ! command -v python3 &> /dev/null; then
    echo "Error: Python 3 is not installed"
    echo "Please install Python 3: sudo apt install python3 python3-pip"
    exit 1
fi

# Check if virtual environment exists
if [ -d "venv" ]; then
    source venv/bin/activate
    echo "Virtual environment activated"
else
    echo "Note: No virtual environment found. Using system Python."
    echo "To create a venv: python3 -m venv venv"
fi

# Install dependencies if needed
if ! python3 -c "import flask" 2>/dev/null; then
    echo "Installing dependencies..."
    pip3 install -r requirements.txt
fi

# Run the application
python3 run.py
