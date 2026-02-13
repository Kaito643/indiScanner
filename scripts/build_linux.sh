#!/bin/bash

# RanSoc - Linux Build Script

echo "=== RanSoc - Linux Builder ==="

# Check for Python
if ! command -v python3 &> /dev/null; then
    echo "Error: python3 could not be found."
    exit 1
fi

# Create Virtual Environment
echo "[*] Creating virtual environment..."
python3 -m venv venv
source venv/bin/activate

# Install Dependencies
echo "[*] Installing dependencies..."
pip install -r requirements.txt
pip install pyinstaller

# Build Binary
echo "[*] Building binary..."
pyinstaller --onefile --name ransoc src/main.py

echo "[+] Build complete!"
echo "Binary location: dist/ransoc"
echo "To run: ./dist/ransoc"
