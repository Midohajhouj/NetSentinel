#!/bin/bash

# This script installs the netdef tool on your system.

# Step 1: Copy the Python script to /usr/local/bin/ (or any directory in PATH)
echo "Copying netdef.py to /usr/local/bin/..."
cp ddos.py /usr/local/bin/netdef

# Step 2: Make the script executable
echo "Making the netdef script executable..."
chmod +x /usr/local/bin/netdef

# Step 3: Verify installation
echo "Installation complete. Verifying netdef command..."

if command -v ddos &>/dev/null; then
    echo "netdef command is now available!"
    echo "You can now run netdef --help for usage instructions."
else
    echo "Something went wrong. netdef command is not available."
    exit 1
fi
