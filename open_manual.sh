#!/bin/bash

FILE="manual_urls.txt"

if [ -f "$FILE" ]; then
    echo "[INFO] '$FILE' found. Opening..."
else
    echo "[INFO] '$FILE' not found. Creating new file..."
    touch "$FILE"
fi

# Open the manual_urls.txt using mousepad
mousepad "$FILE"
