#!/bin/bash

# Default directory is current one, or use first argument
TARGET_DIR="${1:-.}"

# Text to search and replace
SEARCH="quic.saorsalabs.com"
REPLACE="quic.saorsalabs.com"

# Loop through files (skip binary files)
find "$TARGET_DIR" -type f | while read -r file; do
    if grep -Iq . "$file"; then
        LC_CTYPE=UTF-8 sed -i '' "s|$SEARCH|$REPLACE|g" "$file"
    fi
done

echo "✅ Replaced '$SEARCH' with '$REPLACE' in text files under '$TARGET_DIR'"
