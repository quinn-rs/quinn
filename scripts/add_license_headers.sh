#!/bin/bash

# Add license headers to source files missing them
# This script adds the standard license header to all .rs files that don't already have one

LICENSE_HEADER="// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses

"

echo "Adding license headers to source files..."

# Find all .rs files in src/ directory
find src/ -name "*.rs" -type f | while read -r file; do
    # Check if file already has a license header (starts with "// Copyright")
    if ! head -n 5 "$file" | grep -q "Copyright"; then
        echo "Adding license header to: $file"
        # Create a temporary file with the license header and original content
        {
            echo "$LICENSE_HEADER"
            cat "$file"
        } > "${file}.tmp"
        # Replace original file with the new one
        mv "${file}.tmp" "$file"
    else
        echo "License header already present in: $file"
    fi
done

echo "License header addition completed!"