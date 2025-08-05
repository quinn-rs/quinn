#!/bin/bash
# Fix Rust edition 2024 clippy warnings

echo "Fixing map_or(true) to is_none_or..."
find src tests -name "*.rs" -type f -exec sed -i '' 's/\.map_or(true, /.is_none_or(/g' {} \;

echo "Fixing map_err to inspect_err where appropriate..."
# These need more careful handling - let's do them manually

echo "Done!"