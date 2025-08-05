#!/bin/bash
# Script to systematically fix #[allow(dead_code)] patterns

set -e

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'  
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}=== Dead Code Fixer for ant-quic ===${NC}"
echo

# First, analyze what we have
echo -e "${YELLOW}1. Analyzing dead code patterns...${NC}"

# Count by file
echo "Dead code allows by file:"
for file in $(find src -name "*.rs" -type f); do
    count=$(grep -c "#\[allow(dead_code)\]" "$file" 2>/dev/null || echo 0)
    if [ $count -gt 0 ]; then
        echo "  $file: $count"
    fi
done
echo

# Categorize the types
echo -e "${YELLOW}2. Categorizing dead code types...${NC}"

# Find structs/enums marked as dead
echo "Structs/Enums with dead code:"
grep -B1 -A1 "#\[allow(dead_code)\]" src/**/*.rs 2>/dev/null | grep -E "struct|enum" | head -10 || true
echo

# Find functions marked as dead
echo "Functions with dead code:"
grep -A1 "#\[allow(dead_code)\]" src/**/*.rs 2>/dev/null | grep "fn " | head -10 || true
echo

# Find fields marked as dead
echo "Fields with dead code:"
grep -A1 "#\[allow(dead_code)\]" src/**/*.rs 2>/dev/null | grep -E "pub|:" | grep -v "fn" | head -10 || true
echo

echo -e "${BLUE}=== Analysis Summary ===${NC}"
echo "To fix dead code:"
echo "1. For unused structs/fields in nat_traversal.rs:"
echo "   - If part of future infrastructure: Remove and add TODO issue"
echo "   - If used internally: Change visibility to pub(crate) or pub(super)"
echo "   - If truly unused: Delete the code"
echo
echo "2. For functions marked as dead:"
echo "   - Check if they're test utilities -> move to #[cfg(test)]"
echo "   - Check if they're for specific features -> use #[cfg(feature = \"...\")]"
echo "   - Otherwise: Remove or fix visibility"
echo
echo "3. Common patterns to fix:"
echo "   - Resource cleanup functions -> Make pub(super) if used by Connection"
echo "   - Statistics getters -> Make pub(crate) for monitoring"
echo "   - Debug/test helpers -> Move to test modules"