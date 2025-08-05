#!/bin/bash
# Analyze which "dead code" is actually used

set -e

echo "Analyzing dead code usage in nat_traversal.rs..."

# Extract field/function names marked as dead code
grep -B1 "#\[allow(dead_code)\]" src/connection/nat_traversal.rs | \
grep -E "(pub|fn|const|struct|enum)" | \
sed 's/.*\(pub\|fn\|const\|struct\|enum\)[^:]*\s\+\([a-zA-Z_][a-zA-Z0-9_]*\).*/\2/' | \
sort -u > /tmp/dead_code_names.txt

echo "Found $(wc -l < /tmp/dead_code_names.txt) unique names marked as dead code"

# Check usage of each
echo -e "\nChecking usage of each item:"
while read -r name; do
    # Count occurrences (excluding the definition)
    count=$(grep -c "\b$name\b" src/connection/nat_traversal.rs || true)
    if [ $count -gt 1 ]; then
        echo "  $name: used $((count-1)) times (can remove #[allow(dead_code)])"
    else
        echo "  $name: NOT USED (truly dead)"
    fi
done < /tmp/dead_code_names.txt

# Cleanup
rm -f /tmp/dead_code_names.txt