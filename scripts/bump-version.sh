#!/bin/bash
# Version bump helper script for ant-quic
# Usage: ./scripts/bump-version.sh [major|minor|patch]

set -e

BUMP_TYPE="${1:-patch}"

# Get current version from Cargo.toml
CURRENT=$(grep "^version" Cargo.toml | head -1 | cut -d'"' -f2)

if [ -z "$CURRENT" ]; then
    echo "Error: Could not find version in Cargo.toml"
    exit 1
fi

# Parse version
IFS='.' read -r MAJOR MINOR PATCH <<< "$CURRENT"

# Calculate new version
case "$BUMP_TYPE" in
    major)
        NEW="$((MAJOR + 1)).0.0"
        ;;
    minor)
        NEW="${MAJOR}.$((MINOR + 1)).0"
        ;;
    patch)
        NEW="${MAJOR}.${MINOR}.$((PATCH + 1))"
        ;;
    *)
        echo "Usage: $0 [major|minor|patch]"
        echo "Current version: $CURRENT"
        exit 1
        ;;
esac

echo "Bumping version: $CURRENT -> $NEW"

# Update Cargo.toml (macOS compatible)
if [[ "$OSTYPE" == "darwin"* ]]; then
    sed -i '' "s/^version = \"${CURRENT}\"/version = \"${NEW}\"/" Cargo.toml
    for SUBCRATE in crates/*/Cargo.toml; do
        if [ -f "$SUBCRATE" ]; then
            sed -i '' "s/^version = \"${CURRENT}\"/version = \"${NEW}\"/" "$SUBCRATE"
        fi
    done
else
    sed -i "s/^version = \"${CURRENT}\"/version = \"${NEW}\"/" Cargo.toml
    for SUBCRATE in crates/*/Cargo.toml; do
        if [ -f "$SUBCRATE" ]; then
            sed -i "s/^version = \"${CURRENT}\"/version = \"${NEW}\"/" "$SUBCRATE"
        fi
    done
fi

# Update Cargo.lock
cargo update --workspace 2>/dev/null || cargo generate-lockfile

echo "Version bumped to $NEW"
echo ""
echo "To commit and tag:"
echo "  git add Cargo.toml Cargo.lock"
echo "  git commit -m 'chore(release): bump version to v$NEW'"
echo "  git tag v$NEW"
echo "  git push && git push --tags"
