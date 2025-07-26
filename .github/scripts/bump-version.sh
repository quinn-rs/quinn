#!/bin/bash
# Script to bump version in Cargo.toml and create a release tag

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to display usage
usage() {
    echo "Usage: $0 <major|minor|patch|version>"
    echo "  major     - Bump major version (1.0.0 -> 2.0.0)"
    echo "  minor     - Bump minor version (1.0.0 -> 1.1.0)"
    echo "  patch     - Bump patch version (1.0.0 -> 1.0.1)"
    echo "  version   - Set specific version (e.g., 1.2.3)"
    exit 1
}

# Check if argument provided
if [ $# -eq 0 ]; then
    usage
fi

# Get current version from Cargo.toml
CURRENT_VERSION=$(grep "^version" Cargo.toml | head -1 | cut -d'"' -f2)
echo -e "${YELLOW}Current version: $CURRENT_VERSION${NC}"

# Parse version components
IFS='.' read -r MAJOR MINOR PATCH <<< "$CURRENT_VERSION"

# Handle pre-release versions
if [[ $PATCH =~ ^([0-9]+)(-.*)?$ ]]; then
    PATCH_NUM="${BASH_REMATCH[1]}"
    PRE_RELEASE="${BASH_REMATCH[2]}"
else
    PATCH_NUM="$PATCH"
    PRE_RELEASE=""
fi

# Determine new version
case "$1" in
    major)
        NEW_VERSION="$((MAJOR + 1)).0.0"
        ;;
    minor)
        NEW_VERSION="${MAJOR}.$((MINOR + 1)).0"
        ;;
    patch)
        NEW_VERSION="${MAJOR}.${MINOR}.$((PATCH_NUM + 1))"
        ;;
    *)
        # Validate version format
        if [[ ! "$1" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[a-zA-Z0-9]+(\.[0-9]+)?)?$ ]]; then
            echo -e "${RED}Error: Invalid version format: $1${NC}"
            echo "Version must be in format: X.Y.Z or X.Y.Z-suffix"
            exit 1
        fi
        NEW_VERSION="$1"
        ;;
esac

echo -e "${GREEN}New version: $NEW_VERSION${NC}"

# Check if git working directory is clean
if ! git diff --quiet || ! git diff --cached --quiet; then
    echo -e "${RED}Error: Git working directory is not clean${NC}"
    echo "Please commit or stash your changes first"
    exit 1
fi

# Update version in Cargo.toml
echo "Updating Cargo.toml..."
if [[ "$OSTYPE" == "darwin"* ]]; then
    # macOS
    sed -i '' "s/^version = \".*\"/version = \"$NEW_VERSION\"/" Cargo.toml
else
    # Linux
    sed -i "s/^version = \".*\"/version = \"$NEW_VERSION\"/" Cargo.toml
fi

# Update Cargo.lock
echo "Updating Cargo.lock..."
cargo update --workspace

# Run tests to ensure everything works
echo "Running tests..."
cargo test --lib

# Commit changes
echo "Committing version bump..."
git add Cargo.toml Cargo.lock
git commit -m "chore(release): bump version to v$NEW_VERSION"

# Create tag
TAG="v$NEW_VERSION"
echo "Creating tag: $TAG"

# Generate tag message with recent changes
TAG_MESSAGE=$(cat <<EOF
Release $TAG

Changes since last release:
$(git log --oneline $(git describe --tags --abbrev=0 2>/dev/null || echo "")..HEAD | head -20)

Full changelog: https://github.com/dirvine/ant-quic/blob/$TAG/CHANGELOG.md
EOF
)

git tag -a "$TAG" -m "$TAG_MESSAGE"

echo -e "${GREEN}✓ Version bumped to $NEW_VERSION${NC}"
echo -e "${GREEN}✓ Tag $TAG created${NC}"
echo ""
echo "Next steps:"
echo "1. Review the changes: git show"
echo "2. Push the commit: git push origin main"
echo "3. Push the tag: git push origin $TAG"
echo ""
echo "The release workflow will automatically trigger when the tag is pushed."