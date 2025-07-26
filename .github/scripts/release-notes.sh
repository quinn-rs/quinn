#!/bin/bash
# Generate release notes from git history and PR information

set -euo pipefail

# Get the version tag
VERSION="${1:-}"
if [ -z "$VERSION" ]; then
    echo "Usage: $0 <version>"
    exit 1
fi

# Get the previous version tag
PREVIOUS_VERSION=$(git describe --tags --abbrev=0 "${VERSION}^" 2>/dev/null || echo "")

# Function to categorize commits
categorize_commit() {
    local message="$1"
    
    if [[ "$message" =~ ^feat:|^feature: ]]; then
        echo "feature"
    elif [[ "$message" =~ ^fix:|^bugfix: ]]; then
        echo "fix"
    elif [[ "$message" =~ ^perf:|^performance: ]]; then
        echo "performance"
    elif [[ "$message" =~ ^docs:|^documentation: ]]; then
        echo "documentation"
    elif [[ "$message" =~ ^test:|^tests: ]]; then
        echo "test"
    elif [[ "$message" =~ ^refactor: ]]; then
        echo "refactor"
    elif [[ "$message" =~ ^chore:|^build:|^ci: ]]; then
        echo "chore"
    elif [[ "$message" =~ BREAKING[[:space:]]CHANGE|BREAKING: ]]; then
        echo "breaking"
    else
        echo "other"
    fi
}

# Initialize category arrays
declare -A commits_by_category
commits_by_category[breaking]=""
commits_by_category[feature]=""
commits_by_category[fix]=""
commits_by_category[performance]=""
commits_by_category[documentation]=""
commits_by_category[test]=""
commits_by_category[refactor]=""
commits_by_category[chore]=""
commits_by_category[other]=""

# Get commit range
if [ -n "$PREVIOUS_VERSION" ]; then
    COMMIT_RANGE="${PREVIOUS_VERSION}..${VERSION}"
    echo "# Release Notes for ${VERSION}"
    echo ""
    echo "## Changes since ${PREVIOUS_VERSION}"
else
    COMMIT_RANGE="${VERSION}"
    echo "# Release Notes for ${VERSION}"
    echo ""
    echo "## Initial Release"
fi

echo ""
echo "**Release Date**: $(date -u '+%Y-%m-%d')"
echo ""

# Process commits
while IFS= read -r line; do
    commit_hash=$(echo "$line" | cut -d' ' -f1)
    commit_message=$(echo "$line" | cut -d' ' -f2-)
    category=$(categorize_commit "$commit_message")
    
    # Get PR number if available (GitHub specific)
    pr_number=$(git log --format="%b" -n 1 "$commit_hash" | grep -oE '#[0-9]+' | head -1 || echo "")
    
    # Format commit line
    if [ -n "$pr_number" ]; then
        commit_line="- ${commit_message} (${commit_hash:0:7}) ${pr_number}"
    else
        commit_line="- ${commit_message} (${commit_hash:0:7})"
    fi
    
    # Add to appropriate category
    if [ -n "${commits_by_category[$category]}" ]; then
        commits_by_category[$category]="${commits_by_category[$category]}\n${commit_line}"
    else
        commits_by_category[$category]="${commit_line}"
    fi
done < <(git log --format="%H %s" "$COMMIT_RANGE")

# Output categorized commits
if [ -n "${commits_by_category[breaking]}" ]; then
    echo "## 🚨 Breaking Changes"
    echo -e "${commits_by_category[breaking]}"
    echo ""
fi

if [ -n "${commits_by_category[feature]}" ]; then
    echo "## ✨ New Features"
    echo -e "${commits_by_category[feature]}"
    echo ""
fi

if [ -n "${commits_by_category[fix]}" ]; then
    echo "## 🐛 Bug Fixes"
    echo -e "${commits_by_category[fix]}"
    echo ""
fi

if [ -n "${commits_by_category[performance]}" ]; then
    echo "## ⚡ Performance Improvements"
    echo -e "${commits_by_category[performance]}"
    echo ""
fi

if [ -n "${commits_by_category[documentation]}" ]; then
    echo "## 📚 Documentation"
    echo -e "${commits_by_category[documentation]}"
    echo ""
fi

# Add statistics
echo "## 📊 Statistics"
echo ""

# Count files changed
if [ -n "$PREVIOUS_VERSION" ]; then
    FILES_CHANGED=$(git diff --name-only "$COMMIT_RANGE" | wc -l)
    INSERTIONS=$(git diff --shortstat "$COMMIT_RANGE" | grep -oE '[0-9]+ insertions' | grep -oE '[0-9]+' || echo "0")
    DELETIONS=$(git diff --shortstat "$COMMIT_RANGE" | grep -oE '[0-9]+ deletions' | grep -oE '[0-9]+' || echo "0")
    COMMITS=$(git rev-list --count "$COMMIT_RANGE")
    
    echo "- Commits: $COMMITS"
    echo "- Files Changed: $FILES_CHANGED"
    echo "- Lines Added: $INSERTIONS"
    echo "- Lines Removed: $DELETIONS"
fi

# Add contributors
echo ""
echo "## 👥 Contributors"
echo ""
echo "Thanks to all contributors who made this release possible:"
echo ""

# List unique contributors
if [ -n "$PREVIOUS_VERSION" ]; then
    git log --format="%an" "$COMMIT_RANGE" | sort | uniq | while read -r author; do
        echo "- $author"
    done
else
    git log --format="%an" | sort | uniq | while read -r author; do
        echo "- $author"
    done
fi

# Add installation instructions
echo ""
echo "## 📦 Installation"
echo ""
echo "### Binary Installation"
echo ""
echo "Download the appropriate binary for your platform from the release assets below."
echo ""
echo "### Install via Cargo"
echo ""
echo '```bash'
echo "cargo install ant-quic --version ${VERSION#v}"
echo '```'
echo ""
echo "### Docker"
echo ""
echo '```bash'
echo "docker pull antquic/ant-quic:${VERSION}"
echo '```'

# Add upgrade notes if applicable
if [ -n "${commits_by_category[breaking]}" ]; then
    echo ""
    echo "## ⚠️ Upgrade Notes"
    echo ""
    echo "This release contains breaking changes. Please review the breaking changes section above and update your code accordingly."
fi

# Add footer
echo ""
echo "---"
echo ""
echo "For full details, see the [comparison view](https://github.com/ant-design/ant-quic/compare/${PREVIOUS_VERSION}...${VERSION})"