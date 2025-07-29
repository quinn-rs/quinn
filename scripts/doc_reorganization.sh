#!/bin/bash
# Documentation Reorganization Script for ant-quic

set -euo pipefail

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}=== Documentation Reorganization ===${NC}"

# Create new documentation structure
echo -e "${GREEN}Creating new documentation structure...${NC}"
mkdir -p docs/{architecture,guides,development,api,deployment,testing}

# Move architecture docs
echo -e "${YELLOW}Moving architecture documentation...${NC}"
[ -f ARCHITECTURE.md ] && mv ARCHITECTURE.md docs/architecture/
[ -f docs/PROTOCOL_EXTENSIONS.md ] && mv docs/PROTOCOL_EXTENSIONS.md docs/architecture/
[ -f docs/core-components.md ] && cp docs/book/src/core-components.md docs/architecture/

# Move guides
echo -e "${YELLOW}Moving user guides...${NC}"
[ -f README.md ] && cp README.md docs/
[ -f docs/QUICK_START_TESTING.md ] && mv docs/QUICK_START_TESTING.md docs/guides/
[ -f docs/NAT_TRAVERSAL_INTEGRATION_GUIDE.md ] && mv docs/NAT_TRAVERSAL_INTEGRATION_GUIDE.md docs/guides/
[ -f docs/EXTERNAL_TESTING_GUIDE.md ] && mv docs/EXTERNAL_TESTING_GUIDE.md docs/guides/
[ -f docs/COMPREHENSIVE_EXTERNAL_TESTING_GUIDE.md ] && mv docs/COMPREHENSIVE_EXTERNAL_TESTING_GUIDE.md docs/guides/

# Move development docs
echo -e "${YELLOW}Moving development documentation...${NC}"
[ -f CONTRIBUTING.md ] && mv CONTRIBUTING.md docs/development/ 2>/dev/null || echo "No CONTRIBUTING.md found"
[ -f docs/CI_CD_GUIDE.md ] && mv docs/CI_CD_GUIDE.md docs/development/
[ -f docs/RELEASE_PROCESS.md ] && mv docs/RELEASE_PROCESS.md docs/development/
[ -f docs/COVERAGE_GUIDE.md ] && mv docs/COVERAGE_GUIDE.md docs/development/

# Move API docs
echo -e "${YELLOW}Moving API documentation...${NC}"
[ -f docs/API_REFERENCE.md ] && mv docs/API_REFERENCE.md docs/api/

# Move deployment docs
echo -e "${YELLOW}Moving deployment documentation...${NC}"
[ -f deploy/digitalocean/README.md ] && cp deploy/digitalocean/README.md docs/deployment/digitalocean.md
[ -f docker/README.md ] && cp docker/README.md docs/deployment/docker.md

# Move testing docs
echo -e "${YELLOW}Moving testing documentation...${NC}"
[ -f docs/TEST_CATEGORIZATION.md ] && mv docs/TEST_CATEGORIZATION.md docs/testing/
[ -f docs/PROPERTY_TESTING.md ] && mv docs/PROPERTY_TESTING.md docs/testing/
[ -f docs/LONG_TESTS_GUIDE.md ] && mv docs/LONG_TESTS_GUIDE.md docs/testing/
[ -f docker/NAT_TESTING_GUIDE.md ] && cp docker/NAT_TESTING_GUIDE.md docs/testing/

# Clean up old status/summary files from root
echo -e "${YELLOW}Archiving old status files...${NC}"
mkdir -p docs/archive/status
for file in *_SUMMARY.md *_STATUS.md *_RESULTS.md PHASE*.md TEST_*.md; do
    [ -f "$file" ] && mv "$file" docs/archive/status/
done

# Update main README with new structure
echo -e "${GREEN}Updating main README...${NC}"
cat > docs/README.md << 'EOF'
# ant-quic Documentation

Welcome to the ant-quic documentation. This directory contains comprehensive documentation for the project.

## Documentation Structure

### 📚 [Architecture](./architecture/)
- [System Architecture](./architecture/ARCHITECTURE.md)
- [Core Components](./architecture/core-components.md)
- [Protocol Extensions](./architecture/PROTOCOL_EXTENSIONS.md)

### 🚀 [Getting Started](./guides/)
- [Quick Start Guide](./guides/QUICK_START_TESTING.md)
- [NAT Traversal Guide](./guides/NAT_TRAVERSAL_INTEGRATION_GUIDE.md)
- [External Testing Guide](./guides/EXTERNAL_TESTING_GUIDE.md)

### 💻 [Development](./development/)
- [Contributing Guidelines](./development/CONTRIBUTING.md)
- [CI/CD Guide](./development/CI_CD_GUIDE.md)
- [Release Process](./development/RELEASE_PROCESS.md)
- [Code Coverage](./development/COVERAGE_GUIDE.md)

### 📘 [API Reference](./api/)
- [Complete API Reference](./api/API_REFERENCE.md)

### 🚢 [Deployment](./deployment/)
- [Docker Deployment](./deployment/docker.md)
- [DigitalOcean Deployment](./deployment/digitalocean.md)

### 🧪 [Testing](./testing/)
- [Test Categorization](./testing/TEST_CATEGORIZATION.md)
- [Property Testing](./testing/PROPERTY_TESTING.md)
- [NAT Testing Guide](./testing/NAT_TESTING_GUIDE.md)
- [Long Running Tests](./testing/LONG_TESTS_GUIDE.md)

### 📖 [Additional Resources](./book/)
- [mdBook Documentation](./book/) - Comprehensive guide in book format

## Quick Links

- [Main README](../README.md)
- [CHANGELOG](../CHANGELOG.md)
- [LICENSE](../LICENSE-MIT)
- [SECURITY](../SECURITY.md)
EOF

# Check for broken links
echo -e "${BLUE}Checking for broken links...${NC}"
find docs -name "*.md" -type f | while read -r file; do
    # Extract markdown links
    grep -oE '\[([^]]+)\]\(([^)]+)\)' "$file" | while read -r link; do
        url=$(echo "$link" | sed -E 's/\[([^]]+)\]\(([^)]+)\)/\2/')
        # Check if it's a local file link
        if [[ "$url" =~ ^\.\.?/ ]] || [[ ! "$url" =~ ^https?:// ]]; then
            # Convert to absolute path from file location
            dir=$(dirname "$file")
            target="$dir/$url"
            target=$(realpath --relative-to=. "$target" 2>/dev/null || echo "$target")
            if [ ! -f "$target" ] && [ ! -d "$target" ]; then
                echo -e "${YELLOW}Warning: Broken link in $file: $url${NC}"
            fi
        fi
    done
done

# Generate documentation index
echo -e "${GREEN}Generating documentation index...${NC}"
cat > docs/INDEX.md << 'EOF'
# ant-quic Documentation Index

This index provides a complete list of all documentation files in the project.

## Main Documentation
EOF

find docs -name "*.md" -type f | sort | while read -r file; do
    # Skip the index file itself
    [ "$file" = "docs/INDEX.md" ] && continue
    
    # Create relative path and title
    rel_path="${file#docs/}"
    title=$(head -n 1 "$file" | sed 's/^#\+ *//')
    echo "- [$title](./$rel_path)" >> docs/INDEX.md
done

echo -e "${GREEN}Documentation reorganization complete!${NC}"
echo -e "${BLUE}Summary:${NC}"
echo "- Created organized directory structure in docs/"
echo "- Moved documentation to appropriate categories"
echo "- Archived old status files"
echo "- Updated main documentation README"
echo "- Generated documentation index"

# Count documentation files
total_docs=$(find docs -name "*.md" -type f | wc -l)
echo -e "${GREEN}Total documentation files: $total_docs${NC}"